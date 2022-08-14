#!/usr/bin/env python3

# Copyright (c) Aptos
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Dict, Optional
import sys
from nacl.signing import SigningKey
import os
import hashlib
import requests
import time

TESTNET_URL = os.getenv(
    "APTOS_NODE_URL") or "https://fullnode.devnet.aptoslabs.com"
FAUCET_URL = os.getenv(
    "APTOS_FAUCET_URL") or "https://faucet.devnet.aptoslabs.com"


class Account:
    """Represents an account as well as the private, public key-pair for the Aptos blockchain."""

    def __init__(self, seed: bytes = None) -> None:
        if seed is None:
            self.signing_key = SigningKey.generate()
        else:
            self.signing_key = SigningKey(seed)

    def address(self) -> str:
        """Returns the address associated with the given account"""

        return self.auth_key()

    def auth_key(self) -> str:
        """Returns the auth_key for the associated account"""

        hasher = hashlib.sha3_256()
        hasher.update(self.signing_key.verify_key.encode() + b'\x00')
        return hasher.hexdigest()

    def pub_key(self) -> str:
        """Returns the public key for the associated account"""

        return self.signing_key.verify_key.encode().hex()


class RestClient:
    """A wrapper around the Aptos-core Rest API"""

    def __init__(self, url: str) -> None:
        self.url = url


    def account(self, account_address: str) -> Dict[str, str]:
        """Returns the sequence number and authentication key for an account"""

        response = requests.get(f"{self.url}/accounts/{account_address}")
        assert response.status_code == 200, f"{response.text} - {account_address}"
        return response.json()

    def account_resource(self, account_address: str, resource_type: str) -> Optional[Dict[str, Any]]:
        response = requests.get(
            f"{self.url}/accounts/{account_address}/resource/{resource_type}")
        if response.status_code == 404:
            return None
        assert response.status_code == 200, response.text
        return response.json()


    def generate_transaction(self, sender: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a transaction request that can be submitted to produce a raw transaction that
        can be signed, which upon being signed can be submitted to the blockchain. """

        account_res = self.account(sender)
        seq_num = int(account_res["sequence_number"])
        txn_request = {
            "sender": f"0x{sender}",
            "sequence_number": str(seq_num),
            "max_gas_amount": "2000",
            "gas_unit_price": "1",
            "gas_currency_code": "XUS",
            "expiration_timestamp_secs": str(int(time.time()) + 600),
            "payload": payload,
        }
        return txn_request

    def sign_transaction(self, account_from: Account, txn_request: Dict[str, Any]) -> Dict[str, Any]:
        """Converts a transaction request produced by `generate_transaction` into a properly signed
        transaction, which can then be submitted to the blockchain."""

        print("{self.url}/transactions/signing_message", txn_request)

        res = requests.post(
            f"{self.url}/transactions/signing_message", json=txn_request)
        assert res.status_code == 200, res.text
        to_sign = bytes.fromhex(res.json()["message"][2:])
        signature = account_from.signing_key.sign(to_sign).signature
        txn_request["signature"] = {
            "type": "ed25519_signature",
            "public_key": f"0x{account_from.pub_key()}",
            "signature": f"0x{signature.hex()}",
        }
        return txn_request

    def submit_transaction(self, txn: Dict[str, Any]) -> Dict[str, Any]:
        """Submits a signed transaction to the blockchain."""

        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{self.url}/transactions", headers=headers, json=txn)
        assert response.status_code == 202, f"{response.text} - {txn}"
        return response.json()

    def execute_transaction_with_payload(self, account_from: Account, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a transaction for the given payload."""

        txn_request = self.generate_transaction(
            account_from.address(), payload)
        signed_txn = self.sign_transaction(account_from, txn_request)
        return self.submit_transaction(signed_txn)

    def transaction_pending(self, txn_hash: str) -> bool:
        response = requests.get(f"{self.url}/transactions/{txn_hash}")
        if response.status_code == 404:
            return True
        assert response.status_code == 200, f"{response.text} - {txn_hash}"
        return response.json()["type"] == "pending_transaction"

    def wait_for_transaction(self, txn_hash: str) -> None:
        """Waits up to 10 seconds for a transaction to move past pending state."""

        count = 0
        while self.transaction_pending(txn_hash):
            assert count < 10, f"transaction {txn_hash} timed out"
            time.sleep(1)
            count += 1
        response = requests.get(f"{self.url}/transactions/{txn_hash}")
        assert "success" in response.json(), f"{response.text} - {txn_hash}"


    def account_balance(self, account_address: str) -> Optional[int]:
        """Returns the test coin balance associated with the account"""
        return self.account_resource(account_address, "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")

    def transfer(self, account_from: Account, recipient: str, amount: int) -> str:
        """Transfer a given coin amount from a given Account to the recipient's account address.
        Returns the sequence number of the transaction used to transfer."""

        payload = {
            "type": "script_function_payload",
            "function": "0x1::coin::transfer",
            "type_arguments": ["0x1::aptos_coin::AptosCoin"],
            "arguments": [
                f"0x{recipient}",
                str(amount),
            ]
        }
        txn_request = self.generate_transaction(
            account_from.address(), payload)
        signed_txn = self.sign_transaction(account_from, txn_request)
        res = self.submit_transaction(signed_txn)
        return str(res["hash"])


class FaucetClient:
    """Faucet creates and funds accounts. This is a thin wrapper around that."""

    def __init__(self, url: str, rest_client: RestClient) -> None:
        self.url = url
        self.rest_client = rest_client

    def fund_account(self, address: str, amount: int) -> None:
        """This creates an account if it does not exist and mints the specified amount of
        coins into that account."""
        txns = requests.post(
            f"{self.url}/mint?amount={amount}&address={address}")
        assert txns.status_code == 200, txns.text
        for txn_hash in txns.json():
            self.rest_client.wait_for_transaction(txn_hash)


class HelloBlockchainClient(RestClient):
    def publish_module(self, account_from: Account, module_hex: str) -> str:
        """Publish a new module to the blockchain within the specified account"""

        payload = {
            "type": "module_bundle_payload",
            "modules": [
                {"bytecode": f"0x{module_hex}"},
            ],
        }
        txn_request = self.generate_transaction(
            account_from.address(), payload)
        signed_txn = self.sign_transaction(account_from, txn_request)
        res = self.submit_transaction(signed_txn)
        return str(res["hash"])


    def get_value(self, contract_address: str, account_address: str) -> Optional[str]:
        """ Retrieve the resource value::ValueHolder::value """
        return self.account_resource(account_address, f"0x{contract_address}::value::ValueHolder")


    def set_value(self, contract_address: str, account_from: Account, value: str) -> str:
        """ Potentially initialize and set the resource value::ValueHolder::value """

        payload = {
            "type": "script_function_payload",
            "function": f"0x{contract_address}::value::set_value",
            "type_arguments": [],
            "arguments": [
                value.encode("utf-8").hex(),
            ]
        }
        res = self.execute_transaction_with_payload(account_from, payload)
        return str(res["hash"])


if __name__ == "__main__":
    assert len(
        sys.argv) == 2, "Expecting an argument that points to the helloblockchain module"

    client = HelloBlockchainClient(TESTNET_URL)
    faucet_client = FaucetClient(FAUCET_URL, client)

    oracle = Account()
    account = Account()

    print("\n=== Addresses ===")
    print(f"Oracle: {oracle.address()}")
    print(f"Account: {account.address()}")

    faucet_client.fund_account(oracle.address(), 5_000)
    faucet_client.fund_account(account.address(), 5_000)

    print("\n=== Initial Balances ===")
    print(f"Oracle: {client.account_balance(oracle.address())}")
    print(f"Account: {client.account_balance(account.address())}")

    input("\nUpdate the module with Oracle's address, build, copy to the provided path, and press enter.")
    module_path = sys.argv[1]
    with open(module_path, "rb") as f:
        module_hex = f.read().hex()

    print("\n=== Testing Oracle ===")
    print("Publishing...")
    tx_hash = client.publish_module(oracle, module_hex)
    client.wait_for_transaction(tx_hash)
    print(
        f"Initial value: {client.get_value(oracle.address(), oracle.address())}")
    print("Setting the value to \"Hello World\"")
    print(oracle.address(), oracle, "Hello World", sys.argv)
    tx_hash = client.set_value(oracle.address(), oracle, "Hello World")
    client.wait_for_transaction(tx_hash)
    print(f"New value: {client.get_value(oracle.address(), oracle.address())}")

    print("Setting the value to \"Hello World1\"")
    print(oracle.address(), oracle, "Hello World", sys.argv)
    tx_hash = client.set_value(oracle.address(), oracle, "Hello World1")
    client.wait_for_transaction(tx_hash)
    print(f"New value: {client.get_value(oracle.address(), oracle.address())}")
