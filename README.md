## Before any futher you do, download Aptos-core following the instruction below

For the simplicity of this exercise, Aptos-core has a move-examples directory that makes it easy to build and test Move modules without downloading additional resources. Over time, we will expand this section to describe how to leverage Move tools for development.

---

For now, download and prepare Aptos-core:

```
git clone https://github.com/aptos-labs/aptos-core.git

cd aptos-core

./scripts/dev_setup.sh

source ~/.cargo/env

git checkout origin/devnet
```

Install Aptos Commandline tool

```
cargo install --git https://github.com/aptos-labs/aptos-core.git aptos
```

---

### Step 1 Move files

Move oracle folder to aptos-core API according to the following path: 
```
/aptos-core/aptos-move/move-examples/
```
Also, move **oracle.py**  according to the following path: 
```
/aptos-core/developer-docs-site/static/examples/python/
```

### Step 2 Initialize and interact with the Move module

Install the required libraries: pip3 install -r requirements.txt.

Execute the example in /aptos-core/developer-docs-site/static/examples/python/ 

```
python3 orace.py value.mv
```

Compile the modules with Oracle's address by

```
aptos move compile --package-dir . --named-addresses Oracle=0x{oracle_address_here}
```

Copy build/Examples/bytecode_modules/value.mv to the same folder as this tutorial project code.

At this point the outcome should show, that the value was changed a few times. All the transactions must be seen on the Aptos Explorer

---

Example oracle transactions on the [Aptos Explorer](https://aptos-explorer.netlify.app/account/0xbb6bff0f52101a226f847d451b738f6c7d6be2ab11bf3a968c4e96bf0154cd5c)