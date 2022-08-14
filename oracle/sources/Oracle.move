module Oracle::value {
    use std::string;
    use std::error;
    use aptos_std::event;
    use std::signer;

    struct ValueHolder has key {
        value: string::String,
        value_change_events: event::EventHandle<ValueChangeEvent>,
    }

    struct ValueChangeEvent has drop, store {
        from_value: string::String,
        to_value: string::String,
    }

    /// There is no value present
    const ENO_VALUE: u64 = 0;

    public fun get_value(addr: address): string::String acquires ValueHolder {
        assert!(exists<ValueHolder>(addr), error::not_found(ENO_VALUE));
        *&borrow_global<ValueHolder>(addr).value
    }

    public entry fun set_value(account: signer, value_bytes: vector<u8>)
    acquires ValueHolder {
        let value = string::utf8(value_bytes);
        let account_addr = signer::address_of(&account);
        if (!exists<ValueHolder>(account_addr)) {
            move_to(&account, ValueHolder {
                value,
                value_change_events: event::new_event_handle<ValueChangeEvent>(&account),
            })
        } else {
            let old_value_holder = borrow_global_mut<ValueHolder>(account_addr);
            let from_value = *&old_value_holder.value;
            event::emit_event(&mut old_value_holder.value_change_events, ValueChangeEvent {
                from_value,
                to_value: copy value,
            });
            old_value_holder.value = value;
        }
    }

    #[test(account = @0x1)]
    public entry fun sender_can_set_value(account: signer) acquires ValueHolder {
        let addr = signer::address_of(&account);
        set_value(account,  b"Hello, Blockchain");

        assert!(
          get_value(addr) == string::utf8(b"Hello, Blockchain"),
          ENO_VALUE
        );
    }
}
