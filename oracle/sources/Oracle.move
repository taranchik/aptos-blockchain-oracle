module Oracle::value {
    use std::error;
    use aptos_std::event;
    use std::signer;

    struct ValueHolder<T: key> has key {
        value: T,
        value_change_events: event::EventHandle<ValueChangeEvent<T>>,
    }

    struct ValueChangeEvent<T: drop + store> has drop, store {
        from_value: T,
        to_value: T,
    }

    /// There is no value present
    const ENO_VALUE: u64 = 0;

    public fun get_value<T: key + store + copy>(addr: address): T acquires ValueHolder {
        assert!(exists<ValueHolder<T>>(addr), error::not_found(ENO_VALUE));
        *&borrow_global<ValueHolder<T>>(addr).value
    }

    public entry fun set_value<T: key + store + drop + copy>(account: signer, value: T)
    acquires ValueHolder {
        let account_addr = signer::address_of(&account);
        if (!exists<ValueHolder<T>>(account_addr)) {
            move_to(&account, ValueHolder<T> {
                value,
                value_change_events: event::new_event_handle<ValueChangeEvent<T>>(&account),
            })
        } else {
            let old_value_holder = borrow_global_mut<ValueHolder<T>>(account_addr);
            let from_value = *&old_value_holder.value;
            event::emit_event(&mut old_value_holder.value_change_events, ValueChangeEvent<T> {
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
