module psymm::psymm {
    use std::signer;
    use std::string::{Self, String};
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::coin;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::timestamp;
    use aptos_framework::aptos_account;
    use aptos_std::table::{Self, Table};
    use aptos_std::bcs;
    use aptos_std::type_info;
    
    use psymm::schnorr::{Self, PPMKey, Signature};
    use psymm::verification_utils;
    use psymm::sma_registry;

    // Error codes
    const E_INVALID_CUSTODY_STATE: u64 = 1;
    const E_INSUFFICIENT_BALANCE: u64 = 2;
    const E_NULLIFIER_USED: u64 = 3;
    const E_SIGNATURE_EXPIRED: u64 = 4;
    const E_SMA_NOT_WHITELISTED: u64 = 5;
    const E_NO_PERMISSION: u64 = 6;
    const E_ALREADY_CUSTODY_OWNER: u64 = 7;
    const E_SMA_CALL_FAILED: u64 = 8;
    const E_TIMESTAMP_TOO_OLD: u64 = 9;
    const E_UNAUTHORIZED: u64 = 10;

    // Verification data struct
    struct VerificationData has drop, copy {
        id: vector<u8>,          // bytes32 id
        state: u8,               // uint8 state
        timestamp: u64,          // uint256 timestamp
        pub_key: PPMKey,         // Schnorr.PPMKey pubKey
        sig: Signature,          // Schnorr.Signature sig
        merkle_proof: vector<vector<u8>>, // bytes32[] merkleProof
    }

    // Event structs
    struct PPMUpdatedEvent has drop, store {
        id: vector<u8>,
        ppm: vector<u8>,
        timestamp: u64,
    }

    struct CustodyStateChangedEvent has drop, store {
        id: vector<u8>,
        new_state: u8,
    }

    struct SMADeployedEvent has drop, store {
        id: vector<u8>,
        factory_address: address,
        sma_address: address,
    }
    
    struct AddressToCustodyEvent has drop, store {
        id: vector<u8>,
        token: address,
        amount: u64,
    }

    struct CustodyToCustodyEvent has drop, store {
        id: vector<u8>,
        receiver_id: vector<u8>,
        token: address,
        amount: u64,
    }

    struct CustodyToAddressEvent has drop, store {
        id: vector<u8>,
        token: address,
        destination: address,
        amount: u64,
    }

    struct CustodyToSMAEvent has drop, store {
        id: vector<u8>,
        token: address,
        sma_address: address,
        amount: u64,
    }

    struct CallSMAEvent has drop, store {
        id: vector<u8>,
        sma_type: String,
        sma_address: address,
        fixed_call_data: vector<u8>,
        tail_call_data: vector<u8>,
    }

    struct WithdrawReRoutingEvent has drop, store {
        id: vector<u8>,
        sender: address,
        destination: address,
    }

    struct SubmitProvisionalEvent has drop, store {
        id: vector<u8>,
        calldata: vector<u8>,
        msg: vector<u8>,
    }

    struct RevokeProvisionalEvent has drop, store {
        id: vector<u8>,
        calldata: vector<u8>,
        msg: vector<u8>,
    }

    struct DiscussProvisionalEvent has drop, store {
        id: vector<u8>,
        msg: vector<u8>,
    }

    // PSYMM resource
    struct PSYMMResource has key {
        // Event handles
        ppm_updated_events: EventHandle<PPMUpdatedEvent>,
        custody_state_changed_events: EventHandle<CustodyStateChangedEvent>,
        sma_deployed_events: EventHandle<SMADeployedEvent>,
        address_to_custody_events: EventHandle<AddressToCustodyEvent>,
        custody_to_custody_events: EventHandle<CustodyToCustodyEvent>,
        custody_to_address_events: EventHandle<CustodyToAddressEvent>,
        custody_to_sma_events: EventHandle<CustodyToSMAEvent>,
        call_sma_events: EventHandle<CallSMAEvent>,
        withdraw_re_routing_events: EventHandle<WithdrawReRoutingEvent>,
        submit_provisional_events: EventHandle<SubmitProvisionalEvent>,
        revoke_provisional_events: EventHandle<RevokeProvisionalEvent>,
        discuss_provisional_events: EventHandle<DiscussProvisionalEvent>,
    }

    struct CustodyStore has key {
        // Optimized storage using Move Tables
        custody_balances: Table<vector<u8>, Table<address, u64>>, // custodyId => (token => balance)
        ppms: Table<vector<u8>, vector<u8>>,                      // custodyId => ppm
        custody_states: Table<vector<u8>, u8>,                    // custodyId => state
        sma_allowances: Table<vector<u8>, Table<address, bool>>,  // custodyId => (smaAddress => isAllowed)
        only_custody_owner: Table<address, bool>,                 // smaAddress => isDeployed
        last_update_timestamps: Table<vector<u8>, u64>,           // custodyId => timestamp
        nullifiers: Table<vector<u8>, bool>,                      // nullifier => isUsed  
        withdraw_re_routings: Table<vector<u8>, Table<address, address>>, // custodyId => (sender => destination)
        
        // For storing custody messages
        custody_msgs: Table<vector<u8>, Table<u64, vector<u8>>>,  // custodyId => (msgId => message)
        custody_msg_lengths: Table<vector<u8>, u64>,              // custodyId => msgLength
    }

    // Initialize the PSYMM contract
    public entry fun initialize(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        
        // Create resource
        move_to(admin, PSYMMResource {
            ppm_updated_events: account::new_event_handle<PPMUpdatedEvent>(admin),
            custody_state_changed_events: account::new_event_handle<CustodyStateChangedEvent>(admin),
            sma_deployed_events: account::new_event_handle<SMADeployedEvent>(admin),
            address_to_custody_events: account::new_event_handle<AddressToCustodyEvent>(admin),
            custody_to_custody_events: account::new_event_handle<CustodyToCustodyEvent>(admin),
            custody_to_address_events: account::new_event_handle<CustodyToAddressEvent>(admin),
            custody_to_sma_events: account::new_event_handle<CustodyToSMAEvent>(admin),
            call_sma_events: account::new_event_handle<CallSMAEvent>(admin),
            withdraw_re_routing_events: account::new_event_handle<WithdrawReRoutingEvent>(admin),
            submit_provisional_events: account::new_event_handle<SubmitProvisionalEvent>(admin),
            revoke_provisional_events: account::new_event_handle<RevokeProvisionalEvent>(admin),
            discuss_provisional_events: account::new_event_handle<DiscussProvisionalEvent>(admin),
        });
        
        // Initialize store with empty tables
        move_to(admin, CustodyStore {
            custody_balances: table::new<vector<u8>, Table<address, u64>>(),
            ppms: table::new<vector<u8>, vector<u8>>(),
            custody_states: table::new<vector<u8>, u8>(),
            sma_allowances: table::new<vector<u8>, Table<address, bool>>(),
            only_custody_owner: table::new<address, bool>(),
            last_update_timestamps: table::new<vector<u8>, u64>(),
            nullifiers: table::new<vector<u8>, bool>(),
            withdraw_re_routings: table::new<vector<u8>, Table<address, address>>(),
            custody_msgs: table::new<vector<u8>, Table<u64, vector<u8>>>(),
            custody_msg_lengths: table::new<vector<u8>, u64>(),
        });
    }

    // Transfer tokens from an address to custody
    public entry fun address_to_custody<CoinType>(
        sender: &signer, 
        id: vector<u8>, 
        amount: u64
    ) acquires PSYMMResource, CustodyStore {
        let sender_addr = signer::address_of(sender);
        let token_address = type_info::type_of<CoinType>().address;
        let psymm_addr = @psymm;
        
        // Transfer tokens to the module
        let tokens = coin::withdraw<CoinType>(sender, amount);
        coin::deposit(psymm_addr, tokens);
        
        // Update custody balance
        let custody_store = borrow_global_mut<CustodyStore>(psymm_addr);
        
        // Ensure custody_id exists in the balances table
        if (!table::contains(&custody_store.custody_balances, id)) {
            table::add(&mut custody_store.custody_balances, id, table::new<address, u64>());
        };
        
        let balances = table::borrow_mut(&mut custody_store.custody_balances, id);
        
        // Update or initialize token balance
        if (table::contains(balances, token_address)) {
            let balance = table::borrow_mut(balances, token_address);
            *balance = *balance + amount;
        } else {
            table::add(balances, token_address, amount);
        };
        
        // Set PPM to id if not already set
        if (!table::contains(&custody_store.ppms, id)) {
            table::add(&mut custody_store.ppms, id, id);
        };
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.address_to_custody_events,
            AddressToCustodyEvent {
                id,
                token: token_address,
                amount,
            }
        );
    }

    // Transfer tokens from custody to address
    public entry fun custody_to_address<CoinType>(
        caller: &signer,
        destination: address,
        amount: u64,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        let token_address = type_info::type_of<CoinType>().address;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check custody balance
        check_custody_balance(v.id, token_address, amount);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"custodyToAddress"),
            @8888, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            encode_address(destination), // abi.encode(destination)
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_custody_to_address_message(v.timestamp, v.id, token_address, destination, amount),
            v.pub_key,
            v.sig
        );
        
        // Transfer tokens
        let final_destination = destination;
        let custody_store = borrow_global_mut<CustodyStore>(psymm_addr);
        
        // Check if re-routing exists
        if (table::contains(&custody_store.withdraw_re_routings, v.id)) {
            let routings = table::borrow(&custody_store.withdraw_re_routings, v.id);
            if (table::contains(routings, destination)) {
                final_destination = *table::borrow(routings, destination);
            };
        };
        
        // Update custody balance
        let balances = table::borrow_mut(&mut custody_store.custody_balances, v.id);
        let balance = table::borrow_mut(balances, token_address);
        *balance = *balance - amount;
        
        // Transfer tokens to destination
        let signer_cap = account::create_test_signer_capability(@psymm);
        let signer_ref = &account::create_signer_with_capability(signer_cap);
        let coins = coin::withdraw<CoinType>(signer_ref, amount);
        aptos_account::deposit_coins(final_destination, coins);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.custody_to_address_events,
            CustodyToAddressEvent {
                id: v.id,
                token: token_address,
                destination,
                amount,
            }
        );
    }

    // Transfer tokens from custody to custody
    public entry fun custody_to_custody<CoinType>(
        caller: &signer,
        receiver_id: vector<u8>,
        amount: u64,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        let token_address = type_info::type_of<CoinType>().account_address;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check custody balance
        check_custody_balance(v.id, token_address, amount);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"custodyToCustody"),
            @0, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            encode_custody_id(receiver_id), // abi.encode(receiverId)
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_custody_to_custody_message(v.timestamp, v.id, token_address, receiver_id, amount),
            v.pub_key,
            v.sig
        );
        
        // Transfer between custodies (internal accounting)
        let custody_store = borrow_global_mut<CustodyStore>(psymm_addr);
        
        {
            let balances = table::borrow_mut(&mut custody_store.custody_balances, v.id);
            let balance = table::borrow_mut(balances, token_address);
            *balance = *balance - amount;
        };
        
        {
            // Ensure receiver custody exists
            if (!table::contains(&custody_store.custody_balances, receiver_id)) {
                table::add(&mut custody_store.custody_balances, receiver_id, table::new<address, u64>());
            };
            
            let balances = table::borrow_mut(&mut custody_store.custody_balances, receiver_id);
            
            if (table::contains(balances, token_address)) {
                let balance = table::borrow_mut(balances, token_address);
                *balance = *balance + amount;
            } else {
                table::add(balances, token_address, amount);
            };
        };
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.custody_to_custody_events,
            CustodyToCustodyEvent {
                id: v.id,
                receiver_id,
                token: token_address,
                amount,
            }
        );
    }

    // Transfer tokens from custody to SMA
    public entry fun custody_to_sma<CoinType>(
        caller: &signer,
        sma_address: address,
        amount: u64,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        let token_address = type_info::type_of<CoinType>().account_address;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check custody balance
        check_custody_balance(v.id, token_address, amount);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Check SMA allowance and ownership
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        assert!(
            table::contains(&custody_store.sma_allowances, v.id) && 
            table::contains(table::borrow(&custody_store.sma_allowances, v.id), sma_address) &&
            *table::borrow(table::borrow(&custody_store.sma_allowances, v.id), sma_address),
            E_SMA_NOT_WHITELISTED
        );
        
        assert!(
            table::contains(&custody_store.only_custody_owner, sma_address) && 
            *table::borrow(&custody_store.only_custody_owner, sma_address),
            E_NO_PERMISSION
        );
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"custodyToSMA"),
            @8888, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            encode_sma_params(sma_address, token_address), // abi.encode(smaAddress, token)
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_custody_to_sma_message(v.timestamp, v.id, token_address, sma_address, amount),
            v.pub_key,
            v.sig
        );
        
        // Update custody balance
        let custody_store_mut = borrow_global_mut<CustodyStore>(psymm_addr);
        let balances = table::borrow_mut(&mut custody_store_mut.custody_balances, v.id);
        let balance = table::borrow_mut(balances, token_address);
        *balance = *balance - amount;
        
        // Transfer tokens to SMA
        let coins = coin::withdraw<CoinType>(&account::create_signer_with_capability(
            account::get_signer_capability(psymm_addr)), amount);
        aptos_account::deposit_coins(sma_address, coins);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.custody_to_sma_events,
            CustodyToSMAEvent {
                id: v.id,
                token: token_address,
                sma_address,
                amount,
            }
        );
    }

    // Update PPM (Programmable Proof of Merit - Merkle root)
    public entry fun update_ppm(
        caller: &signer,
        new_ppm: vector<u8>,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Check timestamp against last update
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        if (table::contains(&custody_store.last_update_timestamps, v.id)) {
            let last_timestamp = *table::borrow(&custody_store.last_update_timestamps, v.id);
            assert!(v.timestamp > last_timestamp, E_TIMESTAMP_TOO_OLD);
        };
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"updatePPM"),
            @8888, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            vector::empty<u8>(), // no extra parameters
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_update_ppm_message(v.timestamp, v.id, new_ppm),
            v.pub_key,
            v.sig
        );
        
        // Update PPM and timestamp
        let custody_store_mut = borrow_global_mut<CustodyStore>(psymm_addr);
        table::upsert(&mut custody_store_mut.ppms, v.id, new_ppm);
        table::upsert(&mut custody_store_mut.last_update_timestamps, v.id, v.timestamp);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.ppm_updated_events,
            PPMUpdatedEvent {
                id: v.id,
                ppm: new_ppm,
                timestamp: v.timestamp,
            }
        );
    }

    // Deploy SMA (Strategy Management Account)
    public entry fun deploy_sma(
        caller: &signer,
        sma_type: String,
        factory_address: address,
        data: vector<u8>,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Check timestamp against last update
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        if (table::contains(&custody_store.last_update_timestamps, v.id)) {
            let last_timestamp = *table::borrow(&custody_store.last_update_timestamps, v.id);
            assert!(v.timestamp > last_timestamp, E_TIMESTAMP_TOO_OLD);
        };
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"deploySMA"),
            @0, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            encode_deploy_sma_params(sma_type, factory_address, data),
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_deploy_sma_message(v.timestamp, v.id, sma_type, factory_address, data),
            v.pub_key,
            v.sig
        );
        
        // Deploy SMA using registry
        let sma_address = sma_registry::deploy_sma(caller, factory_address, data, psymm_addr);
        
        // Update SMA allowance and ownership
        let custody_store_mut = borrow_global_mut<CustodyStore>(psymm_addr);
        
        // Ensure SMA allowances table exists for custody
        if (!table::contains(&custody_store_mut.sma_allowances, v.id)) {
            table::add(&mut custody_store_mut.sma_allowances, v.id, table::new<address, bool>());
        };
        
        // Add SMA to allowance table
        let allowances = table::borrow_mut(&mut custody_store_mut.sma_allowances, v.id);
        table::upsert(allowances, sma_address, true);
        
        // Mark SMA as owned by custody
        table::upsert(&mut custody_store_mut.only_custody_owner, sma_address, true);
        
        // Update timestamp
        table::upsert(&mut custody_store_mut.last_update_timestamps, v.id, v.timestamp);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.sma_deployed_events,
            SMADeployedEvent {
                id: v.id,
                factory_address,
                sma_address,
            }
        );
    }

    // Call an SMA with action parameters
    public entry fun call_sma(
        caller: &signer,
        sma_type: String,
        sma_address: address,
        fixed_call_data: vector<u8>,
        tail_call_data: vector<u8>,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Check SMA allowance
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        assert!(
            table::contains(&custody_store.sma_allowances, v.id) && 
            table::contains(table::borrow(&custody_store.sma_allowances, v.id), sma_address) &&
            *table::borrow(table::borrow(&custody_store.sma_allowances, v.id), sma_address),
            E_SMA_NOT_WHITELISTED
        );
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"callSMA"),
            @0, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            encode_call_sma_params(sma_type, sma_address, fixed_call_data),
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Combine call data for signature verification
        let full_call_data = vector::empty<u8>();
        vector::append(&mut full_call_data, fixed_call_data);
        vector::append(&mut full_call_data, tail_call_data);
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_call_sma_message(v.timestamp, v.id, sma_type, sma_address, full_call_data),
            v.pub_key,
            v.sig
        );
        
        // Call SMA via registry
        let success = sma_registry::call_sma(caller, sma_address, full_call_data);
        assert!(success, E_SMA_CALL_FAILED);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.call_sma_events,
            CallSMAEvent {
                id: v.id,
                sma_type,
                sma_address,
                fixed_call_data,
                tail_call_data,
            }
        );
    }

    // Update custody state
    public entry fun update_custody_state(
        caller: &signer,
        state: u8,
        v: VerificationData
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        
        // Check custody state
        check_custody_state(v.id, v.state);
        
        // Check expiry
        check_expiry(v.timestamp);
        
        // Check nullifier
        check_nullifier(v.sig.e);
        
        // Verify leaf in Merkle tree
        verification_utils::verify_leaf(
            get_ppm(v.id),
            v.merkle_proof,
            string::utf8(b"changeCustodyState"),
            @0, // chain ID
            psymm_addr,
            get_custody_state(v.id),
            encode_u8(state), // abi.encode(state)
            v.pub_key.parity,
            v.pub_key.x
        );
        
        // Verify Schnorr signature
        verification_utils::verify_schnorr(
            encode_update_custody_state_message(v.timestamp, v.id, state),
            v.pub_key,
            v.sig
        );
        
        // Update custody state
        let custody_store_mut = borrow_global_mut<CustodyStore>(psymm_addr);
        table::upsert(&mut custody_store_mut.custody_states, v.id, state);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.custody_state_changed_events,
            CustodyStateChangedEvent {
                id: v.id,
                new_state: state,
            }
        );
    }

    // Set up withdraw re-routing (for redirecting claims from a dispute)
    public entry fun withdraw_re_routing(
        caller: &signer,
        id: vector<u8>,
        destination: address
    ) acquires PSYMMResource, CustodyStore {
        let psymm_addr = @psymm;
        let caller_addr = signer::address_of(caller);
        
        let custody_store_mut = borrow_global_mut<CustodyStore>(psymm_addr);
        
        // Ensure re-routing table exists for custody
        if (!table::contains(&custody_store_mut.withdraw_re_routings, id)) {
            table::add(&mut custody_store_mut.withdraw_re_routings, id, table::new<address, address>());
        };
        
        // Check if caller already has a re-routing
        let routings = table::borrow_mut(&mut custody_store_mut.withdraw_re_routings, id);
        assert!(!table::contains(routings, caller_addr), E_ALREADY_CUSTODY_OWNER);
        
        // Add re-routing
        table::add(routings, caller_addr, destination);
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.withdraw_re_routing_events,
            WithdrawReRoutingEvent {
                id,
                sender: caller_addr,
                destination,
            }
        );
    }

    // Submit provisional settlement
    public entry fun submit_provisional(
        caller: &signer,
        id: vector<u8>,
        calldata: vector<u8>,
        msg: vector<u8>
    ) acquires PSYMMResource {
        let psymm_addr = @psymm;
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.submit_provisional_events,
            SubmitProvisionalEvent {
                id,
                calldata,
                msg,
            }
        );
    }

    // Revoke provisional settlement
    public entry fun revoke_provisional(
        caller: &signer,
        id: vector<u8>,
        calldata: vector<u8>,
        msg: vector<u8>
    ) acquires PSYMMResource {
        let psymm_addr = @psymm;
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.revoke_provisional_events,
            RevokeProvisionalEvent {
                id,
                calldata,
                msg,
            }
        );
    }

    // Discuss provisional settlement
    public entry fun discuss_provisional(
        caller: &signer,
        id: vector<u8>,
        msg: vector<u8>
    ) acquires PSYMMResource {
        let psymm_addr = @psymm;
        
        // Emit event
        let psymm = borrow_global_mut<PSYMMResource>(psymm_addr);
        event::emit_event(
            &mut psymm.discuss_provisional_events,
            DiscussProvisionalEvent {
                id,
                msg,
            }
        );
    }

    // ============ Custody message functions ============

    // Add message to custody
    public entry fun add_custody_msg(
        caller: &signer,
        id: vector<u8>,
        msg: vector<u8>
    ) acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store_mut = borrow_global_mut<CustodyStore>(psymm_addr);
        
        // Ensure message table exists for custody
        if (!table::contains(&custody_store_mut.custody_msgs, id)) {
            table::add(&mut custody_store_mut.custody_msgs, id, table::new<u64, vector<u8>>());
            table::add(&mut custody_store_mut.custody_msg_lengths, id, 0);
        };
        
        // Get current message length
        let msg_length = *table::borrow(&custody_store_mut.custody_msg_lengths, id);
        
        // Add message
        let msgs = table::borrow_mut(&mut custody_store_mut.custody_msgs, id);
        table::add(msgs, msg_length, msg);
        
        // Increment message length
        *table::borrow_mut(&mut custody_store_mut.custody_msg_lengths, id) = msg_length + 1;
    }

    // ============ Read functions ============

    // Get custody state
    public fun get_custody_state(id: vector<u8>): u8 acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.custody_states, id)) {
            *table::borrow(&custody_store.custody_states, id)
        } else {
            0 // Default state
        }
    }

    // Get PPM (Programmable Proof of Merit - Merkle root)
    public fun get_ppm(id: vector<u8>): vector<u8> acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.ppms, id)) {
            *table::borrow(&custody_store.ppms, id)
        } else {
            vector::empty<u8>() // Default empty PPM
        }
    }

    // Get custody balance
    public fun get_custody_balance(id: vector<u8>, token: address): u64 acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.custody_balances, id)) {
            let balances = table::borrow(&custody_store.custody_balances, id);
            if (table::contains(balances, token)) {
                *table::borrow(balances, token)
            } else {
                0
            }
        } else {
            0
        }
    }

    // Get SMA allowance
    public fun get_sma_allowance(id: vector<u8>, sma_address: address): bool acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.sma_allowances, id)) {
            let allowances = table::borrow(&custody_store.sma_allowances, id);
            if (table::contains(allowances, sma_address)) {
                *table::borrow(allowances, sma_address)
            } else {
                false
            }
        } else {
            false
        }
    }

    // Get only custody owner
    public fun get_only_custody_owner(sma_address: address): bool acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.only_custody_owner, sma_address)) {
            *table::borrow(&custody_store.only_custody_owner, sma_address)
        } else {
            false
        }
    }

    // Get last SMA update timestamp
    public fun get_last_sma_update_timestamp(id: vector<u8>): u64 acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.last_update_timestamps, id)) {
            *table::borrow(&custody_store.last_update_timestamps, id)
        } else {
            0
        }
    }

    // Check if nullifier has been used
    public fun is_nullifier_used(nullifier: vector<u8>): bool acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        table::contains(&custody_store.nullifiers, nullifier)
    }

    // Get custody message
    public fun get_custody_msg(id: vector<u8>, msg_id: u64): vector<u8> acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.custody_msgs, id)) {
            let msgs = table::borrow(&custody_store.custody_msgs, id);
            if (table::contains(msgs, msg_id)) {
                *table::borrow(msgs, msg_id)
            } else {
                vector::empty<u8>()
            }
        } else {
            vector::empty<u8>()
        }
    }

    // Get custody message length
    public fun get_custody_msg_length(id: vector<u8>): u64 acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.custody_msg_lengths, id)) {
            *table::borrow(&custody_store.custody_msg_lengths, id)
        } else {
            0
        }
    }

    // ============ Helper functions ============

    // Check custody state
    fun check_custody_state(id: vector<u8>, expected_state: u8) acquires CustodyStore {
        let actual_state = get_custody_state(id);
        assert!(actual_state == expected_state, E_INVALID_CUSTODY_STATE);
    }

    // Check custody balance
    fun check_custody_balance(id: vector<u8>, token: address, amount: u64) acquires CustodyStore {
        let balance = get_custody_balance(id, token);
        assert!(balance >= amount, E_INSUFFICIENT_BALANCE);
    }

    // Check nullifier
    fun check_nullifier(nullifier_value: vector<u8>) acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global_mut<CustodyStore>(psymm_addr);
        
        // Check if nullifier already used
        assert!(!table::contains(&custody_store.nullifiers, nullifier_value), E_NULLIFIER_USED);
        
        // Mark as used
        table::add(&mut custody_store.nullifiers, nullifier_value, true);
    }

    // Check expiry
    fun check_expiry(timestamp_value: u64) {
        assert!(timestamp_value <= timestamp::now_seconds(), E_SIGNATURE_EXPIRED);
    }

    // Get withdraw re-routing
    fun get_withdraw_re_routing(id: vector<u8>, sender: address): address acquires CustodyStore {
        let psymm_addr = @psymm;
        let custody_store = borrow_global<CustodyStore>(psymm_addr);
        
        if (table::contains(&custody_store.withdraw_re_routings, id)) {
            let routings = table::borrow(&custody_store.withdraw_re_routings, id);
            if (table::contains(routings, sender)) {
                *table::borrow(routings, sender)
            } else {
                @0x0
            }
        } else {
            @0x0
        }
    }

    // ============ Encoding helper functions ============

    // Encode address
    fun encode_address(addr: address): vector<u8> {
        let encoded = vector::empty<u8>();
        let addr_bytes = bcs::to_bytes(&addr);
        vector::append(&mut encoded, addr_bytes);
        encoded
    }

    // Encode custody ID
    fun encode_custody_id(id: vector<u8>): vector<u8> {
        id
    }

    // Encode u8
    fun encode_u8(value: u8): vector<u8> {
        let encoded = vector::empty<u8>();
        let value_bytes = bcs::to_bytes(&value);
        vector::append(&mut encoded, value_bytes);
        encoded
    }

    // Encode SMA params
    fun encode_sma_params(sma_address: address, token: address): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let sma_bytes = bcs::to_bytes(&sma_address);
        vector::append(&mut encoded, sma_bytes);
        
        let token_bytes = bcs::to_bytes(&token);
        vector::append(&mut encoded, token_bytes);
        
        encoded
    }

    // Encode deploy SMA params
    fun encode_deploy_sma_params(sma_type: String, factory_address: address, data: vector<u8>): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let type_bytes = string::bytes(&sma_type);
        vector::append(&mut encoded, *type_bytes);
        
        let factory_bytes = bcs::to_bytes(&factory_address);
        vector::append(&mut encoded, factory_bytes);
        
        vector::append(&mut encoded, data);
        
        encoded
    }

    // Encode call SMA params
    fun encode_call_sma_params(sma_type: String, sma_address: address, fixed_call_data: vector<u8>): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let type_bytes = string::bytes(&sma_type);
        vector::append(&mut encoded, *type_bytes);
        
        let sma_bytes = bcs::to_bytes(&sma_address);
        vector::append(&mut encoded, sma_bytes);
        
        vector::append(&mut encoded, fixed_call_data);
        
        encoded
    }

    // Encode custody to address message
    fun encode_custody_to_address_message(
        timestamp: u64,
        id: vector<u8>,
        token: address,
        destination: address,
        amount: u64
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"custodyToAddress";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        let token_bytes = bcs::to_bytes(&token);
        vector::append(&mut encoded, token_bytes);
        
        let destination_bytes = bcs::to_bytes(&destination);
        vector::append(&mut encoded, destination_bytes);
        
        let amount_bytes = bcs::to_bytes(&amount);
        vector::append(&mut encoded, amount_bytes);
        
        encoded
    }

    // Encode custody to custody message
    fun encode_custody_to_custody_message(
        timestamp: u64,
        id: vector<u8>,
        token: address,
        receiver_id: vector<u8>,
        amount: u64
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"custodyToCustody";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        let token_bytes = bcs::to_bytes(&token);
        vector::append(&mut encoded, token_bytes);
        
        vector::append(&mut encoded, receiver_id);
        
        let amount_bytes = bcs::to_bytes(&amount);
        vector::append(&mut encoded, amount_bytes);
        
        encoded
    }

    // Encode custody to SMA message
    fun encode_custody_to_sma_message(
        timestamp: u64,
        id: vector<u8>,
        token: address,
        sma_address: address,
        amount: u64
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"custodyToSMA";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        let token_bytes = bcs::to_bytes(&token);
        vector::append(&mut encoded, token_bytes);
        
        let sma_bytes = bcs::to_bytes(&sma_address);
        vector::append(&mut encoded, sma_bytes);
        
        let amount_bytes = bcs::to_bytes(&amount);
        vector::append(&mut encoded, amount_bytes);
        
        encoded
    }

    // Encode update PPM message
    fun encode_update_ppm_message(
        timestamp: u64,
        id: vector<u8>,
        new_ppm: vector<u8>
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"updatePPM";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        vector::append(&mut encoded, new_ppm);
        
        encoded
    }

    // Encode deploy SMA message
    fun encode_deploy_sma_message(
        timestamp: u64,
        id: vector<u8>,
        sma_type: String,
        factory_address: address,
        data: vector<u8>
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"deploySMA";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        let type_bytes = string::bytes(&sma_type);
        vector::append(&mut encoded, *type_bytes);
        
        let factory_bytes = bcs::to_bytes(&factory_address);
        vector::append(&mut encoded, factory_bytes);
        
        vector::append(&mut encoded, data);
        
        encoded
    }

    // Encode call SMA message
    fun encode_call_sma_message(
        timestamp: u64,
        id: vector<u8>,
        sma_type: String,
        sma_address: address,
        call_data: vector<u8>
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"callSMA";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        let type_bytes = string::bytes(&sma_type);
        vector::append(&mut encoded, *type_bytes);
        
        let sma_bytes = bcs::to_bytes(&sma_address);
        vector::append(&mut encoded, sma_bytes);
        
        vector::append(&mut encoded, call_data);
        
        encoded
    }

    // Encode update custody state message
    fun encode_update_custody_state_message(
        timestamp: u64,
        id: vector<u8>,
        state: u8
    ): vector<u8> {
        let encoded = vector::empty<u8>();
        
        let timestamp_bytes = bcs::to_bytes(&timestamp);
        vector::append(&mut encoded, timestamp_bytes);
        
        let action = b"changeCustodyState";
        vector::append(&mut encoded, action);
        
        vector::append(&mut encoded, id);
        
        let state_bytes = bcs::to_bytes(&state);
        vector::append(&mut encoded, state_bytes);
        
        encoded
    }
}