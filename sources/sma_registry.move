module psymm::sma_registry {
    use std::signer;
    use std::string::{Self, String};
    use std::vector;
    use std::error;
    use aptos_framework::account;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_std::table::{Self, Table};

    // Error codes
    const E_INVALID_FACTORY: u64 = 600;
    const E_DEPLOYMENT_FAILED: u64 = 601;
    const E_CALL_FAILED: u64 = 602;
    const E_NOT_AUTHORIZED: u64 = 603;

    // SMA deployment event
    struct SMADeploymentEvent has drop, store {
        factory_address: address,
        sma_address: address,
        data: vector<u8>,
    }

    // SMA call event
    struct SMACallEvent has drop, store {
        sma_address: address,
        call_data: vector<u8>,
        success: bool,
    }

    // Registry resource
    struct Registry has key {
        factories: Table<address, bool>,                // Registered factory addresses
        sma_deployments: Table<address, SMADeployment>, // SMA address => deployment info
        authorized_callers: Table<address, bool>,       // Addresses authorized to deploy and call SMAs
        
        // Event handles
        deployment_events: EventHandle<SMADeploymentEvent>,
        call_events: EventHandle<SMACallEvent>,
    }

    // SMA deployment information
    struct SMADeployment has store, drop {
        factory: address,
        deployment_data: vector<u8>,
        owner: address,
    }

    // Initialize registry
    public entry fun initialize(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        
        // Create registry resource
        move_to(admin, Registry {
            factories: table::new<address, bool>(),
            sma_deployments: table::new<address, SMADeployment>(),
            authorized_callers: table::new<address, bool>(),
            deployment_events: account::new_event_handle<SMADeploymentEvent>(admin),
            call_events: account::new_event_handle<SMACallEvent>(admin),
        });
        
        // Add admin as authorized caller
        register_authorized_caller(admin, admin_addr);
    }

    // Register a factory
    public entry fun register_factory(admin: &signer, factory_address: address) acquires Registry {
        let admin_addr = signer::address_of(admin);
        check_authorized(admin_addr);
        
        let registry = borrow_global_mut<Registry>(@psymm);
        table::upsert(&mut registry.factories, factory_address, true);
    }

    // Register an authorized caller
    public entry fun register_authorized_caller(admin: &signer, caller: address) acquires Registry {
        let admin_addr = signer::address_of(admin);
        
        let registry = borrow_global_mut<Registry>(@psymm);
        
        // Check authorization (admin always authorized for first caller)
        if (table::contains(&registry.authorized_callers, admin_addr)) {
            check_authorized(admin_addr);
        };
        
        table::upsert(&mut registry.authorized_callers, caller, true);
    }

    // Deploy an SMA through a factory
    public fun deploy_sma(
        caller: &signer,
        factory_address: address,
        data: vector<u8>,
        owner: address
    ): address acquires Registry {
        let caller_addr = signer::address_of(caller);
        check_authorized(caller_addr);
        
        let registry = borrow_global_mut<Registry>(@psymm);
        
        // Check if factory is registered
        assert!(table::contains(&registry.factories, factory_address) && 
                *table::borrow(&registry.factories, factory_address), E_INVALID_FACTORY);
        
        // In a real implementation, this would call into the factory contract
        // For this mock, we'll create a resource account to simulate the SMA
        let salt = vector::empty<u8>();
        vector::append(&mut salt, b"sma_");
        vector::append(&mut salt, data);
        
        // Create a deterministic address based on factory and data
        let (sma_signer, _cap) = account::create_resource_account(caller, salt);
        let sma_address = signer::address_of(&sma_signer);
        
        // Store SMA deployment info
        table::add(&mut registry.sma_deployments, sma_address, SMADeployment {
            factory: factory_address,
            deployment_data: data,
            owner,
        });
        
        // Emit deployment event
        event::emit_event(
            &mut registry.deployment_events,
            SMADeploymentEvent {
                factory_address,
                sma_address,
                data,
            }
        );
        
        sma_address
    }

    // Call an SMA with the provided data
    public fun call_sma(
        caller: &signer,
        sma_address: address,
        call_data: vector<u8>
    ): bool acquires Registry {
        let caller_addr = signer::address_of(caller);
        check_authorized(caller_addr);
        
        let registry = borrow_global_mut<Registry>(@psymm);
        
        // Check if SMA exists
        assert!(table::contains(&registry.sma_deployments, sma_address), E_CALL_FAILED);
        
        // In a real implementation, this would dispatch the call to the SMA
        // For this mock, we'll simulate success (or failure based on some condition)
        let success = true; // In real impl, this would be result of actual call
        
        // Emit call event
        event::emit_event(
            &mut registry.call_events,
            SMACallEvent {
                sma_address,
                call_data,
                success,
            }
        );
        
        success
    }

    // Check if an address is authorized
    fun check_authorized(addr: address) acquires Registry {
        let registry = borrow_global<Registry>(@psymm);
        assert!(
            table::contains(&registry.authorized_callers, addr) && 
            *table::borrow(&registry.authorized_callers, addr),
            E_NOT_AUTHORIZED
        );
    }

    // Check if an SMA is deployed
    public fun is_sma_deployed(sma_address: address): bool acquires Registry {
        let registry = borrow_global<Registry>(@psymm);
        table::contains(&registry.sma_deployments, sma_address)
    }

    // Get SMA owner
    public fun get_sma_owner(sma_address: address): address acquires Registry {
        let registry = borrow_global<Registry>(@psymm);
        assert!(table::contains(&registry.sma_deployments, sma_address), E_CALL_FAILED);
        
        let deployment = table::borrow(&registry.sma_deployments, sma_address);
        deployment.owner
    }
}