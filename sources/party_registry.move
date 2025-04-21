module psymm::party_registry {
    use std::signer;
    use std::string::{Self, String};
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::event::{Self, EventHandle};
    
    use psymm::schnorr::{Self, PPMKey};

    // PartyData struct
    struct PartyData has copy, drop, store {
        role: String,
        ip_address: String,
        pub_key: PPMKey,
    }

    // Events
    struct PartyRegisteredEvent has drop, store {
        role: String,
        party: address,
        ip_address: String,
        pub_key: PPMKey,
    }

    struct PartyRemovedEvent has drop, store {
        party: address,
    }

    struct ReputationSetEvent has drop, store {
        party: address,
        kyc_provider: address,
        score: u64,
    }

    // Registry resources
    struct Registry has key {
        parties: vector<PartyEntry>,
        reputation: vector<ReputationEntry>,
        kyc_types: vector<KycTypeEntry>,
        
        // Event handles
        party_registered_events: EventHandle<PartyRegisteredEvent>,
        party_removed_events: EventHandle<PartyRemovedEvent>,
        reputation_set_events: EventHandle<ReputationSetEvent>,
    }

    struct PartyEntry has store, drop {
        party: address,
        data: PartyData,
    }

    struct ReputationEntry has store, drop {
        party: address,
        kyc_provider: address,
        score: u64,
    }

    struct KycTypeEntry has store, drop {
        party: address,
        kyc_provider: address,
        kyc_type: u8,
    }

    // Initialize the registry
    public entry fun initialize(admin: &signer) {
        move_to(admin, Registry {
            parties: vector::empty(),
            reputation: vector::empty(),
            kyc_types: vector::empty(),
            party_registered_events: account::new_event_handle<PartyRegisteredEvent>(admin),
            party_removed_events: account::new_event_handle<PartyRemovedEvent>(admin),
            reputation_set_events: account::new_event_handle<ReputationSetEvent>(admin),
        });
    }

    // Register as a party with IP address and public key
    public entry fun register_party(
        party: &signer,
        role: String,
        ip_address: String,
        parity: u8,
        x: vector<u8>
    ) acquires Registry {
        let party_addr = signer::address_of(party);
        let registry = borrow_global_mut<Registry>(account::get_signer_capability_address());
        
        // Create PPMKey
        let pub_key = schnorr::new_ppm_key(parity, x);
        
        // Create PartyData
        let party_data = PartyData {
            role,
            ip_address,
            pub_key,
        };
        
        // Check if party already exists
        let (exists, index) = find_party_index(&registry.parties, party_addr);
        
        if (exists) {
            // Update existing party
            let entry = vector::borrow_mut(&mut registry.parties, index);
            entry.data = party_data;
        } else {
            // Add new party
            vector::push_back(&mut registry.parties, PartyEntry {
                party: party_addr,
                data: party_data,
            });
        };
        
        // Emit event
        event::emit_event(
            &mut registry.party_registered_events,
            PartyRegisteredEvent {
                role,
                party: party_addr,
                ip_address,
                pub_key,
            }
        );
    }

    // Set KYC type for a party
    public entry fun set_kyc_type(
        party: &signer,
        kyc_provider: address,
        kyc_type: u8
    ) acquires Registry {
        let party_addr = signer::address_of(party);
        let registry = borrow_global_mut<Registry>(account::get_signer_capability_address());
        
        // Check if KYC entry already exists
        let (exists, index) = find_kyc_type_index(&registry.kyc_types, party_addr, kyc_provider);
        
        if (exists) {
            // Update existing entry
            let entry = vector::borrow_mut(&mut registry.kyc_types, index);
            entry.kyc_type = kyc_type;
        } else {
            // Add new entry
            vector::push_back(&mut registry.kyc_types, KycTypeEntry {
                party: party_addr,
                kyc_provider,
                kyc_type,
            });
        };
    }

    // Set reputation for a party
    public entry fun set_reputation(
        party: &signer,
        kyc_provider: address,
        score: u64
    ) acquires Registry {
        let party_addr = signer::address_of(party);
        let registry = borrow_global_mut<Registry>(account::get_signer_capability_address());
        
        // Check if reputation entry already exists
        let (exists, index) = find_reputation_index(&registry.reputation, party_addr, kyc_provider);
        
        if (exists) {
            // Update existing entry
            let entry = vector::borrow_mut(&mut registry.reputation, index);
            entry.score = score;
        } else {
            // Add new entry
            vector::push_back(&mut registry.reputation, ReputationEntry {
                party: party_addr,
                kyc_provider,
                score,
            });
        };
        
        // Emit event
        event::emit_event(
            &mut registry.reputation_set_events,
            ReputationSetEvent {
                party: party_addr,
                kyc_provider,
                score,
            }
        );
    }

    // Get party's IP address
    public fun get_party_ip(party: address): String acquires Registry {
        let registry = borrow_global<Registry>(account::get_signer_capability_address());
        
        // Find party
        let (exists, index) = find_party_index(&registry.parties, party);
        
        if (exists) {
            let entry = vector::borrow(&registry.parties, index);
            entry.data.ip_address
        } else {
            string::utf8(b"") // Return empty string if party not found
        }
    }

    // Get KYC type for a party
    public fun get_kyc_type(party: address, kyc_provider: address): u8 acquires Registry {
        let registry = borrow_global<Registry>(account::get_signer_capability_address());
        
        // Find KYC type
        let (exists, index) = find_kyc_type_index(&registry.kyc_types, party, kyc_provider);
        
        if (exists) {
            let entry = vector::borrow(&registry.kyc_types, index);
            entry.kyc_type
        } else {
            0 // Return 0 if not found
        }
    }

    // Get reputation for a party
    public fun get_reputation(party: address, kyc_provider: address): u64 acquires Registry {
        let registry = borrow_global<Registry>(account::get_signer_capability_address());
        
        // Find reputation
        let (exists, index) = find_reputation_index(&registry.reputation, party, kyc_provider);
        
        if (exists) {
            let entry = vector::borrow(&registry.reputation, index);
            entry.score
        } else {
            0 // Return 0 if not found
        }
    }

    // Helper function to find party index
    fun find_party_index(parties: &vector<PartyEntry>, party: address): (bool, u64) {
        let i = 0;
        let len = vector::length(parties);
        
        while (i < len) {
            let entry = vector::borrow(parties, i);
            if (entry.party == party) {
                return (true, i)
            };
            i = i + 1;
        };
        
        (false, 0)
    }

    // Helper function to find KYC type index
    fun find_kyc_type_index(kyc_types: &vector<KycTypeEntry>, party: address, kyc_provider: address): (bool, u64) {
        let i = 0;
        let len = vector::length(kyc_types);
        
        while (i < len) {
            let entry = vector::borrow(kyc_types, i);
            if (entry.party == party && entry.kyc_provider == kyc_provider) {
                return (true, i)
            };
            i = i + 1;
        };
        
        (false, 0)
    }

    // Helper function to find reputation index
    fun find_reputation_index(reputation: &vector<ReputationEntry>, party: address, kyc_provider: address): (bool, u64) {
        let i = 0;
        let len = vector::length(reputation);
        
        while (i < len) {
            let entry = vector::borrow(reputation, i);
            if (entry.party == party && entry.kyc_provider == kyc_provider) {
                return (true, i)
            };
            i = i + 1;
        };
        
        (false, 0)
    }
}