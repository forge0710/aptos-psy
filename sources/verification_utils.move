module psymm::verification_utils {
    use std::string;
    use std::string::String;
    use std::vector;
    use aptos_framework::account;
    use aptos_std::bcs;
    use aptos_std::hash;
    
    use psymm::schnorr::{PPMKey, Signature};

    public fun verify_leaf(
        ppm: vector<u8>,
        merkle_proof: vector<vector<u8>>,
        action: String,
        chain_id: address,
        contract_address: address,
        custody_state: u8,
        encoded_params: vector<u8>,
        pub_key_parity: u8,
        pub_key_x: vector<u8>
    ) {
        // Create leaf hash
        let data = vector::empty<u8>();
        
        // Append action
        let action_bytes = *string::bytes(&action);
        vector::append(&mut data, action_bytes);
        
        // Append chain_id
        let chain_id_bytes = bcs::to_bytes(&chain_id);
        vector::append(&mut data, chain_id_bytes);
        
        // Append contract_address
        let contract_address_bytes = bcs::to_bytes(&contract_address);
        vector::append(&mut data, contract_address_bytes);
        
        // Append custody_state
        let custody_state_bytes = bcs::to_bytes(&custody_state);
        vector::append(&mut data, custody_state_bytes);
        
        // Append encoded_params
        vector::append(&mut data, encoded_params);
        
        // Append public key info
        let parity_bytes = bcs::to_bytes(&pub_key_parity);
        vector::append(&mut data, parity_bytes);
        vector::append(&mut data, pub_key_x);
        
        // Hash the data to create leaf
        let leaf_preimage = hash::sha3_256(data);
        let leaf = hash::sha3_256(leaf_preimage);
        
        // Verify merkle proof
        verify_merkle_proof(merkle_proof, ppm, leaf);
    }

    fun verify_merkle_proof(
        proof: vector<vector<u8>>,
        root: vector<u8>,
        leaf: vector<u8>
    ): bool {
        let computed_hash = leaf;
        let proof_length = vector::length(&proof);
        
        let i = 0;
        while (i < proof_length) {
            let proof_element = *vector::borrow(&proof, i);
            
            // For simplicity, we'll combine hashes in a deterministic way
            let combined = vector::empty<u8>();
            vector::append(&mut combined, computed_hash);
            vector::append(&mut combined, proof_element);
            
            computed_hash = hash::sha3_256(combined);
            
            i = i + 1;
        };
        
        // Check if computed hash matches the root
        computed_hash == root
    }

    public fun verify_schnorr(
        message_data: vector<u8>,
        pub_key: PPMKey,
        sig: Signature
    ): bool {
        let message_hash = hash::sha3_256(message_data);
        psymm::schnorr::verify(pub_key, message_hash, sig)
    }
}