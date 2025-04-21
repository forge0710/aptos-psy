module psymm::verification_utils {
    use std::error;
    use std::signer;
    use std::string::{Self, String};
    use std::vector;
    use aptos_std::aptos_hash;
    
    use psymm::schnorr::{Self, PPMKey, Signature};
    
    // Error codes
    const E_INVALID_MERKLE_PROOF: u64 = 200;
    const E_INVALID_SIGNATURE: u64 = 201;

    // Verifies that the provided leaf (built from the action parameters) is part of the given Merkle root.
    public fun verify_leaf(
        ppm: vector<u8>,
        merkle_proof: vector<vector<u8>>,
        action: String,
        chain_id: u64,
        contract_address: address,
        custody_state: u8,
        encoded_params: vector<u8>,
        pub_key_parity: u8,
        pub_key_x: vector<u8>
    ) {
        // Build the leaf hash from components
        let leaf = build_leaf(
            action,
            chain_id,
            contract_address,
            custody_state,
            encoded_params,
            pub_key_parity,
            pub_key_x
        );
        
        // Verify the Merkle proof
        let is_valid = verify_merkle_proof(merkle_proof, ppm, leaf);
        assert!(is_valid, error::invalid_argument(E_INVALID_MERKLE_PROOF));
    }

    // Builds a leaf hash from action parameters
    fun build_leaf(
        action: String,
        chain_id: u64,
        contract_address: address,
        custody_state: u8,
        encoded_params: vector<u8>,
        pub_key_parity: u8,
        pub_key_x: vector<u8>
    ): vector<u8> {
        // Create a concatenated buffer of all parameters
        let encoded = vector::empty<u8>();
        
        // Add action string
        let action_bytes = string::bytes(&action);
        vector::append(&mut encoded, *action_bytes);
        
        // Add chain ID
        let chain_id_bytes = bcs::to_bytes(&chain_id);
        vector::append(&mut encoded, chain_id_bytes);
        
        // Add contract address
        let contract_address_bytes = bcs::to_bytes(&contract_address);
        vector::append(&mut encoded, contract_address_bytes);
        
        // Add custody state
        let custody_state_bytes = bcs::to_bytes(&custody_state);
        vector::append(&mut encoded, custody_state_bytes);
        
        // Add encoded params
        vector::append(&mut encoded, encoded_params);
        
        // Add public key parity
        let parity_bytes = bcs::to_bytes(&pub_key_parity);
        vector::append(&mut encoded, parity_bytes);
        
        // Add public key x
        vector::append(&mut encoded, pub_key_x);
        
        // Apply keccak256 hash twice (similar to Solidity)
        let hash1 = aptos_hash::keccak256(&encoded);
        let leaf = aptos_hash::keccak256(&hash1);
        
        leaf
    }

    // Verifies a Merkle proof - optimized implementation
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
            
            // Determine order of concatenation by comparing hashes
            if (is_left_node(&computed_hash, &proof_element)) {
                // Current hash on left, proof element on right
                let combined = concat_and_hash(&computed_hash, &proof_element);
                computed_hash = combined;
            } else {
                // Proof element on left, current hash on right
                let combined = concat_and_hash(&proof_element, &computed_hash);
                computed_hash = combined;
            };
            
            i = i + 1;
        };
        
        // Check if the computed hash matches the root
        computed_hash == root
    }
    
    // Helper to concatenate and hash two nodes
    fun concat_and_hash(left: &vector<u8>, right: &vector<u8>): vector<u8> {
        let combined = vector::empty<u8>();
        vector::append(&mut combined, *left);
        vector::append(&mut combined, *right);
        
        aptos_hash::keccak256(&combined)
    }
    
    // Determines if first hash should be on left side
    // This is a critical function for correct Merkle tree verification
    fun is_left_node(a: &vector<u8>, b: &vector<u8>): bool {
        let i = 0;
        let len_a = vector::length(a);
        let len_b = vector::length(b);
        
        // Both should be 32 bytes (keccak256 output)
        assert!(len_a == 32 && len_b == 32, error::invalid_argument(E_INVALID_MERKLE_PROOF));
        
        // Compare byte-by-byte
        while (i < 32) {
            let byte_a = *vector::borrow(a, i);
            let byte_b = *vector::borrow(b, i);
            
            if (byte_a < byte_b) {
                return true
            } else if (byte_a > byte_b) {
                return false
            };
            
            i = i + 1;
        };
        
        // Hashes are equal (should never happen in a valid Merkle tree)
        false
    }

    // Verifies a Schnorr signature
    public fun verify_schnorr(
        message_data: vector<u8>,
        pub_key: PPMKey,
        sig: Signature
    ): bool {
        // Hash the message data
        let message = aptos_hash::keccak256(&message_data);
        
        // Verify the signature
        let is_valid = schnorr::verify(pub_key, message, sig);
        assert!(is_valid, error::invalid_argument(E_INVALID_SIGNATURE));
        
        true
    }
}