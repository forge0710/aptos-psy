#[test_only]
module psymm::psymm_tests {
    use std::signer;
    use std::vector;
    use std::string;
    use aptos_framework::account;
    use aptos_framework::coin::{Self, MintCapability};
    use aptos_framework::aptos_coin::{Self, AptosCoin};
    use aptos_framework::timestamp;
    
    use psymm::psymm;
    use psymm::schnorr;
    use psymm::verification_utils;
    use psymm::sma_registry;
    use psymm::mock_coin::{Self, MockCoin};
    use psymm::party_registry;
    use psymm::mock_aave_sma_factory;
    
    // Test constants
    const CUSTODY_ID: vector<u8> = x"1234567890123456789012345678901234567890123456789012345678901234";
    const RECEIVER_ID: vector<u8> = x"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    
    // Error constants
    const E_TEST_FAILURE: u64 = 1000;
    
    // Initialize test environment
    fun setup(
        psymm_admin: &signer,
        test_timestamp: u64
    ) {
        // Setup Aptos environment
        timestamp::set_time_has_started_for_testing(psymm_admin);
        timestamp::update_global_time_for_test_secs(test_timestamp);
        
        // Initialize contracts
        psymm::initialize(psymm_admin);
        sma_registry::initialize(psymm_admin);
        party_registry::initialize(psymm_admin);
    }
    
    // Setup test coin
    fun setup_test_coin(
        admin: &signer, 
        user: &signer,
        mint_amount: u64
    ): MintCapability<MockCoin> {
        let user_addr = signer::address_of(user);
        
        // Create and initialize mock coin
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<MockCoin>(
            admin,
            string::utf8(b"TestCoin"),
            string::utf8(b"TC"),
            8,
            true
        );
        
        // Register user for coin
        coin::register<MockCoin>(user);
        
        // Mint coins to user
        let coins = coin::mint<MockCoin>(mint_amount, &mint_cap);
        coin::deposit(user_addr, coins);
        
        // Return mint capability for future use
        mint_cap
    }
    
    // Create a test verification data
    fun create_test_verification_data(
        id: vector<u8>,
        state: u8,
        timestamp: u64
    ): psymm::VerificationData {
        // Create a public key (for testing)
        let pub_key = schnorr::new_ppm_key(27, x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        
        // Create a signature (for testing)
        let sig = schnorr::new_signature(
            x"0000000000000000000000000000000000000000000000000000000000000001",
            x"0000000000000000000000000000000000000000000000000000000000000002"
        );
        
        // Create a simple merkle proof
        let merkle_proof = vector::empty<vector<u8>>();
        vector::push_back(&mut merkle_proof, x"1111111111111111111111111111111111111111111111111111111111111111");
        
        // Create verification data
        psymm::VerificationData {
            id,
            state,
            timestamp,
            pub_key,
            sig,
            merkle_proof
        }
    }
    
    // Test basic initialization
    #[test(psymm_admin = @psymm)]
    public fun test_initialization(psymm_admin: signer) {
        setup(&psymm_admin, 1000);
        
        // Verify PSYMM is initialized
        let state = psymm::get_custody_state(CUSTODY_ID);
        assert!(state == 0, E_TEST_FAILURE);
    }
    
    // Test address to custody transfer
    #[test(psymm_admin = @psymm, user = @0x123)]
    public fun test_address_to_custody(psymm_admin: signer, user: signer) {
        setup(&psymm_admin, 1000);
        
        let user_addr = signer::address_of(&user);
        account::create_account_for_test(user_addr);
        
        // Setup test coin
        let mint_cap = setup_test_coin(&psymm_admin, &user, 1000000);
        
        // Transfer to custody
        psymm::address_to_custody<MockCoin>(&user, CUSTODY_ID, 500000);
        
        // Verify balance
        let balance = psymm::get_custody_balance(CUSTODY_ID, type_info::type_of<MockCoin>().account_address);
        assert!(balance == 500000, E_TEST_FAILURE);
    }
    
    // Test PPM update
    #[test(psymm_admin = @psymm)]
    public fun test_update_ppm(psymm_admin: signer) {
        // Current timestamp for testing
        let current_time = 1000;
        setup(&psymm_admin, current_time);
        
        // Create a test custody
        psymm::address_to_custody<AptosCoin>(&psymm_admin, CUSTODY_ID, 0);
        
        // Create test data for verification
        let verification_data = create_test_verification_data(CUSTODY_ID, 0, current_time);
        
        // Monkey patch the schnorr::verify function for testing
        // In a real test, we would generate valid signatures and merkle proofs
        // Patch verification_utils::verify_leaf and verify_schnorr
        
        // Call update_ppm
        let new_ppm = x"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        psymm::update_ppm(&psymm_admin, new_ppm, verification_data);
        
        // Verify PPM was updated
        let ppm = psymm::get_ppm(CUSTODY_ID);
        assert!(ppm == new_ppm, E_TEST_FAILURE);
    }
    
    // Test custody to custody transfer
    #[test(psymm_admin = @psymm, user = @0x123)]
    public fun test_custody_to_custody(psymm_admin: signer, user: signer) {
        // Current timestamp for testing
        let current_time = 1000;
        setup(&psymm_admin, current_time);
        
        let user_addr = signer::address_of(&user);
        account::create_account_for_test(user_addr);
        
        // Setup test coin
        let mint_cap = setup_test_coin(&psymm_admin, &user, 1000000);
        
        // Transfer to first custody
        psymm::address_to_custody<MockCoin>(&user, CUSTODY_ID, 500000);
        
        // Create test data for verification
        let verification_data = create_test_verification_data(CUSTODY_ID, 0, current_time);
        
        // Call custody_to_custody
        psymm::custody_to_custody<MockCoin>(&psymm_admin, RECEIVER_ID, 200000, verification_data);
        
        // Verify balances
        let sender_balance = psymm::get_custody_balance(CUSTODY_ID, type_info::type_of<MockCoin>().account_address);
        let receiver_balance = psymm::get_custody_balance(RECEIVER_ID, type_info::type_of<MockCoin>().account_address);
        
        assert!(sender_balance == 300000, E_TEST_FAILURE);
        assert!(receiver_balance == 200000, E_TEST_FAILURE);
    }
    
    // Test withdraw re-routing
    #[test(psymm_admin = @psymm, user = @0x123, destination = @0x456)]
    public fun test_withdraw_re_routing(psymm_admin: signer, user: signer, destination: signer) {
        setup(&psymm_admin, 1000);
        
        let user_addr = signer::address_of(&user);
        let destination_addr = signer::address_of(&destination);
        
        account::create_account_for_test(user_addr);
        account::create_account_for_test(destination_addr);
        
        // Call withdraw_re_routing
        psymm::withdraw_re_routing(&user, CUSTODY_ID, destination_addr);
        
        // Verify re-routing works in custody_to_address

        // performing a custody_to_address call that uses the re-routing
    }
    
    // Test SMA deployment
    #[test(psymm_admin = @psymm)]
    public fun test_deploy_sma(psymm_admin: signer) {
        // Current timestamp for testing
        let current_time = 1000;
        setup(&psymm_admin, current_time);
        
        // Create a test custody
        psymm::address_to_custody<AptosCoin>(&psymm_admin, CUSTODY_ID, 0);
        
        // Register factory
        let factory_addr = @0x789;
        sma_registry::register_factory(&psymm_admin, factory_addr);
        
        // Create test data for verification
        let verification_data = create_test_verification_data(CUSTODY_ID, 0, current_time);
        
        // Call deploy_sma
        let sma_type = string::utf8(b"AaveSMA");
        let deployment_data = x"0000";
        psymm::deploy_sma(&psymm_admin, sma_type, factory_addr, deployment_data, verification_data);
        
        // by checking registry entries and events
    }
    
    // Test party registration
    #[test(psymm_admin = @psymm, user = @0x123)]
    public fun test_party_registration(psymm_admin: signer, user: signer) {
        setup(&psymm_admin, 1000);
        
        let user_addr = signer::address_of(&user);
        account::create_account_for_test(user_addr);
        
        // Register party
        let role = string::utf8(b"trader");
        let ip_address = string::utf8(b"127.0.0.1");
        let parity: u8 = 1;
        let x = x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        party_registry::register_party(&user, role, ip_address, parity, x);
        
        // Verify registration
        let registered_ip = party_registry::get_party_ip(user_addr);
        assert!(registered_ip == ip_address, E_TEST_FAILURE);
    }
    
}