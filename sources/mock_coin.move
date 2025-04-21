module psymm::mock_coin {
    use std::signer;
    use std::string::{Self, String};
    use aptos_framework::coin::{Self, MintCapability, BurnCapability, FreezeCapability};
    
    // Error codes
    const E_NOT_COIN_OWNER: u64 = 500;

    // Coin resource
    struct MockCoin {}

    // Capabilities resource
    struct Capabilities has key {
        mint_cap: MintCapability<MockCoin>,
        burn_cap: BurnCapability<MockCoin>,
        freeze_cap: FreezeCapability<MockCoin>,
    }

    // Initialize a new MockCoin
    public entry fun initialize(
        admin: &signer,
        name: String,
        symbol: String,
        decimals: u8
    ) {
        // Register the coin
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<MockCoin>(
            admin,
            name,
            symbol,
            decimals,
            true // monitor_supply
        );
        
        // Store capabilities
        move_to(admin, Capabilities {
            mint_cap,
            burn_cap,
            freeze_cap,
        });
    }

    // Mint new coins
    public entry fun mint(
        admin: &signer,
        to: address,
        amount: u64
    ) acquires Capabilities {
        let admin_addr = signer::address_of(admin);
        
        // Check if admin has capabilities
        assert!(exists<Capabilities>(admin_addr), E_NOT_COIN_OWNER);
        
        // Get mint capability
        let capabilities = borrow_global<Capabilities>(admin_addr);
        
        // Mint coins
        let coins = coin::mint(amount, &capabilities.mint_cap);
        
        // Deposit to recipient
        coin::deposit(to, coins);
    }

    // Burn coins
    public entry fun burn(
        admin: &signer,
        from: address,
        amount: u64
    ) acquires Capabilities {
        let admin_addr = signer::address_of(admin);
        
        // Check if admin has capabilities
        assert!(exists<Capabilities>(admin_addr), E_NOT_COIN_OWNER);
        
        // Get burn capability
        let capabilities = borrow_global<Capabilities>(admin_addr);
        
        // Withdraw coins from account (requires proper authorization in real implementation)
        let to_burn = coin::withdraw<MockCoin>(&account::create_signer_with_capability(account::get_signer_capability()), amount);
        
        // Burn coins
        coin::burn(to_burn, &capabilities.burn_cap);
    }

    // Register account to receive this coin
    public entry fun register_account(account: &signer) {
        coin::register<MockCoin>(account);
    }
}