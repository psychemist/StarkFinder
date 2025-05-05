#[starknet::contract]
pub mod ParametricInsurance {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, Map};
    use core::integer::u256;
    use core::num::traits::Zero;
    use core::option::OptionTrait;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    
    // Oracle interface to fetch external data
    #[starknet::interface]
    pub trait IOracle<TContractState> {
        fn get_latest_price(self: @TContractState, data_feed_id: felt252) -> (u128, u64); // (price, timestamp)
        fn get_latest_weather_data(self: @TContractState, location_id: felt252) -> (u8, u64); // (hurricane_category, timestamp)
        fn get_latest_yield_data(self: @TContractState, crop_id: felt252) -> (u64, u64); // (yield_percentage, timestamp)
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    pub struct OracleDispatcher {
        pub contract_address: ContractAddress,
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    pub struct InsurancePool {
        pub pool_token: ContractAddress,        // Token used for premiums and payouts
        pub total_liquidity: u256,              // Total liquidity in the pool
        pub total_staked: u256,                 // Total staked by underwriters
        pub total_premiums: u256,               // Total premiums collected
        pub total_payouts: u256,                // Total payouts made
        pub is_active: bool,                    // Whether the pool is active
        pub reward_rate: u256,                  // Reward rate for underwriters (per second)
        pub last_update_time: u64,              // Last time rewards were updated
        pub reserved_for_claims: u256,          // Amount reserved for potential claims
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    pub struct Policy {
        pub policy_holder: ContractAddress,     // Policy holder address
        pub premium_amount: u256,               // Premium amount paid
        pub coverage_amount: u256,              // Coverage amount
        pub start_time: u64,                    // Policy start time
        pub end_time: u64,                      // Policy end time
        pub trigger_type: TriggerType,          // Type of trigger for payout
        pub trigger_value: u256,                // Threshold value that triggers payout
        pub location_id: felt252,               // Location identifier (e.g., for weather)
        pub data_feed_id: felt252,              // Oracle data feed identifier
        pub is_active: bool,                    // Whether the policy is active
        pub is_claimed: bool,                   // Whether a claim has been paid out
        pub underwriting_pool_id: u64,          // Pool ID that underwrites this policy
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    pub struct StakerInfo {
        pub staked_amount: u256,                // Amount staked by underwriter
        pub reward_debt: u256,                  // Used for reward calculations
        pub last_stake_time: u64,               // Last time stake was updated
    }
    
    // Enum to represent different trigger types for parametric insurance
    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
    pub enum TriggerType {
        HurricaneCategory: (),                  // Hurricane category ≥ threshold
        DroughtIndex: (),                       // Drought index ≥ threshold
        FloodLevel: (),                         // Flood level ≥ threshold
        CropYield: (),                          // Crop yield ≤ threshold (percentage)
        TemperatureExtreme: (),                 // Temperature ≥ or ≤ threshold
        Earthquake: (),                         // Earthquake magnitude ≥ threshold
    }

    // Enum for policy status
    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
    pub enum PolicyStatus {
        Active: (),
        Expired: (),
        Claimed: (),
        Cancelled: (),
    }
    
    // Constants for actuarial calculations
    const BASIS_POINTS: u256 = 10000;            // 100% in basis points
    const MIN_PREMIUM_RATE: u256 = 100;          // 1% minimum premium rate
    const MAX_PREMIUM_RATE: u256 = 3000;         // 30% maximum premium rate
    const LIQUIDITY_BUFFER: u256 = 1500;         // 15% buffer for liquidity
    const REWARD_DISTRIBUTION_RATE: u256 = 500;  // 5% distribution rate for rewards
    const MIN_COVERAGE_PERIOD: u64 = 86400;      // 1 day minimum coverage period
    const MAX_COVERAGE_PERIOD: u64 = 31536000;   // 1 year maximum coverage period
    const ORACLE_STALENESS_THRESHOLD: u64 = 3600; // 1 hour oracle data staleness threshold

    #[storage]
    struct Storage {
        owner: ContractAddress,                 // Contract owner
        active_pools: u64,                       // Number of active pools
        active_policies: u64,                    // Number of active policies
        pools: Map<u64, InsurancePool>,          // Map of pool ID to pool info
        policies: Map<u64, Policy>,              // Map of policy ID to policy info
        policy_status: Map<u64, PolicyStatus>,   // Map of policy ID to status
        staker_info: Map<(u64, ContractAddress), StakerInfo>, // Pool ID, staker address to staker info
        policy_count_by_user: Map<ContractAddress, u64>, // Number of policies by user
        user_policies: Map<(ContractAddress, u64), u64>, // User address, index to policy ID
        oracle_dispatcher: OracleDispatcher,     // Oracle dispatcher
        emergency_paused: bool,                  // Emergency pause switch
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PoolCreated: PoolCreated,
        PolicyIssued: PolicyIssued,
        ClaimPaid: ClaimPaid,
        StakeLiquidity: StakeLiquidity,
        UnstakeLiquidity: UnstakeLiquidity,
        RewardsHarvested: RewardsHarvested,
        PolicyStatusChanged: PolicyStatusChanged,
        OracleUpdated: OracleUpdated,
        EmergencyPaused: EmergencyPaused,
    }

    #[derive(Drop, starknet::Event)]
    struct PoolCreated {
        #[key]
        pool_id: u64,
        pool_token: ContractAddress,
        initial_liquidity: u256,
        reward_rate: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PolicyIssued {
        #[key]
        policy_id: u64,
        #[key]
        policy_holder: ContractAddress,
        premium_amount: u256,
        coverage_amount: u256,
        start_time: u64,
        end_time: u64,
        trigger_type: TriggerType,
        trigger_value: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ClaimPaid {
        #[key]
        policy_id: u64,
        #[key]
        policy_holder: ContractAddress,
        amount: u256,
        trigger_value: u256,
        oracle_value: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StakeLiquidity {
        #[key]
        pool_id: u64,
        #[key]
        staker: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct UnstakeLiquidity {
        #[key]
        pool_id: u64,
        #[key]
        staker: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct RewardsHarvested {
        #[key]
        pool_id: u64,
        #[key]
        staker: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PolicyStatusChanged {
        #[key]
        policy_id: u64,
        status: PolicyStatus,
    }

    #[derive(Drop, starknet::Event)]
    struct OracleUpdated {
        old_oracle: ContractAddress,
        new_oracle: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyPaused {
        is_paused: bool,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, oracle_address: ContractAddress) {
        self.owner.write(owner);
        self.active_pools.write(0);
        self.active_policies.write(0);
        self.oracle_dispatcher.write(OracleDispatcher { contract_address: oracle_address });
        self.emergency_paused.write(false);
    }

    #[external(v0)]
    impl ParametricInsuranceImpl of super::IParametricInsurance<ContractState> {
        // Create a new insurance pool
        fn create_pool(
            ref self: ContractState, 
            pool_token: ContractAddress, 
            initial_liquidity: u256,
            reward_rate: u256
        ) -> u64 {
            // Only owner can create pools
            self.assert_only_owner();
            self.assert_not_paused();
            
            // Validate inputs
            assert(!pool_token.is_zero(), 'Invalid token');
            assert(initial_liquidity > 0, 'Zero liquidity');
            
            // Get pool ID
            let pool_id = self.active_pools.read();
            
            // Create pool
            let pool = InsurancePool {
                pool_token,
                total_liquidity: initial_liquidity,
                total_staked: initial_liquidity, // Initially, all liquidity is staked
                total_premiums: 0,
                total_payouts: 0,
                is_active: true,
                reward_rate,
                last_update_time: get_block_timestamp(),
                reserved_for_claims: 0,
            };
            
            // Store pool in storage
            self.pools.write(pool_id, pool);
            
            // Transfer tokens from owner to contract
            let owner = self.owner.read();
            let token_dispatcher = IERC20Dispatcher { contract_address: pool_token };
            let success = token_dispatcher.transfer_from(
                owner, 
                get_contract_address(), 
                initial_liquidity
            );
            assert(success, 'Transfer failed');
            
            // Update owner's stake in the pool
            let staker_info = StakerInfo {
                staked_amount: initial_liquidity,
                reward_debt: 0,
                last_stake_time: get_block_timestamp(),
            };
            self.staker_info.write((pool_id, owner), staker_info);
            
            // Increment active pools
            self.active_pools.write(pool_id + 1);
            
            // Emit event
            self.emit(PoolCreated { 
                pool_id, 
                pool_token, 
                initial_liquidity, 
                reward_rate 
            });
            
            pool_id
        }
        
        // Purchase an insurance policy
        fn purchase_policy(
            ref self: ContractState,
            pool_id: u64,
            coverage_amount: u256,
            duration: u64,
            trigger_type: TriggerType,
            trigger_value: u256,
            location_id: felt252,
            data_feed_id: felt252
        ) -> u64 {
            self.assert_not_paused();
            
            // Get caller
            let caller = get_caller_address();
            
            // Get pool
            let mut pool = self.pools.read(pool_id);
            assert(pool.is_active, 'Pool inactive');
            
            // Check duration
            assert(duration >= MIN_COVERAGE_PERIOD, 'Duration too short');
            assert(duration <= MAX_COVERAGE_PERIOD, 'Duration too long');
            
            // Calculate policy premium based on actuarial model
            let premium_amount = self.calculate_premium(
                coverage_amount,
                duration,
                trigger_type,
                trigger_value
            );
            
            // Check if pool has enough liquidity to cover potential claim
            let available_for_coverage = pool.total_liquidity - pool.reserved_for_claims;
            assert(available_for_coverage >= coverage_amount, 'Insufficient pool liquidity');
            
            // Transfer premium from user to contract
            let token_dispatcher = IERC20Dispatcher { contract_address: pool.pool_token };
            let success = token_dispatcher.transfer_from(
                caller, 
                get_contract_address(), 
                premium_amount
            );
            assert(success, 'Premium transfer failed');
            
            // Update pool state
            pool.total_premiums += premium_amount;
            pool.total_liquidity += premium_amount;
            pool.reserved_for_claims += coverage_amount;
            self.pools.write(pool_id, pool);
            
            // Get policy ID
            let policy_id = self.active_policies.read();
            
            // Create policy
            let current_time = get_block_timestamp();
            let policy = Policy {
                policy_holder: caller,
                premium_amount,
                coverage_amount,
                start_time: current_time,
                end_time: current_time + duration,
                trigger_type,
                trigger_value,
                location_id,
                data_feed_id,
                is_active: true,
                is_claimed: false,
                underwriting_pool_id: pool_id,
            };
            
            // Store policy
            self.policies.write(policy_id, policy);
            self.policy_status.write(policy_id, PolicyStatus::Active(()));
            
            // Store policy for user lookup
            let user_policy_count = self.policy_count_by_user.read(caller);
            self.user_policies.write((caller, user_policy_count), policy_id);
            self.policy_count_by_user.write(caller, user_policy_count + 1);
            
            // Increment active policies
            self.active_policies.write(policy_id + 1);
            
            // Emit event
            self.emit(PolicyIssued { 
                policy_id, 
                policy_holder: caller, 
                premium_amount, 
                coverage_amount, 
                start_time: current_time, 
                end_time: current_time + duration, 
                trigger_type, 
                trigger_value 
            });
            
            policy_id
        }
        
        // Check for claim eligibility and process claim if eligible
        fn check_claim(ref self: ContractState, policy_id: u64) -> bool {
            self.assert_not_paused();
            
            // Get policy
            let mut policy = self.policies.read(policy_id);
            let caller = get_caller_address();
            
            // Check policy exists and belongs to caller
            assert(policy.policy_holder == caller, 'Not policy holder');
            assert(policy.is_active, 'Policy not active');
            assert(!policy.is_claimed, 'Policy already claimed');
            
            // Check if policy is expired
            let current_time = get_block_timestamp();
            if current_time > policy.end_time {
                // Update policy status
                policy.is_active = false;
                self.policies.write(policy_id, policy);
                self.policy_status.write(policy_id, PolicyStatus::Expired(()));
                self.emit(PolicyStatusChanged { policy_id, status: PolicyStatus::Expired(()) });
                
                // Release reserved funds
                let mut pool = self.pools.read(policy.underwriting_pool_id);
                pool.reserved_for_claims -= policy.coverage_amount;
                self.pools.write(policy.underwriting_pool_id, pool);
                
                return false;
            }
            
            // Check claim eligibility based on oracle data
            let is_eligible = self.is_claim_eligible(policy_id);
            
            if is_eligible {
                // Process claim
                self.process_claim(policy_id);
                return true;
            }
            
            false
        }
        
        // Stake liquidity to a pool
        fn stake_liquidity(ref self: ContractState, pool_id: u64, amount: u256) {
            self.assert_not_paused();
            
            // Get caller
            let caller = get_caller_address();
            
            // Get pool
            let mut pool = self.pools.read(pool_id);
            assert(pool.is_active, 'Pool inactive');
            
            // Transfer tokens from caller to contract
            let token_dispatcher = IERC20Dispatcher { contract_address: pool.pool_token };
            let success = token_dispatcher.transfer_from(
                caller, 
                get_contract_address(), 
                amount
            );
            assert(success, 'Transfer failed');
            
            // Update pool state
            pool.total_liquidity += amount;
            pool.total_staked += amount;
            self.pools.write(pool_id, pool);
            
            // Update staker info
            let mut staker = self.staker_info.read((pool_id, caller));
            
            // Calculate pending rewards before updating stake
            let pending_rewards = self.calculate_rewards(pool_id, caller);
            
            // Update staker info
            staker.staked_amount += amount;
            staker.last_stake_time = get_block_timestamp();
            
            // Update reward debt
            staker.reward_debt = pending_rewards;
            
            self.staker_info.write((pool_id, caller), staker);
            
            // Emit event
            self.emit(StakeLiquidity { pool_id, staker: caller, amount });
        }
        
        // Unstake liquidity from a pool
        fn unstake_liquidity(ref self: ContractState, pool_id: u64, amount: u256) {
            self.assert_not_paused();
            
            // Get caller
            let caller = get_caller_address();
            
            // Get pool
            let mut pool = self.pools.read(pool_id);
            
            // Get staker info
            let mut staker = self.staker_info.read((pool_id, caller));
            assert(staker.staked_amount >= amount, 'Insufficient stake');
            
            // Calculate available liquidity (accounting for reserved claims)
            let available_liquidity = pool.total_liquidity - pool.reserved_for_claims;
            assert(available_liquidity >= amount, 'Insufficient available liquidity');
            
            // Calculate and harvest pending rewards
            let pending_rewards = self.calculate_rewards(pool_id, caller);
            if pending_rewards > 0 {
                // Transfer rewards
                let token_dispatcher = IERC20Dispatcher { contract_address: pool.pool_token };
                let success = token_dispatcher.transfer(caller, pending_rewards);
                assert(success, 'Reward transfer failed');
                
                // Emit event
                self.emit(RewardsHarvested { pool_id, staker: caller, amount: pending_rewards });
            }
            
            // Update staker info
            staker.staked_amount -= amount;
            staker.last_stake_time = get_block_timestamp();
            staker.reward_debt = 0; // Reset reward debt after harvest
            
            self.staker_info.write((pool_id, caller), staker);
            
            // Update pool state
            pool.total_liquidity -= amount;
            pool.total_staked -= amount;
            self.pools.write(pool_id, pool);
            
            // Transfer tokens from contract to caller
            let token_dispatcher = IERC20Dispatcher { contract_address: pool.pool_token };
            let success = token_dispatcher.transfer(caller, amount);
            assert(success, 'Transfer failed');
            
            // Emit event
            self.emit(UnstakeLiquidity { pool_id, staker: caller, amount });
        }
        
        // Harvest rewards from staking
        fn harvest_rewards(ref self: ContractState, pool_id: u64) -> u256 {
            self.assert_not_paused();
            
            // Get caller
            let caller = get_caller_address();
            
            // Get pool
            let pool = self.pools.read(pool_id);
            
            // Calculate pending rewards
            let pending_rewards = self.calculate_rewards(pool_id, caller);
            assert(pending_rewards > 0, 'No rewards');
            
            // Update staker info
            let mut staker = self.staker_info.read((pool_id, caller));
            staker.reward_debt = 0; // Reset reward debt after harvest
            self.staker_info.write((pool_id, caller), staker);
            
            // Transfer rewards
            let token_dispatcher = IERC20Dispatcher { contract_address: pool.pool_token };
            let success = token_dispatcher.transfer(caller, pending_rewards);
            assert(success, 'Reward transfer failed');
            
            // Emit event
            self.emit(RewardsHarvested { pool_id, staker: caller, amount: pending_rewards });
            
            pending_rewards
        }
        
        // Get policy details
        fn get_policy(self: @ContractState, policy_id: u64) -> Policy {
            self.policies.read(policy_id)
        }
        
        // Get pool details
        fn get_pool(self: @ContractState, pool_id: u64) -> InsurancePool {
            self.pools.read(pool_id)
        }
        
        // Get staker info
        fn get_staker_info(self: @ContractState, pool_id: u64, staker: ContractAddress) -> StakerInfo {
            self.staker_info.read((pool_id, staker))
        }
        
        // Get user's policies
        fn get_user_policies(self: @ContractState, user: ContractAddress) -> Array<u64> {
            let policy_count = self.policy_count_by_user.read(user);
            let mut policies = ArrayTrait::new();
            
            let mut i: u64 = 0;
            while i < policy_count {
                let policy_id = self.user_policies.read((user, i));
                policies.append(policy_id);
                i += 1;
            }
            
            policies
        }
        
        // Check if a claim is eligible based on oracle data
        fn is_claim_eligible(self: @ContractState, policy_id: u64) -> bool {
            let policy = self.policies.read(policy_id);
            let oracle = self.oracle_dispatcher.read();
            
            // Get data from oracle based on trigger type
            match policy.trigger_type {
                TriggerType::HurricaneCategory(()) => {
                    let (category, timestamp) = IOracle::get_latest_weather_data(
                        @oracle.contract_address, 
                        policy.location_id
                    );
                    
                    // Check data freshness
                    let current_time = get_block_timestamp();
                    if current_time - timestamp > ORACLE_STALENESS_THRESHOLD {
                        return false; // Data is stale
                    }
                    
                    // Check if category meets or exceeds trigger value
                    return category >= policy.trigger_value.try_into().unwrap();
                },
                TriggerType::DroughtIndex(()) => {
                    // Similar implementation for drought index
                    false // Placeholder for actual implementation
                },
                TriggerType::FloodLevel(()) => {
                    // Similar implementation for flood level
                    false // Placeholder for actual implementation
                },
                TriggerType::CropYield(()) => {
                    let (yield_percentage, timestamp) = IOracle::get_latest_yield_data(
                        @oracle.contract_address, 
                        policy.crop_id
                    );
                    
                    // Check data freshness
                    let current_time = get_block_timestamp();
                    if current_time - timestamp > ORACLE_STALENESS_THRESHOLD {
                        return false; // Data is stale
                    }
                    
                    // For crop yield, we check if yield is BELOW trigger value
                    return yield_percentage <= policy.trigger_value.try_into().unwrap();
                },
                TriggerType::TemperatureExtreme(()) => {
                    // Similar implementation for temperature
                    false // Placeholder for actual implementation
                },
                TriggerType::Earthquake(()) => {
                    // Similar implementation for earthquake magnitude
                    false // Placeholder for actual implementation
                },
            }
        }
        
        // Update oracle address (only owner)
        fn update_oracle(ref self: ContractState, new_oracle: ContractAddress) {
            self.assert_only_owner();
            
            let old_oracle = self.oracle_dispatcher.read().contract_address;
            self.oracle_dispatcher.write(OracleDispatcher { contract_address: new_oracle });
            
            self.emit(OracleUpdated { old_oracle, new_oracle });
        }
        
        // Emergency pause/unpause (only owner)
        fn set_emergency_pause(ref self: ContractState, paused: bool) {
            self.assert_only_owner();
            
            self.emergency_paused.write(paused);
            self.emit(EmergencyPaused { is_paused: paused });
        }
    }
    
    // Internal functions
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        // Calculate premium based on actuarial model
        fn calculate_premium(
            self: @ContractState,
            coverage_amount: u256,
            duration: u64,
            trigger_type: TriggerType,
            trigger_value: u256
        ) -> u256 {
            // Base premium rate depends on trigger type and value
            let base_rate = match trigger_type {
                TriggerType::HurricaneCategory(()) => {
                    // Higher categories have higher premium rates
                    match trigger_value.try_into().unwrap() {
                        1 => 1000, // 10% for Category 1
                        2 => 800,  // 8% for Category 2
                        3 => 600,  // 6% for Category 3
                        4 => 400,  // 4% for Category 4
                        5 => 200,  // 2% for Category 5 (extremely rare)
                        _ => MIN_PREMIUM_RATE,
                    }
                },
                TriggerType::DroughtIndex(()) => {
                    // Implementation for drought index premium calculation
                    500 // 5% placeholder rate
                },
                TriggerType::FloodLevel(()) => {
                    // Implementation for flood level premium calculation
                    800 // 8% placeholder rate
                },
                TriggerType::CropYield(()) => {
                    // Lower yield thresholds have higher premiums
                    let yield_threshold: u64 = trigger_value.try_into().unwrap();
                    if yield_threshold < 30 {
                        2000 // 20% for very low yield threshold
                    } else if yield_threshold < 50 {
                        1500 // 15% for low yield threshold
                    } else if yield_threshold < 70 {
                        1000 // 10% for medium yield threshold
                    } else {
                        500  // 5% for high yield threshold
                    }
                },
                TriggerType::TemperatureExtreme(()) => {
                    // Implementation for temperature premium calculation
                    700 // 7% placeholder rate
                },
                TriggerType::Earthquake(()) => {
                    // Implementation for earthquake premium calculation
                    900 // 9% placeholder rate
                },
            };
            
            // Adjust for duration (longer durations have slightly discounted rates)
            let duration_factor = if duration <= 2592000 { // 30 days
                100 // No discount for short term
            } else if duration <= 7776000 { // 90 days
                95  // 5% discount for medium term
            } else {
                90  // 10% discount for long term
            };
            
            // Calculate premium with duration adjustment
            let premium_rate = (base_rate * duration_factor) / 100;
            
            // Ensure premium rate is within bounds
            let final_rate = if premium_rate < MIN_PREMIUM_RATE {
                MIN_PREMIUM_RATE
            } else if premium_rate > MAX_PREMIUM_RATE {
                MAX_PREMIUM_RATE
            } else {
                premium_rate
            };
            
            // Calculate actual premium amount
            (coverage_amount * final_rate) / BASIS_POINTS
        }
        
        // Process a claim payment
        fn process_claim(ref self: ContractState, policy_id: u64) {
            // Get policy
            let mut policy = self.policies.read(policy_id);
            let mut pool = self.pools.read(policy.underwriting_pool_id);
            
            // Mark policy as claimed
            policy.is_active = false;
            policy.is_claimed = true;
            self.policies.write(policy_id, policy);
            self.policy_status.write(policy_id, PolicyStatus::Claimed(()));
            
            // Update pool state
            pool.total_payouts += policy.coverage_amount;
            pool.total_liquidity -= policy.coverage_amount;
            pool.reserved_for_claims -= policy.coverage_amount;
            self.pools.write(policy.underwriting_pool_id, pool);
            
            // Transfer coverage amount to policy holder
            let token_dispatcher = IERC20Dispatcher { contract_address: pool.pool_token };
            let success = token_dispatcher.transfer(policy.policy_holder, policy.coverage_amount);
            assert(success, 'Claim payment failed');
            
            // Get oracle data for the event
            let oracle_value: u256 = match policy.trigger_type {
                TriggerType::HurricaneCategory(()) => {
                    let (category, _) = IOracle::get_latest_weather_data(
                        @self.oracle_dispatcher.read().contract_address, 
                        policy.location_id
                    );
                    category.into()
                },
                // Other trigger types would have similar implementations
                _ => 0,
            };
            
            // Emit claim paid event
            self.emit(ClaimPaid { 
                policy_id, 
                policy_holder: policy.policy_holder, 
                amount: policy.coverage_amount, 
                trigger_value: policy.trigger_value,
                oracle_value,
                timestamp: get_block_timestamp() 
            });
        }
        
        // Calculate rewards for a staker
        fn calculate_rewards(self: @ContractState, pool_id: u64, staker: ContractAddress) -> u256 {
            let pool = self.pools.read(pool_id);
            let staker_info = self.staker_info.read((pool_id, staker));
            
            if staker_info.staked_amount == 0 {
                return 0;
            }
            
            let current_time = get_block_timestamp();
            let time_elapsed = current_time - staker_info.last_stake_time;
            
            if time_elapsed == 0 {
                return 0;
            }
            
            // Calculate rewards based on staked amount, time elapsed, and reward rate
            // reward = staked_amount * reward_rate * time_elapsed / total_staked
            
            if pool.total_staked == 0 {
                return 0;
            }
            
            let rewards = (staker_info.staked_amount * pool.reward_rate * time_elapsed.into()) / pool.total_staked;
            
            // Add any previously accumulated rewards
            rewards + staker_info.reward_debt
        }
        
        // Check if caller is the owner
        fn assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Only owner');
        }
        
        // Check if contract is not paused
        fn assert_not_paused(self: @ContractState) {
            assert(!self.emergency_paused.read(), 'Contract paused');
        }
    }
}

#[starknet::interface]
pub trait IParametricInsurance<TContractState> {
    fn create_pool(
        ref self: TContractState, 
        pool_token: ContractAddress, 
        initial_liquidity: u256,
        reward_rate: u256
    ) -> u64;
    
    fn purchase_policy(
        ref self: TContractState,
        pool_id: u64,
        coverage_amount: u256,
        duration: u64,
        trigger_type: ParametricInsurance::TriggerType,
        trigger_value: u256,
        location_id: felt252,
        data_feed_id: felt252
    ) -> u64;
    
    fn check_claim(ref self: TContractState, policy_id: u64) -> bool;
    
    fn stake_liquidity(ref self: TContractState, pool_id: u64, amount: u256);
    
    fn unstake_liquidity(ref self: TContractState, pool_id: u64, amount: u256);
    
    fn harvest_rewards(ref self: TContractState, pool_id: u64) -> u256;
    
    fn get_policy(self: @TContractState, policy_id: u64) -> ParametricInsurance::Policy;
    
    fn get_pool(self: @TContractState, pool_id: u64) -> ParametricInsurance::InsurancePool;
    
    fn get_staker_info(self: @TContractState, pool_id: u64, staker: ContractAddress) -> ParametricInsurance::StakerInfo;
    
    fn get_user_policies(self: @TContractState, user: ContractAddress) -> Array<u64>;
    
    fn is_claim_eligible(self: @TContractState, policy_id: u64) -> bool;
    
    fn update_oracle(ref self: TContractState, new_oracle: ContractAddress);
    
    fn set_emergency_pause(ref self: TContractState, paused: bool);
}