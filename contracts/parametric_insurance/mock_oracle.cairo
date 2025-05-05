#[starknet::contract]
pub mod MockOracle {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, Map};
    use contracts::parametric_insurance::lib::ParametricInsurance::IOracle;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        price_data: Map<felt252, (u128, u64)>,             // data_feed_id -> (price, timestamp)
        weather_data: Map<felt252, (u8, u64)>,             // location_id -> (hurricane_category, timestamp)
        yield_data: Map<felt252, (u64, u64)>,              // crop_id -> (yield_percentage, timestamp)
        authorized_updaters: Map<ContractAddress, bool>,   // Address allowed to update data
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PriceUpdated: PriceUpdated,
        WeatherDataUpdated: WeatherDataUpdated,
        YieldDataUpdated: YieldDataUpdated,
        AuthorizedUpdaterAdded: AuthorizedUpdaterAdded,
        AuthorizedUpdaterRemoved: AuthorizedUpdaterRemoved,
    }

    #[derive(Drop, starknet::Event)]
    struct PriceUpdated {
        #[key]
        data_feed_id: felt252,
        price: u128,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WeatherDataUpdated {
        #[key]
        location_id: felt252,
        hurricane_category: u8,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct YieldDataUpdated {
        #[key]
        crop_id: felt252,
        yield_percentage: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthorizedUpdaterAdded {
        #[key]
        updater: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthorizedUpdaterRemoved {
        #[key]
        updater: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.authorized_updaters.write(owner, true); // Owner is authorized by default
    }

    #[external(v0)]
    impl OracleImpl of IOracle<ContractState> {
        fn get_latest_price(self: @ContractState, data_feed_id: felt252) -> (u128, u64) {
            self.price_data.read(data_feed_id)
        }

        fn get_latest_weather_data(self: @ContractState, location_id: felt252) -> (u8, u64) {
            self.weather_data.read(location_id)
        }

        fn get_latest_yield_data(self: @ContractState, crop_id: felt252) -> (u64, u64) {
            self.yield_data.read(crop_id)
        }
    }

    #[external(v0)]
    impl OracleAdminImpl of IMockOracleAdmin<ContractState> {
        fn update_price_data(
            ref self: ContractState,
            data_feed_id: felt252,
            price: u128
        ) {
            self.assert_authorized();
            
            let timestamp = get_block_timestamp();
            self.price_data.write(data_feed_id, (price, timestamp));
            
            self.emit(PriceUpdated { data_feed_id, price, timestamp });
        }

        fn update_weather_data(
            ref self: ContractState,
            location_id: felt252,
            hurricane_category: u8
        ) {
            self.assert_authorized();
            
            let timestamp = get_block_timestamp();
            self.weather_data.write(location_id, (hurricane_category, timestamp));
            
            self.emit(WeatherDataUpdated { location_id, hurricane_category, timestamp });
        }

        fn update_yield_data(
            ref self: ContractState,
            crop_id: felt252,
            yield_percentage: u64
        ) {
            self.assert_authorized();
            
            let timestamp = get_block_timestamp();
            self.yield_data.write(crop_id, (yield_percentage, timestamp));
            
            self.emit(YieldDataUpdated { crop_id, yield_percentage, timestamp });
        }

        fn add_authorized_updater(ref self: ContractState, updater: ContractAddress) {
            self.assert_owner();
            
            self.authorized_updaters.write(updater, true);
            
            self.emit(AuthorizedUpdaterAdded { updater });
        }

        fn remove_authorized_updater(ref self: ContractState, updater: ContractAddress) {
            self.assert_owner();
            
            self.authorized_updaters.write(updater, false);
            
            self.emit(AuthorizedUpdaterRemoved { updater });
        }

        fn is_authorized_updater(self: @ContractState, updater: ContractAddress) -> bool {
            self.authorized_updaters.read(updater)
        }
    }
    
    // Internal functions
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn assert_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Only owner');
        }
        
        fn assert_authorized(self: @ContractState) {
            let caller = get_caller_address();
            let is_authorized = self.authorized_updaters.read(caller);
            assert(is_authorized, 'Not authorized');
        }
    }
}

#[starknet::interface]
pub trait IMockOracleAdmin<TContractState> {
    fn update_price_data(
        ref self: TContractState,
        data_feed_id: felt252,
        price: u128
    );
    
    fn update_weather_data(
        ref self: TContractState,
        location_id: felt252,
        hurricane_category: u8
    );
    
    fn update_yield_data(
        ref self: TContractState,
        crop_id: felt252,
        yield_percentage: u64
    );
    
    fn add_authorized_updater(ref self: TContractState, updater: ContractAddress);
    
    fn remove_authorized_updater(ref self: TContractState, updater: ContractAddress);
    
    fn is_authorized_updater(self: @TContractState, updater: ContractAddress) -> bool;
}