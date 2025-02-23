#[starknet::contract]
pub mod StarkFinderIdentity {
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use core::starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, Map};
    use core::array::ArrayTrait;

    #[derive(Drop, Copy, starknet::Store, Serde)]
    pub struct Identity {
        // Basic Identity
        pub address: ContractAddress,
        pub username: felt252,
        // Web3 Identity Components
        pub ens_name: felt252, // Ethereum Name Service integration
        pub stark_name: felt252, // Starknet Name Service integration
        pub social_connections: u32, // Number of verified social connections
        // DeFi Identity
        pub defi_score: u32,
        pub transaction_volume: u256,
        pub protocols_used: u32,
        // Verification & Trust
        pub verification_level: u8, // 0: None, 1: Basic, 2: Advanced, 3: Full
        // pub trust_score: u32,
        pub is_verified: bool,
        // Activity Metrics
        pub last_active: u64,
        pub created_at: u64,
        pub transaction_count: u32,
        pub reputation_score: u32,
        pub recovery_address: ContractAddress,
    }

    #[derive(Drop, Copy, starknet::Store, Serde)]
    pub struct ActivityRecord {
        pub timestamp: u64,
        pub activity_type: felt252, // 'transaction', 'stake', 'swap', etc.
        pub protocol: felt252,
        pub value: u256,
    }

    #[derive(Drop, Copy, starknet::Store, Serde)]
    pub struct VerificationRequest {
        pub requester: ContractAddress,
        pub verification_type: felt252,
        pub status: u8, // 0: Pending, 1: Approved, 2: Rejected
        pub timestamp: u64,
    }

    #[derive(Drop, Copy, starknet::Store, Serde)]
    pub struct ProtocolUsage {
        pub protocol: felt252,
        pub first_used: u64,
        pub last_used: u64,
        pub interaction_count: u32,
    }

    #[derive(Drop, Copy, starknet::Store, Serde)]
    pub struct SocialProof {
        pub platform: felt252,
        pub timestamp: u64,
        pub signature: felt252,
        pub verified_by: ContractAddress,
    }

    #[storage]
    struct Storage {
        identities: Map<ContractAddress, Identity>,
        verification_requests: Map<(ContractAddress, felt252), VerificationRequest>,
        admin: ContractAddress,
        verifiers: Map<ContractAddress, bool>,
        protocol_usage: Map<(ContractAddress, felt252), ProtocolUsage>,
        address_signatures: Map<ContractAddress, felt252>,
        social_proofs: Map<(ContractAddress, felt252), SocialProof>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        IdentityCreated: IdentityCreated,
        IdentityUpdated: IdentityUpdated,
        VerificationRequested: VerificationRequested,
        VerificationStatusChanged: VerificationStatusChanged,
        ReputationUpdated: ReputationUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct IdentityCreated {
        address: ContractAddress,
        username: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct IdentityUpdated {
        address: ContractAddress,
        field: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationRequested {
        requester: ContractAddress,
        verification_type: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationStatusChanged {
        address: ContractAddress,
        verification_type: felt252,
        status: u8,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ReputationUpdated {
        address: ContractAddress,
        old_score: u32,
        new_score: u32,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl StarkFinderIdentityImpl of super::IStarkFinderIdentity<ContractState> {
        fn create_identity(
            ref self: ContractState, username: felt252, recovery_address: ContractAddress,
        ) {
            let caller = get_caller_address();
            assert(!self.identity_exists(caller), 'Identity already exists');

            let identity = Identity {
                address: caller,
                username,
                reputation_score: 0,
                created_at: get_block_timestamp(),
                last_active: get_block_timestamp(),
                transaction_count: 0,
                is_verified: false,
                defi_score: 0,
                recovery_address,
            };

            self.identities.write(caller, identity);
            self
                .emit(
                    IdentityCreated { address: caller, username, timestamp: get_block_timestamp() },
                );
        }

        fn add_identity(
            ref self: ContractState, username: felt252, ens_name: felt252, stark_name: felt252,
        ) {
            let caller = get_caller_address();
            assert(!self.identity_exists(caller), 'Identity already exists');

            let identity = Identity {
                address: caller,
                username,
                ens_name,
                stark_name,
                social_connections: 0,
                defi_score: 0,
                transaction_volume: 0,
                protocols_used: 0,
                verification_level: 0,
                trust_score: 0,
                is_verified: false,
                last_active: get_block_timestamp(),
                created_at: get_block_timestamp(),
                transaction_count: 0,
            };

            self.identities.write(caller, identity);
            self
                .emit(
                    IdentityCreated {
                        address: caller,
                        username,
                        ens_name,
                        stark_name,
                        timestamp: get_block_timestamp(),
                    },
                );
        }

        // Link multiple addresses to one identity
        fn link_address(ref self: ContractState, address_to_link: ContractAddress) {
            let caller = get_caller_address();
            assert(self.identity_exists(caller), 'Identity does not exist');

            // Verify ownership of address_to_link (implementation depends on your verification
            // method)
            assert(
                self.verify_address_ownership(address_to_link), 'Address ownership not verified',
            );

            self.connected_addresses.write((caller, address_to_link), true);
            self
                .emit(
                    AddressLinked {
                        primary_address: caller,
                        linked_address: address_to_link,
                        timestamp: get_block_timestamp(),
                    },
                );
        }

        // Add social verification
        fn add_social_verification(
            ref self: ContractState, platform: felt252, verification_proof: felt252,
        ) {
            let caller = get_caller_address();
            assert(self.identity_exists(caller), 'Identity does not exist');

            // Verify the social proof (implementation depends on your verification method)
            assert(self.verify_social_proof(platform, verification_proof), 'Invalid verification');

            self.social_verifications.write((caller, platform), true);

            // Update social connections count
            let mut identity = self.identities.read(caller);
            identity.social_connections += 1;
            self.identities.write(caller, identity);

            self
                .emit(
                    SocialVerificationAdded {
                        address: caller, platform, timestamp: get_block_timestamp(),
                    },
                );
        }

        // Record DeFi activity
        fn record_activity(
            ref self: ContractState, activity_type: felt252, protocol: felt252, value: u256,
        ) {
            let caller = get_caller_address();
            assert(self.identity_exists(caller), 'Identity does not exist');

            let current_count = self.activity_count.read(caller);
            let activity = ActivityRecord {
                timestamp: get_block_timestamp(), activity_type, protocol, value,
            };

            self.activity_records.write((caller, current_count), activity);
            self.activity_count.write(caller, current_count + 1);

            // Update identity metrics
            let mut identity = self.identities.read(caller);
            identity.transaction_count += 1;
            identity.transaction_volume += value;
            identity.last_active = get_block_timestamp();

            // Update protocols used if new
            if !self.has_used_protocol(caller, protocol) {
                identity.protocols_used += 1;
            }

            self.identities.write(caller, identity);

            self
                .emit(
                    ActivityRecorded {
                        address: caller,
                        activity_type,
                        protocol,
                        value,
                        timestamp: get_block_timestamp(),
                    },
                );
        }

        // Get identity with all web3 credentials
        fn get_identity(self: @ContractState, address: ContractAddress) -> Identity {
            assert(self.identity_exists(address), 'Identity does not exist');
            self.identities.read(address)
        }

        // Get all activities for an address
        fn get_activities(
            self: @ContractState, address: ContractAddress, start_index: u32, limit: u32,
        ) -> Array<ActivityRecord> {
            let mut activities = ArrayTrait::new();
            let total_activities = self.activity_count.read(address);

            let mut i = start_index;
            while i < total_activities.min(start_index + limit) {
                activities.append(self.activity_records.read((address, i)));
                i += 1;
            };

            activities
        }

        fn update_identity(ref self: ContractState, field: felt252, value: felt252) {
            let caller = get_caller_address();
            let mut identity = self.identities.read(caller);
            assert(identity.address == caller, 'Identity does not exist');

            // Update specific field based on field parameter
            match field {
                'username' => identity.username = value,
                'recovery_address' => identity.recovery_address = value.try_into().unwrap(),
                _ => panic!('Invalid field'),
            };

            self.identities.write(caller, identity);
            self.emit(IdentityUpdated { address: caller, field, timestamp: get_block_timestamp() });
        }

        fn request_verification(ref self: ContractState, verification_type: felt252) {
            let caller = get_caller_address();
            assert(self.identity_exists(caller), 'Identity does not exist');

            let request = VerificationRequest {
                requester: caller,
                verification_type,
                status: 0, // Pending
                timestamp: get_block_timestamp(),
            };

            self.verification_requests.write((caller, verification_type), request);
            self
                .emit(
                    VerificationRequested {
                        requester: caller, verification_type, timestamp: get_block_timestamp(),
                    },
                );
        }

        fn update_reputation(ref self: ContractState, address: ContractAddress, points: i32) {
            let caller = get_caller_address();
            assert(self.verifiers.read(caller), 'Not authorized');

            let mut identity = self.identities.read(address);
            let old_score = identity.reputation_score;

            // Update score (handle overflow/underflow)
            if points >= 0 {
                identity.reputation_score += points.try_into().unwrap();
            } else {
                identity
                    .reputation_score = identity
                    .reputation_score
                    .saturating_sub((-points).try_into().unwrap());
            }

            self.identities.write(address, identity);
            self
                .emit(
                    ReputationUpdated {
                        address,
                        old_score,
                        new_score: identity.reputation_score,
                        timestamp: get_block_timestamp(),
                    },
                );
        }

        fn get_identity(self: @ContractState, address: ContractAddress) -> Identity {
            self.identities.read(address)
        }

        fn identity_exists(self: @ContractState, address: ContractAddress) -> bool {
            let identity = self.identities.read(address);
            identity.created_at != 0
        }

        fn has_used_protocol(
            self: @ContractState, address: ContractAddress, protocol: felt252,
        ) -> bool {
            // Get protocol usage data for the address
            let usage = self.protocol_usage.read((address, protocol));

            // If first_used is not 0, the protocol has been used
            usage.first_used != 0
        }

        fn verify_address_ownership(self: @ContractState, address: ContractAddress) -> bool {
            // Get the caller's address
            let caller = get_caller_address();

            // If the caller is the address itself, it's verified
            if caller == address {
                return true;
            }

            // Check if there's a stored signature proving ownership
            let stored_signature = self.address_signatures.read(address);
            if stored_signature == 0 {
                return false;
            }

            // Verify the signature matches the expected pattern
            // This is a simplified example - in production you'd want more robust verification
            let expected_signature = self.generate_ownership_signature(caller, address);
            stored_signature == expected_signature
        }

        fn verify_social_proof(self: @ContractState, platform: felt252, proof: felt252) -> bool {
            let caller = get_caller_address();

            // Get the stored proof for this platform and address
            let stored_proof = self.social_proofs.read((caller, platform));

            // Check if proof exists and is verified by an authorized verifier
            if stored_proof.timestamp == 0 {
                return false;
            }

            // Verify the verifier's authorization
            let is_verifier = self.verifiers.read(stored_proof.verified_by);
            if !is_verifier {
                return false;
            }

            // Check if the proof matches and is not expired
            let current_time = get_block_timestamp();
            let proof_age = current_time - stored_proof.timestamp;

            // Proofs are valid for 30 days (2592000 seconds)
            if proof_age > 2592000 {
                return false;
            }

            // Verify the proof signature matches
            stored_proof.signature == proof
        }

        // Helper functions for the verification system

        fn record_protocol_usage(
            ref self: ContractState, address: ContractAddress, protocol: felt252,
        ) {
            let current_time = get_block_timestamp();
            let mut usage = self.protocol_usage.read((address, protocol));

            if usage.first_used == 0 {
                // First time using this protocol
                usage =
                    ProtocolUsage {
                        protocol,
                        first_used: current_time,
                        last_used: current_time,
                        interaction_count: 1,
                    };
            } else {
                // Update existing usage
                usage.last_used = current_time;
                usage.interaction_count += 1;
            }

            self.protocol_usage.write((address, protocol), usage);
        }

        fn submit_address_signature(
            ref self: ContractState, address: ContractAddress, signature: felt252,
        ) {
            let caller = get_caller_address();
            assert(caller == address, 'Only address owner can submit');
            self.address_signatures.write(address, signature);
        }

        fn submit_social_proof(ref self: ContractState, platform: felt252, signature: felt252) {
            let caller = get_caller_address();
            assert(self.verifiers.read(caller), 'Only verifiers can submit proofs');

            let proof = SocialProof {
                platform, timestamp: get_block_timestamp(), signature, verified_by: caller,
            };

            let user_address = self.get_proof_address(signature);
            self.social_proofs.write((user_address, platform), proof);
        }

        fn generate_ownership_signature(
            self: @ContractState, owner: ContractAddress, address: ContractAddress,
        ) -> felt252 {
            // This is a simplified example - in production use proper signature verification
            // Typically would use pedersen hash or other cryptographic function
            let timestamp = get_block_timestamp();
            owner.into() + address.into() + timestamp
        }

        fn get_proof_address(self: @ContractState, signature: felt252) -> ContractAddress {
            // In production, this would decode the signature to get the user's address
            // This is a simplified placeholder
            contract_address_const::<0>()
        }
    }
}
