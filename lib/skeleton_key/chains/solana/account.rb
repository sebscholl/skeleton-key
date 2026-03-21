# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Solana
      ##
      # Solana account derivation using hardened SLIP-0010 Ed25519 paths.
      #
      # Solana in SkeletonKey is intentionally hardened-only. This class owns the
      # Solana path convention and turns a shared seed into Ed25519 key material
      # and Base58 addresses, while the underlying SLIP-0010 math remains in the
      # derivation layer.
      #
      # @example Derive the default wallet-style Solana address
      #   account = SkeletonKey::Chains::Solana::Account.new(seed: seed.bytes)
      #   account.address(change: 0)
      class Account
        include Support
        include Derivation::SLIP10

        # @return [Integer] derivation purpose, fixed at 44
        # @return [Integer] SLIP-0044 coin type, fixed at 501 for Solana
        # @return [Integer] account index within the Solana namespace
        # @return [Hash] cached account-level key seed and chain code
        attr_reader :purpose, :coin_type, :account_index, :derived

        DEFAULT_PURPOSE = 44
        SOLANA_COIN = 501
        DEFAULT_DERIVATION_PATH = Object.new.freeze
        UNSPECIFIED_CHANGE = Object.new.freeze

        # @param seed [String] canonical seed bytes
        # @param purpose [Integer] derivation purpose, fixed at 44
        # @param coin_type [Integer] SLIP-0044 coin type, fixed at 501
        # @param account_index [Integer] hardened account index
        # @param derivation_path [nil] set to `nil` to match Solana CLI no-path mode
        # @raise [Errors::UnsupportedPurposeError] if non-Solana path parameters are requested
        def initialize(
          seed:, 
          purpose: DEFAULT_PURPOSE, 
          coin_type: SOLANA_COIN, 
          account_index: 0,
          derivation_path:
          DEFAULT_DERIVATION_PATH
        )
          @purpose = purpose
          @coin_type = coin_type
          @account_index = account_index
          @derived = derive(
            seed, 
            purpose: purpose, 
            coin_type: coin_type, 
            account: account_index,                     
            derivation_path: derivation_path
          )
        end

        # Returns the hardened account prefix for future child derivation.
        #
        # @return [String]
        def path
          derived[:path_prefix]
        end

        # Derives a hardened Solana child path below the account prefix.
        #
        # In practice this supports both the shorter account-root convention and
        # the wallet-style `.../change'/index'` convention used by many tools.
        #
        # @param change [Integer, nil] hardened child directly beneath the account
        # @param index [Integer, nil] hardened child beneath the change node
        # @return [Hash] path, private key, public key, address, and chain code
        def address(change: UNSPECIFIED_CHANGE, index: nil)
          return no_path_address(change: change, index: index) if path.nil?

          key_seed, chain_code = derived[:key_seed], derived[:chain_code]
          current_path = path
          change = 0 if change.equal?(UNSPECIFIED_CHANGE)

          unless change.nil?
            current_path = "#{current_path}/#{change}'"
            key_seed, chain_code = ckd_priv(key_seed, chain_code, hardened(change))
          end

          unless index.nil?
            current_path = "#{current_path}/#{index}'"
            key_seed, chain_code = ckd_priv(key_seed, chain_code, hardened(index))
          end

          private_key, public_key = keypair_from_seed(key_seed)

          {
            path: current_path,
            chain_code: chain_code,
            address: to_address(public_key),
            public_key: public_key.unpack1("H*"),
            private_key: private_key.unpack1("H*"),
          }
        end

        private

        def derive(seed_bytes, purpose:, coin_type:, account:, derivation_path:)
          return derive_without_path(seed_bytes, purpose: purpose, coin_type: coin_type, account: account) if derivation_path.nil?

          unless derivation_path.equal?(DEFAULT_DERIVATION_PATH)
            raise Errors::InvalidPathFormatError, "unsupported Solana derivation_path override"
          end

          derive_from_seed(seed_bytes, purpose: purpose, coin_type: coin_type, account: account)
        end

        def derive_from_seed(seed_bytes, purpose:, coin_type:, account:)
          raise Errors::UnsupportedPurposeError.new(purpose) unless purpose == 44
          raise Errors::UnsupportedPurposeError.new(coin_type) unless coin_type == SOLANA_COIN

          key_seed, chain_code = master_from_seed(seed_bytes)
          # Every Solana child step is hardened. The path prefix stored here is
          # the account node from which wallet-style descendants are derived.
          [
            hardened(purpose),
            hardened(coin_type),
            hardened(account)
          ].each do |index|
            key_seed, chain_code = ckd_priv(key_seed, chain_code, index)
          end

          {
            path_prefix: "m/#{purpose}'/#{coin_type}'/#{account}'",
            key_seed: key_seed,
            chain_code: chain_code
          }
        end

        def derive_without_path(seed_bytes, purpose:, coin_type:, account:)
          unless purpose == DEFAULT_PURPOSE && coin_type == SOLANA_COIN && account.zero?
            raise Errors::InvalidPathFormatError,
                  "solana derivation_path=nil is incompatible with purpose, coin_type, or account_index overrides"
          end

          if seed_bytes.bytesize < Constants::PRIVATE_KEY_LENGTH
            raise Errors::InvalidSeedError, "solana derivation_path=nil requires at least 32 seed bytes"
          end

          {
            path_prefix: nil,
            key_seed: seed_bytes.byteslice(0, Constants::PRIVATE_KEY_LENGTH),
            chain_code: nil
          }
        end

        def no_path_address(change:, index:)
          unless (change.equal?(UNSPECIFIED_CHANGE) || change.nil?) && index.nil?
            raise Errors::InvalidPathFormatError, "solana derivation_path=nil does not support child derivation"
          end

          private_key, public_key = keypair_from_seed(derived[:key_seed])

          {
            path: nil,
            private_key: private_key.unpack1("H*"),
            public_key: public_key.unpack1("H*"),
            address: to_address(public_key),
            chain_code: nil
          }
        end

        # Encodes a child index as a hardened SLIP-0010 index.
        #
        # @param index [Integer]
        # @return [Integer]
        def hardened(index)
          index | Derivation::SLIP10::HARDENED_FLAG
        end
      end
    end
  end
end
