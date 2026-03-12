# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Bitcoin
      # Represents a Bitcoin HD account node derived via BIP32/BIP84.
      #
      # Handles derivation of xprv/xpub for a given account path.
      #
      # @example Default mainnet account
      #   acct = SkeletonKey::Chains::Bitcoin::Account.new(seed: seed.bytes)
      #   acct.xprv # => "xprv..."
      #   acct.xpub # => "xpub..."
      class Account
        include Support
        include AccountDerivation
        include Derivation::BIP32

        attr_reader :purpose, :coin_type, :account_index, :network, :derived

        LEGACY_BIP32_PURPOSE = 32
        LEGACY_BIP141_PURPOSE = 141
        DEFAULT_PURPOSE = 84
        MAINNET_COIN = 0
        TESTNET_COIN = 1

        # @param seed [String] raw seed bytes
        # @param purpose [Integer] derivation purpose (44, 49, 84)
        # @param coin_type [Integer] 0 = mainnet, 1 = testnet
        # @param account_index [Integer] account number (hardened)
        # @param network [:mainnet, :testnet]
        def initialize(seed:, purpose: DEFAULT_PURPOSE, coin_type: MAINNET_COIN, account_index: 0, network: :mainnet)
          @purpose = purpose
          @coin_type = coin_type
          @account_index = account_index
          @network = network

          @derived = derive_from_seed(
            seed,
            purpose: purpose,
            coin_type: coin_type,
            account: account_index
          )
        end

        # @return [String] BIP32 extended private key (xprv, zprv if re-encoded)
        def xprv
          @derived[:xprv]
        end

        # @return [String] BIP32 extended public key (xpub, zpub if re-encoded)
        def xpub
          @derived[:xpub]
        end

        # @return [String] BIP32 path
        def path
          return "m" if legacy_root_branch?

          "m/#{purpose}'/#{coin_type}'/#{account_index}'"
        end

        # Derive a child address from this account.
        #
        # @param change [Integer] 0 = external, 1 = internal/change
        # @param index [Integer] address index
        # @return [Hash] derived address details (privkey, pubkey, wif, bech32, etc.)
        def address(change: 0, index: 0, hardened_change: false, hardened_index: false)
          derive_address_from_account(
            change: change,
            index: index,
            hardened_change: hardened_change,
            hardened_index: hardened_index
          )
        end

        def branch_extended_keys(change: 0, hardened_change: false)
          derive_branch_extended_keys(change: change, hardened_change: hardened_change)
        end

        private

        def legacy_bip32?
          purpose == LEGACY_BIP32_PURPOSE
        end

        def legacy_bip141?
          purpose == LEGACY_BIP141_PURPOSE
        end

        def legacy_root_branch?
          legacy_root_branch_purpose?(purpose)
        end

        def legacy_root_branch_purpose?(value)
          [LEGACY_BIP32_PURPOSE, LEGACY_BIP141_PURPOSE].include?(value)
        end
      end
    end
  end
end
