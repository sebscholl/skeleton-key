# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Ethereum
      ##
      # Ethereum account derivation from a shared {Seed}.
      #
      # This class owns Ethereum path conventions and Ethereum-facing account
      # semantics. Shared secp256k1 and BIP32 primitives remain in the derivation
      # layer; this class decides which path to walk and how to expose the
      # resulting branch and address data.
      #
      # Supported modes:
      # - legacy BIP32 root mode (`purpose == 32`)
      # - BIP44 account mode (`m/44'/60'/account'`)
      #
      # @example Derive the first Ethereum address from a BIP44 account
      #   account = SkeletonKey::Chains::Ethereum::Account.new(seed: seed.bytes)
      #   account.address(change: 0, index: 0)
      class Account
        include Support
        include Derivation::BIP32

        # @return [Integer] derivation purpose (32 or 44)
        # @return [Integer] SLIP-0044 coin type, normally 60 for Ethereum
        # @return [Integer] account index within the purpose/coin namespace
        # @return [Hash] cached derived account metadata and extended keys
        attr_reader :purpose, :coin_type, :account_index, :derived

        LEGACY_BIP32_PURPOSE = 32
        DEFAULT_PURPOSE = 44
        ETHEREUM_COIN = 60

        # @param seed [String] canonical seed bytes
        # @param purpose [Integer] derivation purpose (32 or 44)
        # @param coin_type [Integer] SLIP-0044 coin type
        # @param account_index [Integer] account number to derive
        # @raise [Errors::UnsupportedPurposeError] if the requested path family is unsupported
        def initialize(seed:, purpose: DEFAULT_PURPOSE, coin_type: ETHEREUM_COIN, account_index: 0)
          @purpose = purpose
          @coin_type = coin_type
          @account_index = account_index
          @derived = derive_from_seed(seed, purpose: purpose, coin_type: coin_type, account: account_index)
        end

        # Returns the account path prefix that future branch and address
        # derivations are anchored to.
        #
        # @return [String]
        def path
          derived[:path_prefix]
        end

        # Derives an Ethereum address node below the account prefix.
        #
        # Ethereum keeps the BIP44 `change/index` shape for compatibility even
        # though the chain is account-based rather than UTXO-based.
        #
        # @param change [Integer] branch index beneath the account
        # @param index [Integer] address index within the branch
        # @param hardened_change [Boolean] whether to harden the branch step
        # @param hardened_index [Boolean] whether to harden the address step
        # @return [Hash] private key, public keys, checksummed address, and path metadata
        def address(change: 0, index: 0, hardened_change: false, hardened_index: false)
          derive_address_from_node(
            change: change,
            index: index,
            hardened_change: hardened_change,
            hardened_index: hardened_index
          )
        end

        # Serializes the extended keypair for a branch directly beneath the
        # current account or root node.
        #
        # @param change [Integer] branch index to derive
        # @param hardened_change [Boolean] whether the branch child is hardened
        # @return [Hash] serialized extended keypair and rendered path
        def branch_extended_keys(change: 0, hardened_change: false)
          derive_branch_extended_keys(change: change, hardened_change: hardened_change)
        end

        private

        def derive_from_seed(seed_bytes, purpose:, coin_type:, account:)
          return derive_legacy_root_from_seed(seed_bytes) if purpose == LEGACY_BIP32_PURPOSE
          return derive_bip44_account_from_seed(seed_bytes, purpose: purpose, coin_type: coin_type, account: account) if purpose == 44

          raise Errors::UnsupportedPurposeError.new(purpose)
        end

      def derive_legacy_root_from_seed(seed_bytes)
        k_master, c_master = master_from_seed(seed_bytes)
        master_pub = privkey_to_pubkey_compressed(k_master)
        master_fpr = fingerprint_from_pubkey(master_pub)
        k_branch, c_branch = ckd_priv(k_master, c_master, 0)
        pub_branch = privkey_to_pubkey_compressed(k_branch)

        {
          path_prefix: "m",
          k_int: k_master,
          c: c_master,
          account_extended_private_key: "",
          account_extended_public_key: "",
          branch_extended_private_key: serialize_xprv(
            k_branch,
            c_branch,
            depth: 1,
            parent_fpr: master_fpr,
            child_num: 0,
            version: extended_private_version
          ),
          branch_extended_public_key: serialize_xpub(
            pub_branch,
            c_branch,
            depth: 1,
            parent_fpr: master_fpr,
            child_num: 0,
            version: extended_public_version
          )
        }
      end

      def derive_bip44_account_from_seed(seed_bytes, purpose:, coin_type:, account:)
        k_int, chain_code = master_from_seed(seed_bytes)
        depth = 0

        # Walk the BIP44 hardened account path one level at a time so the
        # serialized parent fingerprint and child number remain explicit.
        derive_step = ->(k_in, c_in, depth_in, index) do
          parent_pub = privkey_to_pubkey_compressed(k_in)
          parent_fpr = fingerprint_from_pubkey(parent_pub)
          k_out, c_out = ckd_priv(k_in, c_in, index)
          [k_out, c_out, depth_in + 1, parent_fpr, index]
        end

        k_int, chain_code, depth, _, _ = derive_step.call(k_int, chain_code, depth, 0x8000_0000 | purpose)
        k_int, chain_code, depth, _, _ = derive_step.call(k_int, chain_code, depth, 0x8000_0000 | coin_type)
        k_account, c_account, depth_account, parent_fpr, child_num = derive_step.call(k_int, chain_code, depth, 0x8000_0000 | account)
        pub_account = privkey_to_pubkey_compressed(k_account)

        k_branch, c_branch, depth_branch, branch_parent_fpr, branch_child_num = derive_step.call(k_account, c_account, depth_account, 0)
        pub_branch = privkey_to_pubkey_compressed(k_branch)

        {
          path_prefix: "m/#{purpose}'/#{coin_type}'/#{account}'",
          k_int: k_account,
          c: c_account,
          account_extended_private_key: serialize_xprv(
            k_account,
            c_account,
            depth: depth_account,
            parent_fpr: parent_fpr,
            child_num: child_num,
            version: extended_private_version
          ),
          account_extended_public_key: serialize_xpub(
            pub_account,
            c_account,
            depth: depth_account,
            parent_fpr: parent_fpr,
            child_num: child_num,
            version: extended_public_version
          ),
          branch_extended_private_key: serialize_xprv(
            k_branch,
            c_branch,
            depth: depth_branch,
            parent_fpr: branch_parent_fpr,
            child_num: branch_child_num,
            version: extended_private_version
          ),
          branch_extended_public_key: serialize_xpub(
            pub_branch,
            c_branch,
            depth: depth_branch,
            parent_fpr: branch_parent_fpr,
            child_num: branch_child_num,
            version: extended_public_version
          )
        }
      end

        def legacy_root_branch?
          purpose == LEGACY_BIP32_PURPOSE
        end
      end
    end
  end
end
