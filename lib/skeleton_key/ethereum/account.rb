# frozen_string_literal: true

module SkeletonKey
  module Ethereum
    class Account
      include Support
      include Derivation::BIP32

      attr_reader :purpose, :coin_type, :account_index, :derived

      LEGACY_BIP32_PURPOSE = 32
      DEFAULT_PURPOSE = 44
      ETHEREUM_COIN = 60

      def initialize(seed:, purpose: DEFAULT_PURPOSE, coin_type: ETHEREUM_COIN, account_index: 0)
        @purpose = purpose
        @coin_type = coin_type
        @account_index = account_index
        @derived = derive_from_seed(seed, purpose: purpose, coin_type: coin_type, account: account_index)
      end

      def path
        derived[:path_prefix]
      end

      def address(change: 0, index: 0, hardened_change: false, hardened_index: false)
        derive_address_from_node(
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
