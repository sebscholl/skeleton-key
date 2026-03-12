# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Bitcoin
      # Internal account-derivation helpers for Bitcoin account objects.
      module AccountDerivation
        private

        def derive_from_seed(seed_bytes, purpose: 84, coin_type: 0, account: 0)
          return derive_legacy_root_from_seed(seed_bytes) if legacy_root_branch_purpose?(purpose)

          derive_standard_account_from_seed(seed_bytes, purpose: purpose, coin_type: coin_type, account: account)
        end

        def derive_standard_account_from_seed(seed_bytes, purpose:, coin_type:, account:)
          key, chain_code = master_from_seed(seed_bytes)
          depth = 0

          key, chain_code, depth, = derive_step(key, chain_code, depth, hardened(purpose))
          key, chain_code, depth, = derive_step(key, chain_code, depth, hardened(coin_type))
          account_key, account_chain_code, account_depth, account_parent_fpr, account_child_num =
            derive_step(key, chain_code, depth, hardened(account))

          serialize_standard_account(
            account_key,
            account_chain_code,
            account_depth,
            account_parent_fpr,
            account_child_num
          )
        end

        def derive_legacy_root_from_seed(seed_bytes)
          master_key, master_chain_code = master_from_seed(seed_bytes)
          master_pubkey = privkey_to_pubkey_compressed(master_key)
          master_fingerprint = fingerprint_from_pubkey(master_pubkey)
          branch_key, branch_chain_code = ckd_priv(master_key, master_chain_code, 0)
          branch_pubkey = privkey_to_pubkey_compressed(branch_key)

          {
            k_int: master_key,
            c: master_chain_code,
            bip32_xprv: serialize_xprv(
              branch_key,
              branch_chain_code,
              depth: 1,
              parent_fpr: master_fingerprint,
              child_num: 0,
              version: version_byte(network: network, purpose: purpose, private: true)
            ),
            bip32_xpub: serialize_xpub(
              branch_pubkey,
              branch_chain_code,
              depth: 1,
              parent_fpr: master_fingerprint,
              child_num: 0,
              version: version_byte(network: network, purpose: purpose)
            ),
            account_xprv: "",
            account_xpub: ""
          }
        end

        def derive_step(parent_key, parent_chain_code, parent_depth, child_index)
          parent_pubkey = privkey_to_pubkey_compressed(parent_key)
          parent_fingerprint = fingerprint_from_pubkey(parent_pubkey)
          child_key, child_chain_code = ckd_priv(parent_key, parent_chain_code, child_index)

          [child_key, child_chain_code, parent_depth + 1, parent_fingerprint, child_index]
        end

        def serialize_standard_account(account_key, account_chain_code, account_depth, account_parent_fpr, account_child_num)
          account_pubkey = privkey_to_pubkey_compressed(account_key)
          branch_key, branch_chain_code, branch_depth, branch_parent_fpr, branch_child_num = derive_step(
            account_key,
            account_chain_code,
            account_depth,
            0
          )
          branch_pubkey = privkey_to_pubkey_compressed(branch_key)

          {
            k_int: account_key,
            c: account_chain_code,
            bip32_xprv: serialize_xprv(
              branch_key,
              branch_chain_code,
              depth: branch_depth,
              parent_fpr: branch_parent_fpr,
              child_num: branch_child_num,
              version: version_byte(network: network, purpose: purpose, private: true)
            ),
            bip32_xpub: serialize_xpub(
              branch_pubkey,
              branch_chain_code,
              depth: branch_depth,
              parent_fpr: branch_parent_fpr,
              child_num: branch_child_num,
              version: version_byte(network: network, purpose: purpose)
            ),
            account_xprv: serialize_xprv(
              account_key,
              account_chain_code,
              depth: account_depth,
              parent_fpr: account_parent_fpr,
              child_num: account_child_num,
              version: version_byte(network: network, purpose: purpose, private: true)
            ),
            account_xpub: serialize_xpub(
              account_pubkey,
              account_chain_code,
              depth: account_depth,
              parent_fpr: account_parent_fpr,
              child_num: account_child_num,
              version: version_byte(network: network, purpose: purpose)
            )
          }
        end

        def hardened(index)
          index | 0x8000_0000
        end
      end
    end
  end
end
