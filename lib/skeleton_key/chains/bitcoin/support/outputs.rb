# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Bitcoin
      module Support
        module Outputs
          module_function

          def derive_address_from_account(change: 0, index: 0, hardened_change: false, hardened_index: false)
            k, c = derived[:k_int], derived[:c]
            change_index = hardened_change ? change | Derivation::Path::HARDENED_FLAG : change
            address_index = hardened_index ? index | Derivation::Path::HARDENED_FLAG : index

            k, c = ckd_priv(k, c, change_index)
            k, c = ckd_priv(k, c, address_index)

            pub = privkey_to_pubkey_compressed(k)

            {
              path: build_derived_path(change: change, index: index, hardened_change: hardened_change, hardened_index: hardened_index),
              privkey: k,
              pubkey: pub,
              chain_code: c,
              wif: to_wif(ser256(k), network: network),
              address: address_for_pubkey(pub)
            }
          end

          def derive_branch_extended_keys(change: 0, hardened_change: false)
            parent_key = derived[:k_int]
            parent_chain_code = derived[:c]
            parent_pubkey = privkey_to_pubkey_compressed(parent_key)
            child_num = hardened_change ? change | Derivation::Path::HARDENED_FLAG : change
            branch_key, branch_chain_code = ckd_priv(parent_key, parent_chain_code, child_num)
            branch_pubkey = privkey_to_pubkey_compressed(branch_key)

            {
              path: branch_derived_path(change: change, hardened_change: hardened_change),
              xprv: serialize_xprv(
                branch_key,
                branch_chain_code,
                depth: legacy_root_branch? ? 1 : 4,
                parent_fpr: fingerprint_from_pubkey(parent_pubkey),
                child_num: child_num,
                version: version_byte(network: network, purpose: purpose, private: true)
              ),
              xpub: serialize_xpub(
                branch_pubkey,
                branch_chain_code,
                depth: legacy_root_branch? ? 1 : 4,
                parent_fpr: fingerprint_from_pubkey(parent_pubkey),
                child_num: child_num,
                version: version_byte(network: network, purpose: purpose)
              )
            }
          end

          private

          def address_for_pubkey(pubkey)
            case purpose
            when 32, 44
              to_p2pkh_address(pubkey, network: network)
            when 49
              to_p2sh_p2wpkh_address(pubkey, network: network)
            when 84, 141
              to_bech32_address(pubkey, hrp: network == :mainnet ? "bc" : "tb")
            else
              raise Errors::UnsupportedPurposeError.new(purpose)
            end
          end
        end
      end
    end
  end
end
