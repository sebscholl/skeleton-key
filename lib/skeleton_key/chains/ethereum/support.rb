# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Ethereum
      ##
      # Ethereum-specific serialization and address helpers.
      #
      # This module owns the Ethereum-facing parts of account derivation:
      # - extended key version bytes used by the current API surface
      # - EIP-55 checksum address rendering
      # - rendering of Ethereum child paths below an account node
      #
      # It intentionally does not own the underlying secp256k1 arithmetic.
      module Support
        extend Utils::Hashing
        extend Utils::Encoding

        XPUB_VERSION = 0x0488B21E
        XPRV_VERSION = 0x0488ADE4

        module_function

      # Returns the four-byte version used for serialized extended private keys.
      #
      # @return [String] big-endian 4-byte version
        def extended_private_version
          [XPRV_VERSION].pack("N")
        end

      # Returns the four-byte version used for serialized extended public keys.
      #
      # @return [String] big-endian 4-byte version
        def extended_public_version
          [XPUB_VERSION].pack("N")
        end

      # Converts an uncompressed secp256k1 public key into a checksummed
      # Ethereum address per EIP-55.
      #
      # @param pubkey_uncompressed [String] 65-byte uncompressed public key
      # @return [String] checksummed `0x...` Ethereum address
        def to_checksum_address(pubkey_uncompressed)
          address_bytes = keccak256(pubkey_uncompressed.byteslice(1, 64)).byteslice(-20, 20)
          address_hex = bytes_to_hex(address_bytes)
          address_hash = bytes_to_hex(keccak256(address_hex))

          checksummed = address_hex.chars.each_with_index.map do |char, idx|
            next char if char.match?(/[0-9]/)

            address_hash[idx].hex >= 8 ? char.upcase : char
          end.join

          "0x#{checksummed}"
        end

      # Derives a child node below the current account/root node and returns the
      # Ethereum-facing representation of that child.
      #
      # @param change [Integer] branch index
      # @param index [Integer] child index within the branch
      # @param hardened_change [Boolean] whether the branch step is hardened
      # @param hardened_index [Boolean] whether the address step is hardened
      # @return [Hash] rendered path, private key, public keys, address, and chain code
        def derive_address_from_node(change: 0, index: 0, hardened_change: false, hardened_index: false)
          k_int, chain_code = derived[:k_int], derived[:c]
          change_index = hardened_change ? change | Derivation::Path::HARDENED_FLAG : change
          address_index = hardened_index ? index | Derivation::Path::HARDENED_FLAG : index

          k_int, chain_code = ckd_priv(k_int, chain_code, change_index)
          k_int, chain_code = ckd_priv(k_int, chain_code, address_index)

        pubkey_compressed = privkey_to_pubkey_compressed(k_int)
        pubkey_uncompressed = privkey_to_pubkey_uncompressed(k_int)
        ethereum_public_key = pubkey_uncompressed.byteslice(1, 64)

          {
            path: build_derived_path(change: change, index: index, hardened_change: hardened_change, hardened_index: hardened_index),
            private_key: ser256(k_int).unpack1("H*"),
            public_key: ethereum_public_key.unpack1("H*"),
            compressed_public_key: pubkey_compressed.unpack1("H*"),
            address: to_checksum_address(pubkey_uncompressed),
            chain_code: chain_code,
            privkey: k_int,
            pubkey: ethereum_public_key
          }
        end

      # Derives and serializes a branch node directly beneath the current
      # account/root prefix.
      #
      # @param change [Integer] branch index
      # @param hardened_change [Boolean] whether the branch child is hardened
      # @return [Hash] branch path with serialized xprv/xpub
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
              version: extended_private_version
            ),
            xpub: serialize_xpub(
              branch_pubkey,
              branch_chain_code,
              depth: legacy_root_branch? ? 1 : 4,
              parent_fpr: fingerprint_from_pubkey(parent_pubkey),
              child_num: child_num,
              version: extended_public_version
            )
          }
        end

      # Renders the derived child path in canonical BIP32 string form.
      #
      # @return [String]
        def build_derived_path(change:, index:, hardened_change:, hardened_index:)
          rendered_change = hardened_change ? "#{change}'" : change.to_s
          rendered_index = hardened_index ? "#{index}'" : index.to_s
          "#{path}/#{rendered_change}/#{rendered_index}"
        end

      # Renders the derived branch path in canonical BIP32 string form.
      #
      # @return [String]
        def branch_derived_path(change:, hardened_change:)
          rendered_change = hardened_change ? "#{change}'" : change.to_s
          "#{path}/#{rendered_change}"
        end
      end
    end
  end
end
