# frozen_string_literal: true

module SkeletonKey
  module Ethereum
    module Support
      extend Utils::Hashing
      extend Utils::Encoding

      XPUB_VERSION = 0x0488B21E
      XPRV_VERSION = 0x0488ADE4

      module_function

      def extended_private_version
        [XPRV_VERSION].pack("N")
      end

      def extended_public_version
        [XPUB_VERSION].pack("N")
      end

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

      def derive_address_from_node(change: 0, index: 0)
        k_int, chain_code = derived[:k_int], derived[:c]
        k_int, chain_code = ckd_priv(k_int, chain_code, change)
        k_int, chain_code = ckd_priv(k_int, chain_code, index)

        pubkey_compressed = privkey_to_pubkey_compressed(k_int)
        pubkey_uncompressed = privkey_to_pubkey_uncompressed(k_int)
        ethereum_public_key = pubkey_uncompressed.byteslice(1, 64)

        {
          path: "#{path}/#{change}/#{index}",
          private_key: ser256(k_int).unpack1("H*"),
          public_key: ethereum_public_key.unpack1("H*"),
          address: to_checksum_address(pubkey_uncompressed),
          chain_code: chain_code,
          privkey: k_int,
          pubkey: ethereum_public_key
        }
      end
    end
  end
end
