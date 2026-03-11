# frozen_string_literal: true

require "openssl"
require "digest"

module SkeletonKey
  module Derivation
    module BIP32
      # Utility modules
      include Utils::Hashing
      include Utils::Encoding

      # Constants
      CURVE = OpenSSL::PKey::EC.new("secp256k1")
      GROUP = CURVE.group
      ORDER = GROUP.order

      module_function

      # Create master key from seed
      #
      # @param seed_bytes [String] seed byte string
      # @return [Array(Integer, String)] [master_privkey_int, master_chain_code] Master key result
      def master_from_seed(seed_bytes)
        i = hmac_sha512("Bitcoin seed", seed_bytes)

        il = i[0, 32]
        ir = i[32, 32]
        k_int = parse256(il)

        raise Errors::InvalidMasterKeyError if k_int <= 0 || k_int >= ORDER

        [k_int, ir]
      end

      # Convert private key integer to compressed public key bytes
      #
      # @param k_int [Integer] private key as integer
      # @return [String] compressed public key (33 bytes)
      def privkey_to_pubkey_compressed(k_int)
        raise Errors::InvalidPrivateKeyError if k_int <= 0 || k_int >= ORDER

        bn = OpenSSL::BN.new(k_int.to_s(16), 16)
        point = GROUP.generator.mul(bn)
        point_to_bytes_compressed(point)
      end

      def privkey_to_pubkey_uncompressed(k_int)
        raise Errors::InvalidPrivateKeyError if k_int <= 0 || k_int >= ORDER

        bn = OpenSSL::BN.new(k_int.to_s(16), 16)
        point = GROUP.generator.mul(bn)
        point.to_octet_string(:uncompressed)
      end

      # Convert OpenSSL::PKey::EC::Point to compressed public key bytes
      #
      # @param point [OpenSSL::PKey::EC::Point] EC point
      # @return [String] compressed public key (33 bytes)
      def point_to_bytes_compressed(point)
        point.to_octet_string(:compressed)
      end

      # Convert compressed public key bytes to OpenSSL::PKey::EC::Point
      #
      # @param pub_compressed [String] compressed public key (33 bytes)
      # @return [OpenSSL::PKey::EC::Point] EC point
      def bytes_to_point(pub_compressed)
        # OpenSSL can parse a full EC::Point from octet string if we use PKey
        key = OpenSSL::PKey::EC.new("secp256k1")
        key.public_key = OpenSSL::PKey::EC::Point.new(GROUP, OpenSSL::BN.new(pub_compressed, 2))
        key.public_key
      end

      # Compute the parent fingerprint for BIP32 serialization.
      #
      # Per BIP32: identifier = hash160(compressed_pubkey).
      # The fingerprint is the first 4 bytes of this identifier.
      #
      # @param pubkey_compressed [String] compressed secp256k1 pubkey (33 bytes)
      # @return [String] 4-byte binary fingerprint
      def fingerprint_from_pubkey(pubkey_compressed)
        hash160(pubkey_compressed)[0, 4]
      end

      # Serializes an extended private key (xprv)
      #
      # @param k_int [Integer] private key as integer
      # @param chain_code [String] 32-byte chain code
      # @param depth [Integer] depth in the derivation path
      # @param parent_fpr [String] 4-byte parent fingerprint
      # @param child_num [Integer] child index
      # @param version [Integer] version byte (optional)
      # @return [String] base58check-encoded xprv
      def serialize_xprv(k_int, chain_code, depth:, parent_fpr:, child_num:, version: nil)
        priv_version = version || version_byte(network: @network, purpose: @purpose, private: true)

        payload = [
          priv_version,
          [depth].pack("C"),
          parent_fpr,
          ser32(child_num),
          chain_code,
          "\x00", ser256(k_int)
        ].map(&:b).join

        base58check_encode(payload)
      end

      # Serializes an extended public key (xpub)
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param chain_code [String] 32-byte chain code
      # @param depth [Integer] depth in the derivation path
      # @param parent_fpr [String] 4-byte parent fingerprint
      # @param child_num [Integer] child index
      # @param version [Integer] version byte (optional)
      # @return [String] base58check-encoded xpub
      def serialize_xpub(pubkey_bytes, chain_code, depth:, parent_fpr:, child_num:, version: nil)
        pub_version = version || version_byte(network: @network, purpose: @purpose)

        payload = [
          pub_version,
          [depth].pack("C"),
          parent_fpr,
          ser32(child_num),
          chain_code,
          pubkey_bytes
        ].map(&:b).join

        base58check_encode(payload)
      end

      # CDKpriv (hardened and non-hardened)
      #
      # @param k_parent_int [Integer] parent private key as integer
      # @param c_parent [String] 32-byte parent chain code
      # @param index [Integer] child index
      # @return [Array(Integer, String)] [child_privkey_int, child_chain_code] CKDpriv result
      def ckd_priv(k_parent_int, c_parent, index)
        data =
          if index >= 0x8000_0000
            # hardened: 0x00 || ser256(k_par) || ser32(i)
            "\x00" + ser256(k_parent_int) + ser32(index)
          else
            # non-hardened: serP(point(k_par)) || ser32(i)
            pub = privkey_to_pubkey_compressed(k_parent_int)
            pub + ser32(index)
          end

        i = hmac_sha512(c_parent, data)
        il = parse256(i[0, 32])
        ir = i[32, 32]
        raise Errors::DerivationValueOutOfRangeError if il >= ORDER

        child = (il + k_parent_int) % ORDER
        raise Errors::InvalidDerivedKeyError if child == 0
        [child, ir]
      end

      # CKDpub (non-hardened only)
      #
      # @param pub_parent_bytes [String] compressed public key (33 bytes)
      # @param c_parent [String] 32-byte chain code
      # @param index [Integer] child index (non-hardened only)
      # @return [Array(String, String)] [child_pubkey_bytes, child_chain_code] CKDpub result
      def ckd_pub(pub_parent_bytes, c_parent, index)
        raise Errors::HardenedPublicDerivationError if index >= 0x8000_0000

        i = hmac_sha512(c_parent, pub_parent_bytes + ser32(index))
        il = parse256(i[0, 32])
        ir = i[32, 32]
        raise Errors::DerivationValueOutOfRangeError if il >= ORDER

        # child_point = G*IL + K_par
        child_point = GROUP.generator.mul(OpenSSL::BN.new(il.to_s(16), 16)) +
                      bytes_to_point(pub_parent_bytes)
        [point_to_bytes_compressed(child_point), ir]
      end
    end
  end
end
