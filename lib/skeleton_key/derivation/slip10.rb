# frozen_string_literal: true

require "openssl"

module SkeletonKey
  module Derivation
    ##
    # Hardened-only SLIP-0010 derivation for Ed25519 keys.
    #
    # This module provides the shared derivation primitive used by Solana. It
    # owns seed-to-master-key derivation, hardened child derivation, and
    # deterministic Ed25519 keypair reconstruction from a 32-byte seed. It does
    # not define any chain-specific path conventions or address formats.
    module SLIP10
      include Utils::Hashing
      include Utils::Encoding

      HARDENED_FLAG = 0x8000_0000
      ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420"
      ED25519_PKCS8_PRIVATE_KEY_SIZE = 32
      ED25519_SPKI_PUBLIC_KEY_SIZE = 32

      module_function

      # Derives the master key seed and chain code from a seed byte string.
      #
      # @param seed_bytes [String] canonical seed bytes
      # @return [Array(String, String)] 32-byte key seed and 32-byte chain code
      def master_from_seed(seed_bytes)
        i = hmac_sha512("ed25519 seed", seed_bytes)
        [i.byteslice(0, 32), i.byteslice(32, 32)]
      end

      # Derives a hardened SLIP-0010 child.
      #
      # Ed25519 SLIP-0010 does not support unhardened child derivation.
      #
      # @param parent_key [String] 32-byte parent key seed
      # @param parent_chain_code [String] 32-byte parent chain code
      # @param index [Integer] hardened child index
      # @return [Array(String, String)] child key seed and child chain code
      # @raise [Errors::UnsupportedDerivationIndexError] if a non-hardened index is requested
      def ckd_priv(parent_key, parent_chain_code, index)
        raise Errors::UnsupportedDerivationIndexError, "ed25519 SLIP-10 requires hardened indices" if index < HARDENED_FLAG

        data = "\x00".b + parent_key + ser32(index)
        i = hmac_sha512(parent_chain_code, data)
        [i.byteslice(0, 32), i.byteslice(32, 32)]
      end

      # Reconstructs an Ed25519 keypair from a 32-byte seed.
      #
      # @param seed [String] 32-byte private seed
      # @return [Array(String, String)] raw private key and raw public key
      def keypair_from_seed(seed)
        key = OpenSSL::PKey.read([ED25519_PKCS8_PREFIX + seed.unpack1("H*")].pack("H*"))
        [raw_private_key(key), raw_public_key(key)]
      end

      # Extracts the 32-byte private seed from an Ed25519 key object.
      #
      # Some Ruby/OpenSSL builds expose `raw_private_key`; older builds only
      # expose PKCS#8 DER serialization. The trailing 32 bytes of the PKCS#8
      # structure are the original seed.
      #
      # @param key [OpenSSL::PKey::PKey] Ed25519 key object
      # @return [String] 32-byte private seed
      def raw_private_key(key)
        return key.raw_private_key if key.respond_to?(:raw_private_key)

        key.private_to_der.byteslice(-ED25519_PKCS8_PRIVATE_KEY_SIZE, ED25519_PKCS8_PRIVATE_KEY_SIZE)
      end

      # Extracts the 32-byte public key from an Ed25519 key object.
      #
      # Some Ruby/OpenSSL builds expose `raw_public_key`; older builds only
      # expose SubjectPublicKeyInfo DER. The trailing 32 bytes of the SPKI
      # structure are the Ed25519 public key bytes.
      #
      # @param key [OpenSSL::PKey::PKey] Ed25519 key object
      # @return [String] 32-byte public key
      def raw_public_key(key)
        return key.raw_public_key if key.respond_to?(:raw_public_key)

        key.public_to_der.byteslice(-ED25519_SPKI_PUBLIC_KEY_SIZE, ED25519_SPKI_PUBLIC_KEY_SIZE)
      end
    end
  end
end
