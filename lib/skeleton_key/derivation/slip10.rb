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
        [key.raw_private_key, key.raw_public_key]
      end
    end
  end
end
