# frozen_string_literal: true

require "digest"
require "openssl"

module SkeletonKey
  module Utils
    ##
    # Collection of cryptographic hashing and HMAC utilities.
    #
    # This module wraps common digest primitives into clear,
    # chainable methods with explicit names.
    #
    # These are the **building blocks** for higher-level functions
    # like address encoding (Bitcoin), key derivation (BIP32/SLIP-10),
    # and message authentication.
    #
    # @example Compute a Bitcoin address hash
    #   pubkey = "\x02..." # compressed secp256k1 public key
    #   addr_hash = SkeletonKey::Hashing.hash160(pubkey)
    #
    # @example Compute a BIP32 master key
    #   seed = SecureRandom.random_bytes(64)
    #   i = SkeletonKey::Hashing.hmac_sha512("Bitcoin seed", seed)
    #
    module Hashing
      module_function
      ##
      # Generate n-byte checksum (first n bytes of double SHA256)
      #
      # @param payload [String] input byte string
      # @return [String] n-byte checksum
      def checksum(payload, length: 4)
        double_sha256(payload)[0, length]
      end

      ##
      # Single SHA-256 digest of data.
      #
      # @param data [String] input byte string
      # @return [String] 32-byte binary digest
      #
      # @see https://en.wikipedia.org/wiki/SHA-2
      def sha256(data)
        Digest::SHA256.digest(data)
      end

      ##
      # Single RIPEMD-160 digest of data.
      #
      # @param data [String] input byte string
      # @return [String] 20-byte binary digest
      #
      # @see https://homes.esat.kuleuven.be/~bosselae/ripemd160/
      def ripemd160(data)
        Digest::RMD160.digest(data)
      end

      ##
      # Hash160 = RIPEMD-160(SHA-256(data))
      #
      # Widely used in Bitcoin for address derivation from public keys.
      #
      # @param data [String] input byte string
      # @return [String] 20-byte binary digest
      #
      # @example
      #   SkeletonKey::Hashing.hash160(pubkey)
      def hash160(data)
        ripemd160(sha256(data))
      end

      ##
      # Double SHA-256 digest.
      #
      # Used in Bitcoin for checksums and block header hashing.
      #
      # @param data [String] input byte string
      # @return [String] 32-byte binary digest
      #
      # @example
      #   SkeletonKey::Hashing.double_sha256("hello")
      def double_sha256(data)
        sha256(sha256(data))
      end

      ##
      # HMAC-SHA512 keyed hash.
      #
      # Used in BIP32 master key and child key derivation.
      #
      # @param key [String] HMAC key
      # @param data [String] message input
      # @return [String] 64-byte binary HMAC digest
      #
      # @see https://en.wikipedia.org/wiki/HMAC
      # @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
      #
      # @example BIP32 master key
      #   i = SkeletonKey::Hashing.hmac_sha512("Bitcoin seed", seed)
      #   il, ir = i[0, 32], i[32, 32]
      def hmac_sha512(key, data)
        OpenSSL::HMAC.digest("SHA512", key, data)
      end
    end
  end
end
