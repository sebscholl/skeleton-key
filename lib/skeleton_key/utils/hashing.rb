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

      def keccak256(data)
        rate = 136
        state = Array.new(25, 0)
        offset = 0

        while offset + rate <= data.bytesize
          keccak_absorb_block(state, data.byteslice(offset, rate))
          keccak_f1600(state)
          offset += rate
        end

        tail = (data.byteslice(offset, data.bytesize - offset) || +"").b
        tail << "\x01".b
        tail << "\x00".b * (rate - tail.bytesize)
        tail.setbyte(rate - 1, tail.getbyte(rate - 1) | 0x80)

        keccak_absorb_block(state, tail)
        keccak_f1600(state)
        keccak_squeeze(state, 32)
      end

      def keccak_absorb_block(state, block)
        (block.bytesize / 8).times do |idx|
          lane_bytes = block.byteslice(idx * 8, 8).bytes
          lane = lane_bytes.each_with_index.reduce(0) do |acc, (byte, byte_idx)|
            acc | (byte << (8 * byte_idx))
          end
          state[idx] ^= lane
        end
      end

      def keccak_squeeze(state, length)
        output = +"".b
        lane_index = 0

        while output.bytesize < length
          output << [state[lane_index]].pack("Q<")
          lane_index += 1
          if lane_index == 17 && output.bytesize < length
            keccak_f1600(state)
            lane_index = 0
          end
        end

        output.byteslice(0, length)
      end

      def keccak_f1600(state)
        24.times do |round|
          c = 5.times.map do |x|
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
          end

          d = 5.times.map do |x|
            c[(x - 1) % 5] ^ keccak_rotl64(c[(x + 1) % 5], 1)
          end

          25.times do |idx|
            state[idx] = (state[idx] ^ d[idx % 5]) & keccak_mask
          end

          b = Array.new(25, 0)
          5.times do |x|
            5.times do |y|
              b[y + (5 * ((2 * x + 3 * y) % 5))] =
                keccak_rotl64(state[x + (5 * y)], keccak_rotation_offsets[x][y])
            end
          end

          5.times do |x|
            5.times do |y|
              idx = x + (5 * y)
              state[idx] = b[idx] ^ ((~b[((x + 1) % 5) + (5 * y)]) & b[((x + 2) % 5) + (5 * y)])
              state[idx] &= keccak_mask
            end
          end

          state[0] ^= keccak_round_constants[round]
        end
      end

      def keccak_rotl64(value, shift)
        shift %= 64
        return value & keccak_mask if shift.zero?

        ((value << shift) | (value >> (64 - shift))) & keccak_mask
      end

      def keccak_mask
        0xFFFF_FFFF_FFFF_FFFF
      end

      def keccak_rotation_offsets
        [
          [0, 36, 3, 41, 18],
          [1, 44, 10, 45, 2],
          [62, 6, 43, 15, 61],
          [28, 55, 25, 21, 56],
          [27, 20, 39, 8, 14]
        ]
      end

      def keccak_round_constants
        [
          0x0000000000000001,
          0x0000000000008082,
          0x800000000000808A,
          0x8000000080008000,
          0x000000000000808B,
          0x0000000080000001,
          0x8000000080008081,
          0x8000000000008009,
          0x000000000000008A,
          0x0000000000000088,
          0x0000000080008009,
          0x000000008000000A,
          0x000000008000808B,
          0x800000000000008B,
          0x8000000000008089,
          0x8000000000008003,
          0x8000000000008002,
          0x8000000000000080,
          0x000000000000800A,
          0x800000008000000A,
          0x8000000080008081,
          0x8000000000008080,
          0x0000000080000001,
          0x8000000080008008
        ]
      end
    end
  end
end
