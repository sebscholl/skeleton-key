# frozen_string_literal: true

module SkeletonKey
  module Utils
    ##
    # Static helpers for encoding/decoding binary values
    # into hex, base64, base58, etc.
    #
    # Also provides validation helpers for distinguishing
    # between byte strings and hex strings.
    #
    # Usage:
    #   SkeletonKey::Utils::Encoding.hex_to_bytes("deadbeef")
    #   SkeletonKey::Utils::Encoding.bytes_to_hex("\xDE\xAD")
    #   SkeletonKey::Utils::Encoding.hex_string?("zzzz") # => false
    #
    module Encoding
      module_function

      ##
      # Base58Check encoding (Bitcoin alphabet)
      #
      # @param [String] payload binary string to encode
      # @return [String] base58check-encoded string
      def base58check_encode(payload)
        Base58.binary_to_base58(payload + Hashing.checksum(payload), :bitcoin)
      end

      ##
      # Convert a hex string into raw bytes.
      #
      # @param [String] hex a valid hex string
      # @return [String] binary string of bytes
      # @raise [ArgumentError] if input is not valid hex
      def hex_to_bytes(hex)
        raise ArgumentError, "invalid hex string" unless hex_string?(hex)
        [hex].pack("H*")
      end

      ##
      # Convert raw bytes into a hex string.
      #
      # @param [String] bytes binary string
      # @return [String] hex string
      def bytes_to_hex(bytes)
        bytes.unpack1("H*")
      end

      ##
      # Convert an array of octets (integers 0-255) into raw bytes.
      #
      # @param [Array<Integer>] octets array of byte values
      # @return [String] binary string of bytes
      def octets_to_bytes(octets)
        octets.pack("C*")
      end

      ##
      # Check if a value is valid hex.
      #
      # @param [String] value
      # @return [Boolean]
      def hex_string?(value)
        value.is_a?(String) && value.match?(/\A[0-9a-fA-F]+\z/) && value.length.even?
      end

      ##
      # Check if a value looks like a raw byte string.
      #
      # @param [String] value
      # @return [Boolean]
      def byte_string?(value)
        value.is_a?(String) && value.encoding == ::Encoding::BINARY
      end

      ##
      # Checks if a value is an array of octets (integers 0-255)
      #
      # @param [Object] value
      # @return [Boolean]
      def octet_array?(value)
        value.is_a?(Array) && value.all? { |b| b.is_a?(Integer) && b.between?(0, 255) }
      end

      ##
      # Serialize a 32-bit unsigned integer to big-endian binary.
      #
      # Used in BIP32 child index encoding and serialization.
      #
      # @param i [Integer] integer in range 0..2^32-1
      # @return [String] 4-byte big-endian representation
      #
      # @example
      #   ser32(1)   # => "\x00\x00\x00\x01"
      #   ser32(256) # => "\x00\x00\x01\x00"
      def ser32(i)
        [i].pack("N")
      end

      ##
      # Serialize a 256-bit integer into a fixed-length 32-byte string.
      #
      # Pads with leading zeros if necessary. Used for private key
      # and scalar encoding in BIP32.
      #
      # @param i [Integer] integer in range 0..2^256-1
      # @return [String] 32-byte binary string
      #
      # @example
      #   ser256(1).bytesize  # => 32
      #   ser256(1).unpack1("H*") # => "0000...0001" (64 hex chars)
      def ser256(i)
        i.to_s(16).rjust(64, "0").scan(/../).map { |b| b.hex }.pack("C*")
      end

      ##
      # Parse a 32-byte string into a 256-bit integer.
      #
      # Inverse of {#ser256}. Converts a big-endian binary
      # string into an Integer.
      #
      # @param b [String] 32-byte binary string
      # @return [Integer] integer value
      #
      # @example
      #   i = 42
      #   bin = ser256(i)
      #   parse256(bin) # => 42
      def parse256(b)
        b.unpack1("H*").to_i(16)
      end
    end
  end
end
