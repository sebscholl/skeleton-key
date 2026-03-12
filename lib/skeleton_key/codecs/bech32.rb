# frozen_string_literal: true

module SkeletonKey
  module Codecs
    ##
    # Local Bech32 and Bech32m codec implementation.
    #
    # This module implements the exact checksum and charset rules needed for
    # Bitcoin SegWit address encoding. It is intentionally generic at the codec
    # boundary: HRP handling, checksum creation, and bit conversion live here,
    # while script semantics remain in the Bitcoin layer.
    module Bech32
      CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".freeze
      CHARSET_INDEX = CHARSET.chars.each_with_index.to_h.freeze
      GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3].freeze
      SEPARATOR = "1"
      MAX_LENGTH = 90

      module Encoding
        BECH32 = :bech32
        BECH32M = :bech32m
      end

      module_function

      # Encodes an HRP and 5-bit data words into a Bech32 or Bech32m string.
      #
      # @param hrp [String] human-readable prefix
      # @param data [Array<Integer>] data words in the range 0..31
      # @param encoding [Symbol] {Encoding::BECH32} or {Encoding::BECH32M}
      # @return [String] encoded Bech32 string
      def encode(hrp, data, encoding = Encoding::BECH32)
        validate_hrp!(hrp)
        validate_data!(data)

        hrp = hrp.downcase
        combined = data + create_checksum(hrp, data, encoding)
        "#{hrp}#{SEPARATOR}#{combined.map { |value| CHARSET[value] }.join}"
      end

      # Decodes a Bech32/Bech32m string and validates its checksum.
      #
      # @param bech [String] encoded Bech32 string
      # @return [Array(String, Array<Integer>, Symbol)] HRP, data words, encoding type
      # @raise [Errors::InvalidBech32Error] if the string is malformed or the checksum fails
      def decode(bech)
        raise Errors::InvalidBech32Error unless bech.is_a?(String)
        raise Errors::InvalidBech32Error if bech.empty? || bech.length > MAX_LENGTH

        has_lower = bech.match?(/[a-z]/)
        has_upper = bech.match?(/[A-Z]/)
        raise Errors::InvalidBech32Error if has_lower && has_upper

        normalized = bech.downcase
        separator_index = normalized.rindex(SEPARATOR)
        raise Errors::InvalidBech32Error if separator_index.nil?
        raise Errors::InvalidBech32Error if separator_index < 1
        raise Errors::InvalidBech32Error if separator_index + 7 > normalized.length

        hrp = normalized[0...separator_index]
        data_part = normalized[(separator_index + 1)..]
        raise Errors::InvalidBech32Error if hrp.empty? || data_part.empty?

        data = data_part.chars.map do |char|
          value = CHARSET_INDEX[char]
          raise Errors::InvalidBech32Error unless value

          value
        end

        encoding = verify_checksum(hrp, data)
        raise Errors::InvalidBech32Error unless encoding

        [hrp, data[0...-6], encoding]
      end

      # Converts a stream of fixed-width integers into another width.
      #
      # This is the normalization step required when moving between raw bytes
      # (8-bit values) and Bech32 witness program words (5-bit values).
      #
      # @param data [Array<Integer>] source values
      # @param from_bits [Integer] bit width of each source value
      # @param to_bits [Integer] desired bit width of each output value
      # @param pad [Boolean] whether trailing zero padding is permitted
      # @return [Array<Integer>]
      # @raise [Errors::InvalidConvertBitsError] if the input cannot be losslessly converted
      def convert_bits(data, from_bits, to_bits, pad)
        acc = 0
        bits = 0
        result = []
        maxv = (1 << to_bits) - 1
        max_acc = (1 << (from_bits + to_bits - 1)) - 1

        data.each do |value|
          raise Errors::InvalidConvertBitsError if value.negative? || (value >> from_bits) != 0

          acc = ((acc << from_bits) | value) & max_acc
          bits += from_bits
          while bits >= to_bits
            bits -= to_bits
            result << ((acc >> bits) & maxv)
          end
        end

        if pad
          result << ((acc << (to_bits - bits)) & maxv) if bits.positive?
        elsif bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0
          raise Errors::InvalidConvertBitsError
        end

        result
      end

      # Creates the six checksum words for the given payload.
      #
      # @return [Array<Integer>]
      def create_checksum(hrp, data, encoding)
        constant = checksum_constant(encoding)
        values = hrp_expand(hrp) + data
        polymod = polymod(values + [0, 0, 0, 0, 0, 0]) ^ constant
        6.times.map { |idx| (polymod >> (5 * (5 - idx))) & 31 }
      end

      # Verifies the checksum and returns the detected Bech32 encoding family.
      #
      # @return [Symbol, nil]
      def verify_checksum(hrp, data)
        value = polymod(hrp_expand(hrp) + data)
        return Encoding::BECH32 if value == 1
        return Encoding::BECH32M if value == 0x2bc830a3

        nil
      end

      # Returns the checksum constant for the selected encoding family.
      #
      # @return [Integer]
      def checksum_constant(encoding)
        case encoding
        when Encoding::BECH32 then 1
        when Encoding::BECH32M then 0x2bc830a3
        else
          raise Errors::InvalidBech32Error, "unsupported bech32 encoding"
        end
      end

      # Computes the Bech32 polymod checksum accumulator.
      #
      # @return [Integer]
      def polymod(values)
        chk = 1
        values.each do |value|
          top = chk >> 25
          chk = ((chk & 0x1ffffff) << 5) ^ value
          5.times do |idx|
            chk ^= GENERATOR[idx] if ((top >> idx) & 1) == 1
          end
        end
        chk
      end

      # Expands the HRP into the form required by the Bech32 checksum.
      #
      # @return [Array<Integer>]
      def hrp_expand(hrp)
        hrp.bytes.map { |byte| byte >> 5 } + [0] + hrp.bytes.map { |byte| byte & 31 }
      end

      def validate_hrp!(hrp)
        raise Errors::InvalidBech32Error unless hrp.is_a?(String)
        raise Errors::InvalidBech32Error if hrp.empty?
        raise Errors::InvalidBech32Error unless hrp.bytes.all? { |byte| byte.between?(33, 126) }
      end

      def validate_data!(data)
        raise Errors::InvalidBech32Error unless data.is_a?(Array)
        raise Errors::InvalidBech32Error unless data.all? { |value| value.is_a?(Integer) && value.between?(0, 31) }
      end
    end
  end
end
