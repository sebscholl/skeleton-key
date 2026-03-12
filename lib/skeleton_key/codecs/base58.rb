# frozen_string_literal: true

module SkeletonKey
  module Codecs
    ##
    # Raw Base58 codec using the Bitcoin alphabet.
    #
    # This module performs plain Base58 conversion only. It does not append or
    # validate checksums; callers that need Base58Check should use
    # {Base58Check}. The implementation preserves leading zero bytes as `"1"`
    # characters to match Bitcoin-compatible tooling.
    module Base58
      ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".freeze
      INDEXES = ALPHABET.chars.each_with_index.to_h.freeze

      module_function

      # Encodes raw bytes as a Base58 string.
      #
      # @param bytes [String] binary payload
      # @return [String] Base58 string
      def encode(bytes)
        return "" if bytes.empty?

        zero_prefixes = bytes.bytes.take_while(&:zero?).size
        value = bytes.unpack1("H*").to_i(16)
        encoded = +""

        while value.positive?
          value, remainder = value.divmod(58)
          encoded.prepend(ALPHABET[remainder])
        end

        ("1" * zero_prefixes) + encoded
      end

      # Decodes a Base58 string into raw bytes.
      #
      # @param encoded [String] Base58 string
      # @return [String] decoded binary payload
      # @raise [Errors::InvalidBase58Error] if the string contains invalid characters
      def decode(encoded)
        raise Errors::InvalidBase58Error if encoded.nil?
        raise Errors::InvalidBase58Error unless encoded.is_a?(String)
        raise Errors::InvalidBase58Error if encoded.empty?

        value = 0
        encoded.each_char do |char|
          digit = INDEXES[char]
          raise Errors::InvalidBase58Error unless digit

          value = (value * 58) + digit
        end

        hex = value.to_s(16)
        hex = "0#{hex}" if hex.length.odd?
        decoded = hex.empty? ? +"".b : [hex].pack("H*")

        leading_zeroes = encoded.each_char.take_while { |char| char == "1" }.size
        ("\x00".b * leading_zeroes) + decoded
      end
    end
  end
end
