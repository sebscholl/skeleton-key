# frozen_string_literal: true

module SkeletonKey
  module Codecs
    module Base58Check
      extend Utils::Hashing

      ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      INDEXES = ALPHABET.chars.each_with_index.to_h.freeze

      module_function

      def encode(payload)
        binary_to_base58(payload + checksum(payload))
      end

      def decode(encoded)
        decoded = base58_to_binary(encoded)
        raise Errors::InvalidBase58Error if decoded.bytesize < 4

        payload = decoded.byteslice(0, decoded.bytesize - 4)
        observed_checksum = decoded.byteslice(-4, 4)
        raise Errors::InvalidChecksumError unless checksum(payload) == observed_checksum

        payload
      end

      def binary_to_base58(bytes)
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

      def base58_to_binary(encoded)
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
