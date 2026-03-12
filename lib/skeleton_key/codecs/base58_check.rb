# frozen_string_literal: true

module SkeletonKey
  module Codecs
    ##
    # Base58Check codec used by Bitcoin-facing serialization.
    #
    # Base58Check appends a four-byte double-SHA256 checksum to the payload
    # before Base58 encoding. This module owns checksum construction and
    # verification, while {Base58} handles the underlying alphabet conversion.
    module Base58Check
      extend Utils::Hashing

      module_function

      # Encodes a payload with a four-byte checksum.
      #
      # @param payload [String] raw bytes to encode
      # @return [String] Base58Check string
      def encode(payload)
        Base58.encode(payload + checksum(payload))
      end

      # Decodes and verifies a Base58Check string.
      #
      # @param encoded [String] Base58Check string
      # @return [String] decoded payload without checksum bytes
      # @raise [Errors::InvalidBase58Error] if the string is malformed
      # @raise [Errors::InvalidChecksumError] if the checksum does not match
      def decode(encoded)
        decoded = Base58.decode(encoded)
        raise Errors::InvalidBase58Error if decoded.bytesize < 4

        payload = decoded.byteslice(0, decoded.bytesize - 4)
        observed_checksum = decoded.byteslice(-4, 4)
        raise Errors::InvalidChecksumError unless checksum(payload) == observed_checksum

        payload
      end
    end
  end
end
