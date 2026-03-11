# frozen_string_literal: true

module SkeletonKey
  module Codecs
    module Base58Check
      extend Utils::Hashing

      module_function

      def encode(payload)
        Base58.encode(payload + checksum(payload))
      end

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
