module SkeletonKey
  module Core
    ##
    # Cryptographically secure entropy generation.
    #
    # This module is the raw randomness boundary for SkeletonKey. It generates
    # entropy suitable for seed creation and mnemonic generation, but it does
    # not interpret that entropy as a chain-specific key or address.
    module Entropy
      # Generates cryptographically secure random entropy
      #
      # @param bytes [Integer] the number of random bytes to generate (default: 32)
      # @param format [Symbol] the format of the output (:bytes, :octets, :hex)
      # @return [String, Array<Integer>] the generated entropy in the specified format
      # @raise [ArgumentError] if bytes is not a valid entropy length or format is invalid
      def self.generate(bytes: 32, format: :bytes)
        raise SkeletonKey::Errors::InvalidEntropyLengthError unless valid_entropy_lengths.include?(bytes)
        raw = SecureRandom.random_bytes(bytes)

        case format
        when :bytes  then raw.freeze                  # binary string (32 bytes)
        when :octets then raw.bytes.freeze            # array of byte values (32 integers)
        when :hex    then raw.unpack1("H*")           # 64 hex chars for 32 bytes
        else
          raise SkeletonKey::Errors::InvalidEntropyFormatError
        end
      end

      # Returns the valid byte sizes for entropy generation
      #
      # @return [Array<Integer>] valid byte sizes
      def self.valid_entropy_lengths
        SkeletonKey::Constants::ENTROPY_LENGTHS
      end
    end
  end
end
