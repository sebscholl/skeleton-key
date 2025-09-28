module SkeletonKey
  module Errors
    # Custom error for invalid seed
    class InvalidSeedError < StandardError
      def initialize(msg = "must be a byte string of length #{SkeletonKey::Constants::SEED_LENGTHS.inspect}")
        super(msg)
      end
    end

    # Custom error for invalid entropy
    class InvalidEntropyLengthError < StandardError
      def initialize(msg = "must be a byte string of length #{SkeletonKey::Constants::ENTROPY_LENGTHS.inspect}")
        super(msg)
      end
    end

    # Custom error for entropy format issues
    class InvalidEntropyFormatError < StandardError
      def initialize(msg = "must be one of :bytes, :hex, or :base64")
        super(msg)
      end
    end
  end
end
