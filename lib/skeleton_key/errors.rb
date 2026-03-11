module SkeletonKey
  module Errors
    class SkeletonKeyError < StandardError; end

    # Custom error for invalid seed
    class InvalidSeedError < SkeletonKeyError
      def initialize(msg = "must be a byte string of length #{SkeletonKey::Constants::SEED_LENGTHS.inspect}")
        super(msg)
      end
    end

    # Custom error for invalid entropy
    class InvalidEntropyLengthError < SkeletonKeyError
      def initialize(msg = "must be a byte string of length #{SkeletonKey::Constants::ENTROPY_LENGTHS.inspect}")
        super(msg)
      end
    end

    # Custom error for entropy format issues
    class InvalidEntropyFormatError < SkeletonKeyError
      def initialize(msg = "must be one of :bytes, :hex, or :base64")
        super(msg)
      end
    end

    class InvalidPathFormatError < SkeletonKeyError
      def initialize(msg = "invalid path format")
        super(msg)
      end
    end

    class IndexOutOfBoundsError < SkeletonKeyError
      def initialize(msg = "index out of bounds")
        super(msg)
      end
    end

    class InvalidMasterKeyError < SkeletonKeyError
      def initialize(msg = "invalid master key")
        super(msg)
      end
    end

    class InvalidPrivateKeyError < SkeletonKeyError
      def initialize(msg = "invalid private key")
        super(msg)
      end
    end

    class DerivationValueOutOfRangeError < SkeletonKeyError
      def initialize(msg = "derived IL out of range")
        super(msg)
      end
    end

    class InvalidDerivedKeyError < SkeletonKeyError
      def initialize(msg = "derived invalid key")
        super(msg)
      end
    end

    class HardenedPublicDerivationError < SkeletonKeyError
      def initialize(msg = "cannot derive hardened child from public key")
        super(msg)
      end
    end

    class UnsupportedPurposeError < SkeletonKeyError
      def initialize(purpose)
        super("unsupported purpose: #{purpose}")
      end
    end

    class UnsupportedPurposeNetworkError < SkeletonKeyError
      def initialize(purpose:, network:)
        super("unsupported purpose/network combination: purpose=#{purpose}, network=#{network}")
      end
    end
  end
end
