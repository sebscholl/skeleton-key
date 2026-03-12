module SkeletonKey
  module Errors
    ##
    # Base class for typed SkeletonKey failures.
    #
    # Typed errors are part of the repository contract. They allow callers and
    # tests to distinguish invalid recovery material, unsupported derivation
    # paths, and codec failures without pattern-matching free-form strings.
    class SkeletonKeyError < StandardError; end

    # Raised when seed material cannot be normalized to an allowed byte length.
    class InvalidSeedError < SkeletonKeyError
      def initialize(msg = "must be a byte string of length #{SkeletonKey::Constants::SEED_LENGTHS.inspect}")
        super(msg)
      end
    end

    # Raised when entropy length is outside the supported range.
    class InvalidEntropyLengthError < SkeletonKeyError
      def initialize(msg = "must be a byte string of length #{SkeletonKey::Constants::ENTROPY_LENGTHS.inspect}")
        super(msg)
      end
    end

    # Raised when a requested entropy output format is unsupported.
    class InvalidEntropyFormatError < SkeletonKeyError
      def initialize(msg = "must be one of :bytes, :hex, or :base64")
        super(msg)
      end
    end

    # Raised when a BIP39 mnemonic fails word-count, wordlist, or checksum validation.
    class InvalidMnemonicError < SkeletonKeyError
      def initialize(msg = "must be a BIP39 mnemonic with #{SkeletonKey::Constants::MNEMONIC_WORD_COUNTS.inspect} words")
        super(msg)
      end
    end

    # Raised when BIP39 generation parameters are invalid.
    class InvalidMnemonicConfigurationError < SkeletonKeyError
      def initialize(msg = "invalid BIP39 generation parameters")
        super(msg)
      end
    end

    # Raised when a SLIP-0039 share or share set fails validation or threshold checks.
    class InvalidSlip39ShareError < SkeletonKeyError
      def initialize(msg = "invalid SLIP-0039 share set")
        super(msg)
      end
    end

    # Raised when SLIP-0039 generation parameters are invalid.
    class InvalidSlip39ConfigurationError < SkeletonKeyError
      def initialize(msg = "invalid SLIP-0039 generation parameters")
        super(msg)
      end
    end

    # Raised when a derivation path string cannot be parsed.
    class InvalidPathFormatError < SkeletonKeyError
      def initialize(msg = "invalid path format")
        super(msg)
      end
    end

    # Raised when a caller requests a path component that does not exist.
    class IndexOutOfBoundsError < SkeletonKeyError
      def initialize(msg = "index out of bounds")
        super(msg)
      end
    end

    # Raised when seed material cannot produce a valid master key.
    class InvalidMasterKeyError < SkeletonKeyError
      def initialize(msg = "invalid master key")
        super(msg)
      end
    end

    # Raised when a private key falls outside the valid curve range.
    class InvalidPrivateKeyError < SkeletonKeyError
      def initialize(msg = "invalid private key")
        super(msg)
      end
    end

    # Raised when HMAC output yields an out-of-range derivation scalar.
    class DerivationValueOutOfRangeError < SkeletonKeyError
      def initialize(msg = "derived IL out of range")
        super(msg)
      end
    end

    # Raised when child key derivation lands on an invalid point or scalar.
    class InvalidDerivedKeyError < SkeletonKeyError
      def initialize(msg = "derived invalid key")
        super(msg)
      end
    end

    # Raised when hardened derivation is requested from public key material.
    class HardenedPublicDerivationError < SkeletonKeyError
      def initialize(msg = "cannot derive hardened child from public key")
        super(msg)
      end
    end

    # Raised when a chain account class does not support the requested purpose.
    class UnsupportedPurposeError < SkeletonKeyError
      def initialize(purpose)
        super("unsupported purpose: #{purpose}")
      end
    end

    # Raised when a purpose/network combination is not defined by the chain layer.
    class UnsupportedPurposeNetworkError < SkeletonKeyError
      def initialize(purpose:, network:)
        super("unsupported purpose/network combination: purpose=#{purpose}, network=#{network}")
      end
    end

    # Raised when Base58 input contains invalid characters or structure.
    class InvalidBase58Error < SkeletonKeyError
      def initialize(msg = "invalid base58 string")
        super(msg)
      end
    end

    # Raised when a serialized checksum does not match the payload.
    class InvalidChecksumError < SkeletonKeyError
      def initialize(msg = "invalid checksum")
        super(msg)
      end
    end

    # Raised when Bech32 or Bech32m input fails format or checksum validation.
    class InvalidBech32Error < SkeletonKeyError
      def initialize(msg = "invalid bech32 string")
        super(msg)
      end
    end

    # Raised when 5-bit/8-bit conversion cannot be performed losslessly.
    class InvalidConvertBitsError < SkeletonKeyError
      def initialize(msg = "invalid convert_bits input")
        super(msg)
      end
    end

    # Raised when a derivation family rejects the requested child index.
    class UnsupportedDerivationIndexError < SkeletonKeyError
      def initialize(msg = "unsupported derivation index")
        super(msg)
      end
    end
  end
end
