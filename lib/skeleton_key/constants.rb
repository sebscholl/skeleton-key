# frozen_string_literal: true

module SkeletonKey
  ##
  # Core constants shared across the SkeletonKey library.
  #
  # These constants define valid seed and entropy lengths
  # according to BIP-39 (mnemonics), SLIP-39 (Shamir mnemonics),
  # and common cryptographic practice.
  #
  # @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki BIP-39
  # @see https://github.com/satoshilabs/slips/blob/master/slip-0039.md SLIP-39
  module Constants
    ##
    # Valid entropy lengths for mnemonic generation.
    #
    # BIP-39 specifies entropy sizes of 128–256 bits,
    # in steps of 32 bits. These map to 12–24 words.
    #
    # @return [Array<Integer>] allowed entropy sizes in bytes
    ENTROPY_LENGTHS = [16, 20, 24, 28, 32].freeze

    ##
    # Valid BIP39 mnemonic lengths in words.
    #
    # BIP39 supports 12, 15, 18, 21, and 24 word phrases.
    #
    # @return [Array<Integer>] allowed mnemonic word counts
    MNEMONIC_WORD_COUNTS = [12, 15, 18, 21, 24].freeze

    ##
    # Valid master secret lengths for SLIP-39.
    #
    # SLIP-39 supports secrets of 128, 192, or 256 bits,
    # which are represented as 16, 24, or 32 bytes.
    #
    # @return [Array<Integer>] allowed SLIP-39 master secret sizes
    SLIP39_SECRET_LENGTHS = [16, 24, 32].freeze

    ##
    # Valid seed lengths for wallet derivation.
    #
    # - BIP-39 seeds are produced by PBKDF2 and are always 64 bytes (512 bits).
    # - SLIP-39 master secrets are used directly and may be 16, 24, or 32 bytes.
    #
    # @return [Array<Integer>] allowed seed sizes in bytes
    SEED_LENGTHS = (SLIP39_SECRET_LENGTHS + [64]).freeze

    ##
    # Standard length of a private key (secp256k1 or Ed25519).
    #
    # Both Bitcoin/Ethereum (secp256k1) and Solana (Ed25519)
    # use 32-byte private keys.
    #
    # @return [Integer]
    PRIVATE_KEY_LENGTH = 32

    ##
    # Standard length of a public key (compressed Ed25519 or secp256k1).
    #
    # - Ed25519 public keys are 32 bytes.
    # - Compressed secp256k1 public keys are 33 bytes,
    #   but the underlying X coordinate is 32 bytes.
    #
    # @return [Integer]
    PUBLIC_KEY_LENGTH = 32
  end
end
