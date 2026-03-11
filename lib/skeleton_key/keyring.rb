
module SkeletonKey
  ##
  # SkeletonKey::Keyring
  #
  # The {Keyring} class is the entry point for working with chain-agnostic key
  # material. It encapsulates a master {Seed} and exposes convenience accessors
  # for deriving accounts on supported blockchains (e.g. Bitcoin, Ethereum,
  # Solana).
  #
  # A {Keyring} can be initialized with:
  # - a raw byte string (32–64 bytes),
  # - a hex-encoded seed string,
  # - an array of octets (Array<Integer>),
  # - another {Seed} instance,
  # - or nothing (in which case a new random seed will be generated).
  #
  # Each plugin (e.g. {SkeletonKey::Bitcoin::Account}) receives the canonical
  # {Seed} and is responsible for deriving its own keys according to the
  # chain’s standard derivation path (BIP44, BIP84, SLIP-10, etc.).
  #
  # @example Generate a new keyring with a random seed
  #   keyring = SkeletonKey::Keyring.new
  #   account = keyring.bitcoin
  #
  # @example Initialize from an existing hex seed
  #   keyring = SkeletonKey::Keyring.new(seed: "2df1184bbb5ee0e4303d6db3b4013284")
  #   account = keyring.bitcoin(purpose: 84, coin_type: 0, account: 0)
  #
  # @see SkeletonKey::Seed
  # @see SkeletonKey::Bitcoin::Account
  class Keyring
    # Initializes a new Keyring with an optional seed
    #
    # @param seed [String, Seed, Array<Integer>, nil] the seed to initialize the Keyring with (optional)
    # @return [Keyring] the initialized Keyring
    def initialize(seed: nil)
      @seed = Seed.import(seed)
    end

    # Access the Bitcoin account derived from the seed
    #
    # @param kwargs [Hash] options to pass to Bitcoin::Account (purpose, coin_type, account_index, network)
    # @return [Bitcoin::Account] the derived Bitcoin account
    def bitcoin(**)
      SkeletonKey::Bitcoin::Account.new(seed: seed.bytes, **)
    end

    def ethereum(**)
      SkeletonKey::Ethereum::Account.new(seed: seed.bytes, **)
    end

    def solana(**)
      SkeletonKey::Solana::Account.new(seed: seed.bytes, **)
    end

    private

    # Reader for the seed
    # @return [Seed] the seed
    attr_reader :seed
  end
end
