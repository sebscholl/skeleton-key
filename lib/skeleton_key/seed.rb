require "securerandom"

module SkeletonKey
  ##
  # Canonical seed container shared by all chain derivation entry points.
  #
  # {Seed} is the normalization boundary between recovery inputs
  # (BIP39/SLIP-0039), raw entropy-like byte material, and downstream chain
  # derivation. Callers can import from several supported input forms, but once
  # constructed the object always wraps validated raw bytes.
  class Seed
    include Utils::Encoding
    extend Utils::Encoding

    # Raw seed bytes after normalization and validation.
    #
    # @return [String]
    attr_reader :bytes

    # @param bytes [String] raw seed bytes
    # @raise [Errors::InvalidSeedError] if the seed length is not valid
    def initialize(bytes)
      @bytes = bytes

      raise Errors::InvalidSeedError unless Constants::SEED_LENGTHS.include?(@bytes.bytesize)
    end

    # Returns the hex representation of the seed
    #
    # @return [String] hex string
    def hex
      bytes_to_hex(@bytes)
    end

    # Returns the array of octets (integers 0-255) representation of the seed
    #
    # @return [Array<Integer>] array of byte values
    def octets
      @bytes.bytes
    end

    class << self
      # Loads a seed from a given value
      #
      # Supported inputs:
      # - `nil` to generate a new random seed
      # - existing {Seed}
      # - validated {Recovery::Bip39}
      # - hex string
      # - mnemonic string
      # - raw byte string
      # - array of octets
      #
      # @param value [String, Seed, Recovery::Bip39, Array<Integer>, nil]
      # @param passphrase [String] optional BIP39 passphrase for mnemonic input
      # @return [Seed]
      # @raise [Errors::InvalidSeedError] if the value cannot be normalized
      def import(value, passphrase: "")
        case
        when value.nil? then generate
        when value.is_a?(Seed) then import_from_seed(value)
        when value.is_a?(Recovery::Bip39) then import_from_mnemonic(value, passphrase: passphrase)
        when hex_string?(value) then import_from_hex(value)
        when mnemonic_string?(value) then import_from_mnemonic(value, passphrase: passphrase)
        when byte_string?(value) then import_from_bytes(value)
        when octet_array?(value) then import_from_octets(value)
        else
          raise Errors::InvalidSeedError
        end
      end

      # Generates a new random 32-byte seed
      #
      # @return [Seed] the generated seed
      def generate
        new(Core::Entropy.generate(bytes: 32))
      end

      # Creates a new seed from a byte string
      #
      # @param seed [String] the byte string seed
      # @return [Seed] the created Seed
      def import_from_bytes(bytes)
        new(bytes)
      end

      # Creates a new seed from a hex string
      #
      # @param seed_hex [String] the hex string seed
      # @return [Seed] the created Seed
      def import_from_hex(hex)
        new(hex_to_bytes(hex))
      end

      # Creates a new seed from an array of octets
      #
      # @param seed_octets [Array<Integer>] the array of octets
      # @return [Seed] the created Seed
      def import_from_octets(octets)
        new(octets_to_bytes(octets))
      end

      # Creates a new seed from another Seed
      #
      # @param seed [Seed] the Seed to copy
      # @return [Seed] the created Seed
      def import_from_seed(seed)
        new(seed.bytes)
      end

      # Recovers a seed from a BIP39 mnemonic phrase.
      #
      # @param mnemonic [Recovery::Bip39, String]
      # @param passphrase [String] optional BIP39 passphrase
      # @return [Seed]
      def import_from_mnemonic(mnemonic, passphrase: "")
        Recovery::Bip39.import(mnemonic).seed(passphrase: passphrase)
      end

      private

      def mnemonic_string?(value)
        return false unless value.is_a?(String)

        Constants::MNEMONIC_WORD_COUNTS.include?(value.strip.split(/\s+/).length)
      end
    end
  end
end
