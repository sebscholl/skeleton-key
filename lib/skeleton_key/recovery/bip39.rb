# frozen_string_literal: true

require "openssl"
require "securerandom"
require "digest"

module SkeletonKey
  module Recovery
    ##
    # BIP39 mnemonic validation and seed recovery.
    #
    # This class owns the *recovery* side of BIP39:
    # - mnemonic generation from entropy
    # - phrase normalization
    # - word membership validation against the canonical English wordlist
    # - checksum validation
    # - PBKDF2 seed derivation
    #
    # It does not perform downstream HD derivation. Callers should treat the
    # returned {Seed} as the boundary between recovery and derivation layers.
    #
    # @example Recover a seed from a 12-word mnemonic
    #   bip39 = SkeletonKey::Recovery::Bip39.new("abandon abandon ... about")
    #   seed = bip39.seed
    class Bip39
      include Utils::Hashing
      extend Utils::Encoding

      WORDLIST_PATH = File.expand_path("bip39_english.txt", __dir__)

      # The normalized BIP39 phrase as a single space-delimited string.
      #
      # @return [String]
      attr_reader :phrase

      # @param phrase [String] mnemonic phrase to validate and normalize
      # @raise [Errors::InvalidMnemonicError] if the phrase fails BIP39 checks
      def initialize(phrase)
        @phrase = normalize_phrase(phrase)
        validate!
      end

      # Returns the mnemonic words after normalization.
      #
      # @return [Array<String>]
      def words
        phrase.split(" ")
      end

      # Derives the BIP39 seed using PBKDF2-HMAC-SHA512.
      #
      # BIP39 seed derivation is intentionally separate from wordlist and
      # checksum validation. This method assumes the phrase has already been
      # validated during initialization.
      #
      # @param passphrase [String] optional BIP39 passphrase
      # @return [Seed] recovered 64-byte BIP39 seed
      def seed(passphrase: "")
        seed_bytes = OpenSSL::PKCS5.pbkdf2_hmac(
          normalized_utf8(phrase),
          normalized_utf8("mnemonic#{passphrase}"),
          2048,
          64,
          "sha512"
        )

        Seed.import_from_bytes(seed_bytes)
      end

      class << self
        # Generates a new BIP39 mnemonic for the requested word count.
        #
        # Supply `entropy` to deterministically reproduce a mnemonic. If
        # omitted, fresh entropy is generated internally.
        #
        # @param word_count [Integer] one of the supported BIP39 word counts
        # @param entropy [String, Array<Integer>, nil] optional explicit entropy
        # @return [Bip39]
        # @raise [Errors::InvalidMnemonicConfigurationError] if the word count is unsupported
        # @raise [Errors::InvalidEntropyLengthError] if explicit entropy has the wrong size
        def generate(word_count: 12, entropy: nil)
          entropy_bytes =
            if entropy.nil?
              Core::Entropy.generate(bytes: entropy_length_for_word_count(word_count))
            else
              normalize_entropy(entropy, expected_bytes: entropy_length_for_word_count(word_count))
            end

          from_entropy(entropy_bytes)
        end

        # Converts entropy into a validated BIP39 mnemonic.
        #
        # @param entropy [String, Array<Integer>] entropy bytes, hex, or octets
        # @return [Bip39]
        # @raise [Errors::InvalidEntropyLengthError] if the entropy length is unsupported
        def from_entropy(entropy)
          entropy_bytes = normalize_entropy(entropy)
          raise Errors::InvalidEntropyLengthError unless Constants::ENTROPY_LENGTHS.include?(entropy_bytes.bytesize)

          checksum_length_bits = (entropy_bytes.bytesize * 8) / 32
          entropy_bits = entropy_bytes.unpack1("B*")
          checksum_bits = Digest::SHA256.digest(entropy_bytes).unpack1("B*")[0, checksum_length_bits]
          bitstream = entropy_bits + checksum_bits

          words = bitstream.scan(/.{11}/).map do |chunk|
            wordlist.fetch(chunk.to_i(2))
          end

          new(words.join(" "))
        end

        # Coerces raw input into a validated {Bip39} instance.
        #
        # @param value [Bip39, String]
        # @return [Bip39]
        # @raise [Errors::InvalidMnemonicError] if the value cannot be imported
        def import(value)
          case
          when value.is_a?(Bip39) then value
          when value.is_a?(String) then new(value)
          else
            raise Errors::InvalidMnemonicError
          end
        end

        # Loads the canonical English BIP39 wordlist.
        #
        # @return [Array<String>] frozen array of 2048 words
        def wordlist
          @wordlist ||= File.readlines(WORDLIST_PATH, chomp: true).freeze
        end

        # Builds a constant-time-ish lookup map from word to index.
        #
        # @return [Hash{String => Integer}]
        def word_index
          @word_index ||= wordlist.each_with_index.to_h.freeze
        end

        private

        def entropy_length_for_word_count(word_count)
          raise Errors::InvalidMnemonicConfigurationError, "unsupported BIP39 word count: #{word_count}" unless Constants::MNEMONIC_WORD_COUNTS.include?(word_count)

          (word_count * 11 * 32) / (33 * 8)
        end

        def normalize_entropy(entropy, expected_bytes: nil)
          entropy_bytes =
            if octet_array?(entropy)
              octets_to_bytes(entropy)
            elsif hex_string?(entropy)
              hex_to_bytes(entropy)
            elsif byte_string?(entropy)
              entropy
            else
              raise Errors::InvalidEntropyLengthError
            end

          if expected_bytes && entropy_bytes.bytesize != expected_bytes
            raise Errors::InvalidEntropyLengthError, "entropy must be #{expected_bytes} bytes for the requested mnemonic length"
          end

          entropy_bytes
        end
      end

      private

      def normalize_phrase(value)
        normalized_utf8(value.to_s).strip.gsub(/\s+/, " ")
      end

      def normalized_utf8(value)
        value.unicode_normalize(:nfkd).encode(Encoding::UTF_8)
      end

      def validate!
        raise Errors::InvalidMnemonicError unless valid_word_count?(words)
        raise Errors::InvalidMnemonicError unless valid_words?(words)
        raise Errors::InvalidMnemonicError unless valid_checksum?(words)
      end

      def valid_word_count?(mnemonic_words)
        Constants::MNEMONIC_WORD_COUNTS.include?(mnemonic_words.length)
      end

      def valid_words?(mnemonic_words)
        mnemonic_words.all? { |word| self.class.word_index.key?(word) }
      end

      def valid_checksum?(mnemonic_words)
        # BIP39 packs each word index into 11 bits, then splits the resulting
        # bitstream into entropy bits plus checksum bits derived from SHA-256.
        bitstream = mnemonic_words.map do |word|
          self.class.word_index.fetch(word).to_s(2).rjust(11, "0")
        end.join

        entropy_length_bits = (mnemonic_words.length * 11 * 32) / 33
        checksum_length_bits = bitstream.length - entropy_length_bits
        entropy_bits = bitstream[0, entropy_length_bits]
        checksum_bits = bitstream[entropy_length_bits, checksum_length_bits]

        entropy_bytes = [entropy_bits].pack("B*")
        expected_checksum_bits = sha256(entropy_bytes).unpack1("B*")[0, checksum_length_bits]

        checksum_bits == expected_checksum_bits
      end
    end
  end
end
