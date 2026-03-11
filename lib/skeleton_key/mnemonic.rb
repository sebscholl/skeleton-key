# frozen_string_literal: true

require "openssl"

module SkeletonKey
  class Mnemonic
    include Utils::Hashing

    WORDLIST_PATH = File.expand_path("core/bip39_english.txt", __dir__)

    attr_reader :phrase

    def initialize(phrase)
      @phrase = normalize_phrase(phrase)
      validate!
    end

    def words
      phrase.split(" ")
    end

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
      def import(value)
        case
        when value.is_a?(Mnemonic) then value
        when value.is_a?(String) then new(value)
        else
          raise Errors::InvalidMnemonicError
        end
      end

      def wordlist
        @wordlist ||= File.readlines(WORDLIST_PATH, chomp: true).freeze
      end

      def word_index
        @word_index ||= wordlist.each_with_index.to_h.freeze
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
