# frozen_string_literal: true

require "openssl"
require "securerandom"

module SkeletonKey
  module Recovery
    ##
    # SLIP-0039 Shamir-share recovery for master secrets.
    #
    # This class validates SLIP-0039 mnemonic shares, enforces group and member
    # thresholds, can generate new share sets from a master secret, reconstructs
    # the encrypted master secret, and decrypts it into a {Seed}. It belongs to
    # the recovery layer and intentionally stops before any downstream chain
    # derivation begins.
    #
    # Caller input is a **flat array of share strings**. The caller does not
    # supply nested groups. Instead, each share encodes its own group metadata,
    # and {Slip39} reconstructs the group structure internally during recovery.
    #
    # In other words, the protocol is multi-group, but the Ruby interface is:
    # - `Array<String>` of shares
    # - optional ASCII passphrase
    # - return a recovered {Seed}
    #
    # @example Recover a seed from a single-group threshold set
    #   seed = SkeletonKey::Recovery::Slip39.recover(shares, passphrase: "")
    #
    # @example Recover a seed from a multi-group threshold set
    #   shares = [
    #     group_0_share_0,
    #     group_0_share_1,
    #     group_2_share_0,
    #     group_2_share_1
    #   ]
    #
    #   # Group membership is inferred from the encoded SLIP-0039 share data.
    #   seed = SkeletonKey::Recovery::Slip39.recover(shares, passphrase: "PASS8")
    class Slip39
      extend Utils::Encoding

      WORDLIST_PATH = File.expand_path("slip39_wordlist.txt", __dir__)
      include Slip39Support::Protocol

      class << self
        # Generates SLIP-0039 mnemonic shares from a master secret.
        #
        # For single-group sharing, provide `member_threshold` and
        # `member_count`. For advanced multi-group sharing, provide `groups:`
        # and `group_threshold:`.
        #
        # @param master_secret [String, Array<Integer>, Seed] 16, 24, or 32-byte master secret
        # @param member_threshold [Integer, nil] single-group member threshold
        # @param member_count [Integer, nil] single-group member count
        # @param groups [Array<Hash>, nil] multi-group member thresholds/counts
        # @param group_threshold [Integer] number of groups required for recovery
        # @param passphrase [String] optional SLIP-0039 passphrase
        # @param extendable [Boolean]
        # @param iteration_exponent [Integer]
        # @param random_bytes [#call, nil] optional deterministic random-byte source
        # @return [Slip39Support::GeneratedSet]
        def generate(
          master_secret:,
          member_threshold: nil,
          member_count: nil,
          groups: nil,
          group_threshold: 1,
          passphrase: "",
          extendable: true,
          iteration_exponent: 1,
          random_bytes: nil
        )
          group_config = normalize_groups(member_threshold:, member_count:, groups:)
          generator = Slip39Support::Generator.new(
            wordlist: wordlist,
            customization_string: method(:customization_string_for),
            cipher: Slip39Support::Cipher.new(
              customization_string_orig: Slip39Support::Protocol::CUSTOMIZATION_STRING_ORIG
            ),
            random_bytes: random_bytes || SecureRandom.method(:random_bytes)
          )

          generator.generate(
            master_secret: normalize_master_secret(master_secret),
            group_threshold: group_threshold,
            groups: group_config,
            passphrase: passphrase,
            extendable: extendable,
            iteration_exponent: iteration_exponent
          )
        end

        # Recovers a master secret from a set of SLIP-0039 mnemonics.
        #
        # The input is a flat list of share strings. Grouping is inferred from
        # the metadata encoded inside each share rather than from caller-supplied
        # nesting.
        #
        # @param mnemonics [Array<String>] flat threshold set of SLIP-0039 shares
        # @param passphrase [String] optional SLIP-0039 passphrase
        # @return [Seed]
        def recover(mnemonics, passphrase: "")
          new(mnemonics).recover(passphrase: passphrase)
        end

        # Loads the canonical SLIP-0039 wordlist.
        #
        # @return [Array<String>] frozen list of 1024 words
        # @raise [Errors::InvalidSlip39ShareError] if the vendored wordlist is malformed
        def wordlist
          @wordlist ||= begin
            words = File.readlines(WORDLIST_PATH, chomp: true)
            raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 wordlist length" unless words.length == Slip39Support::Protocol::RADIX

            words.freeze
          end
        end

        # Maps each word to its 10-bit index.
        #
        # @return [Hash{String => Integer}]
        def word_index
          @word_index ||= wordlist.each_with_index.to_h.freeze
        end

        def customization_string_for(extendable)
          if extendable
            Slip39Support::Protocol::CUSTOMIZATION_STRING_EXTENDABLE
          else
            Slip39Support::Protocol::CUSTOMIZATION_STRING_ORIG
          end
        end

        private

        def normalize_groups(member_threshold:, member_count:, groups:)
          if groups
            raise Errors::InvalidSlip39ConfigurationError, "pass either groups or member_threshold/member_count, not both" unless member_threshold.nil? && member_count.nil?

            return groups.map do |group|
              {
                member_threshold: group.fetch(:member_threshold),
                member_count: group.fetch(:member_count)
              }
            end
          end

          if member_threshold.nil? || member_count.nil?
            raise Errors::InvalidSlip39ConfigurationError,
                  "single-group generation requires member_threshold and member_count"
          end

          [{ member_threshold: member_threshold, member_count: member_count }]
        end

        def normalize_master_secret(master_secret)
          if master_secret.is_a?(Seed)
            return master_secret.bytes
          end

          return octets_to_bytes(master_secret) if octet_array?(master_secret)
          return hex_to_bytes(master_secret) if hex_string?(master_secret)
          return master_secret if byte_string?(master_secret)

          raise Errors::InvalidSlip39ConfigurationError, "master_secret must be bytes, hex, octets, or Seed"
        end
      end

      def initialize(mnemonics)
        @mnemonics = Array(mnemonics)
        @decoder = Slip39Support::Decoder.new(
          word_index: self.class.word_index,
          customization_string: method(:customization_string)
        )
        @secret_recovery = Slip39Support::SecretRecovery.new
        @cipher = Slip39Support::Cipher.new(
          customization_string_orig: CUSTOMIZATION_STRING_ORIG
        )
      end

      # Validates the share set and recovers the decrypted master secret.
      #
      # Shares may span one or more protocol groups, but callers still pass a
      # single flat array. This method decodes the embedded group metadata and
      # reconstructs the required group/member threshold structure internally.
      #
      # @param passphrase [String] optional SLIP-0039 passphrase
      # @return [Seed]
      # @raise [Errors::InvalidSlip39ShareError] if the share set is invalid or insufficient
      def recover(passphrase: "")
        raise Errors::InvalidSlip39ShareError, "the list of SLIP-0039 shares is empty" if @mnemonics.empty?

        groups = @decoder.decode(@mnemonics)
        encrypted_master_secret = @secret_recovery.recover_encrypted_master_secret(groups)
        validate_passphrase!(passphrase)
        Seed.import_from_bytes(
          @cipher.decrypt(
            encrypted_master_secret.fetch(:ciphertext),
            passphrase.b,
            encrypted_master_secret.fetch(:iteration_exponent),
            encrypted_master_secret.fetch(:identifier),
            encrypted_master_secret.fetch(:extendable)
          )
        )
      end

      private

      def validate_passphrase!(passphrase)
        return if passphrase.bytes.all? { |byte| byte.between?(32, 126) }

        raise Errors::InvalidSlip39ShareError, "SLIP-0039 passphrase must contain only printable ASCII characters"
      end

      def customization_string(extendable)
        extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG
      end
    end
  end
end
