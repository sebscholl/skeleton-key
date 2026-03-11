# frozen_string_literal: true

require "openssl"
require "set"

module SkeletonKey
  module Recovery
    class Slip39
      include Utils::Hashing

      WORDLIST_PATH = File.expand_path("slip39_wordlist.txt", __dir__)

      RADIX_BITS = 10
      RADIX = 1 << RADIX_BITS
      ID_LENGTH_BITS = 15
      EXTENDABLE_FLAG_LENGTH_BITS = 1
      ITERATION_EXP_LENGTH_BITS = 4
      ID_EXP_LENGTH_WORDS = ((ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS) + RADIX_BITS - 1) / RADIX_BITS
      CHECKSUM_LENGTH_WORDS = 3
      DIGEST_LENGTH_BYTES = 4
      CUSTOMIZATION_STRING_ORIG = "shamir".b
      CUSTOMIZATION_STRING_EXTENDABLE = "shamir_extendable".b
      GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1
      METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS
      MIN_STRENGTH_BITS = 128
      MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + ((MIN_STRENGTH_BITS + RADIX_BITS - 1) / RADIX_BITS)
      BASE_ITERATION_COUNT = 10_000
      ROUND_COUNT = 4
      SECRET_INDEX = 255
      DIGEST_INDEX = 254
      MAX_SHARE_COUNT = 16

      RawShare = Struct.new(:x, :data, keyword_init: true)
      Share = Struct.new(
        :identifier,
        :extendable,
        :iteration_exponent,
        :group_index,
        :group_threshold,
        :group_count,
        :index,
        :member_threshold,
        :value,
        keyword_init: true
      ) do
        def common_parameters
          [identifier, extendable, iteration_exponent, group_threshold, group_count]
        end

        def group_parameters
          [
            identifier,
            extendable,
            iteration_exponent,
            group_index,
            group_threshold,
            group_count,
            member_threshold
          ]
        end
      end

      class << self
        def recover(mnemonics, passphrase: "")
          new(mnemonics).recover(passphrase: passphrase)
        end

        def wordlist
          @wordlist ||= begin
            words = File.readlines(WORDLIST_PATH, chomp: true)
            raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 wordlist length" unless words.length == RADIX

            words.freeze
          end
        end

        def word_index
          @word_index ||= wordlist.each_with_index.to_h.freeze
        end

        def exp_table
          @exp_table ||= begin
            exp = Array.new(255, 0)
            log = Array.new(256, 0)
            poly = 1

            255.times do |i|
              exp[i] = poly
              log[poly] = i
              poly = (poly << 1) ^ poly
              poly ^= 0x11B if (poly & 0x100) != 0
            end

            @log_table = log.freeze
            exp.freeze
          end
        end

        def log_table
          exp_table
          @log_table
        end

        private

        def bits_to_words(bit_count)
          (bit_count + RADIX_BITS - 1) / RADIX_BITS
        end
      end

      def initialize(mnemonics)
        @mnemonics = Array(mnemonics)
      end

      def recover(passphrase: "")
        raise Errors::InvalidSlip39ShareError, "the list of SLIP-0039 shares is empty" if @mnemonics.empty?

        groups = decode_mnemonics(@mnemonics)
        encrypted_master_secret = recover_encrypted_master_secret(groups)
        validate_passphrase!(passphrase)
        Seed.import_from_bytes(
          decrypt(
            encrypted_master_secret.fetch(:ciphertext),
            passphrase.b,
            encrypted_master_secret.fetch(:iteration_exponent),
            encrypted_master_secret.fetch(:identifier),
            encrypted_master_secret.fetch(:extendable)
          )
        )
      end

      private

      def decode_mnemonics(mnemonics)
        common_params = Set.new
        groups = Hash.new { |hash, key| hash[key] = [] }

        mnemonics.each do |mnemonic|
          share = share_from_mnemonic(mnemonic)
          common_params << share.common_parameters
          groups[share.group_index] << share
        end

        if common_params.length != 1
          raise Errors::InvalidSlip39ShareError,
                "all SLIP-0039 shares must have matching identifier, group threshold, and group count"
        end

        groups.transform_values { |shares| dedupe_and_validate_group(shares) }
      end

      def dedupe_and_validate_group(shares)
        unique = shares.uniq { |share| share.index }
        if unique.length != shares.length
          raise Errors::InvalidSlip39ShareError, "SLIP-0039 share indices must be unique within a group"
        end

        group_parameters = unique.first.group_parameters
        unless unique.all? { |share| share.group_parameters == group_parameters }
          raise Errors::InvalidSlip39ShareError, "SLIP-0039 group parameters do not match"
        end

        unique
      end

      def share_from_mnemonic(mnemonic)
        indices = mnemonic_to_indices(mnemonic)
        if indices.length < MIN_MNEMONIC_LENGTH_WORDS
          raise Errors::InvalidSlip39ShareError,
                "invalid SLIP-0039 mnemonic length: must be at least #{MIN_MNEMONIC_LENGTH_WORDS} words"
        end

        padding_length = (RADIX_BITS * (indices.length - METADATA_LENGTH_WORDS)) % 16
        raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 mnemonic length" if padding_length > 8

        id_exp_int = int_from_indices(indices.first(ID_EXP_LENGTH_WORDS))
        identifier = id_exp_int >> (EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS)
        extendable = ((id_exp_int >> ITERATION_EXP_LENGTH_BITS) & 1) == 1
        iteration_exponent = id_exp_int & ((1 << ITERATION_EXP_LENGTH_BITS) - 1)

        unless verify_checksum(indices, customization_string(extendable))
          raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 checksum"
        end

        share_params_int = int_from_indices(indices[ID_EXP_LENGTH_WORDS, 2])
        group_index, group_threshold_minus_one, group_count_minus_one, index, member_threshold_minus_one =
          int_to_indices(share_params_int, 5, 4)

        if group_count_minus_one < group_threshold_minus_one
          raise Errors::InvalidSlip39ShareError, "SLIP-0039 group threshold cannot exceed group count"
        end

        value_indices = indices[(ID_EXP_LENGTH_WORDS + 2)...-CHECKSUM_LENGTH_WORDS]
        value_byte_count = bits_to_bytes(RADIX_BITS * value_indices.length - padding_length)
        value_int = int_from_indices(value_indices)
        value = [value_int.to_s(16).rjust(value_byte_count * 2, "0")].pack("H*")

        Share.new(
          identifier: identifier,
          extendable: extendable,
          iteration_exponent: iteration_exponent,
          group_index: group_index,
          group_threshold: group_threshold_minus_one + 1,
          group_count: group_count_minus_one + 1,
          index: index,
          member_threshold: member_threshold_minus_one + 1,
          value: value
        )
      rescue RangeError
        raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 mnemonic padding"
      end

      def mnemonic_to_indices(mnemonic)
        mnemonic.split.map do |word|
          self.class.word_index.fetch(word.downcase)
        rescue KeyError
          raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 mnemonic word: #{word}"
        end
      end

      def recover_encrypted_master_secret(groups)
        raise Errors::InvalidSlip39ShareError, "the set of SLIP-0039 shares is empty" if groups.empty?

        params = groups.values.first.first
        if groups.length < params.group_threshold
          raise Errors::InvalidSlip39ShareError,
                "insufficient number of mnemonic groups: requires #{params.group_threshold}"
        end

        if groups.length != params.group_threshold
          raise Errors::InvalidSlip39ShareError,
                "wrong number of mnemonic groups: expected #{params.group_threshold}, got #{groups.length}"
        end

        group_shares = groups.map do |group_index, shares|
          if shares.length != shares.first.member_threshold
            raise Errors::InvalidSlip39ShareError,
                  "wrong number of mnemonics for group #{group_index}: expected #{shares.first.member_threshold}, got #{shares.length}"
          end

          RawShare.new(
            x: group_index,
            data: recover_secret(
              shares.first.member_threshold,
              shares.map { |share| RawShare.new(x: share.index, data: share.value) }
            )
          )
        end

        ciphertext = recover_secret(params.group_threshold, group_shares)
        {
          identifier: params.identifier,
          extendable: params.extendable,
          iteration_exponent: params.iteration_exponent,
          ciphertext: ciphertext
        }
      end

      def recover_secret(threshold, shares)
        return shares.first.data if threshold == 1

        shared_secret = interpolate(shares, SECRET_INDEX)
        digest_share = interpolate(shares, DIGEST_INDEX)
        digest = digest_share.byteslice(0, DIGEST_LENGTH_BYTES)
        random_part = digest_share.byteslice(DIGEST_LENGTH_BYTES, digest_share.bytesize - DIGEST_LENGTH_BYTES)

        unless digest == create_digest(random_part, shared_secret)
          raise Errors::InvalidSlip39ShareError, "invalid digest of the shared secret"
        end

        shared_secret
      end

      def interpolate(shares, x_coordinate)
        x_values = shares.map(&:x)
        raise Errors::InvalidSlip39ShareError, "SLIP-0039 share indices must be unique" unless x_values.uniq.length == x_values.length

        share_lengths = shares.map { |share| share.data.bytesize }.uniq
        raise Errors::InvalidSlip39ShareError, "all SLIP-0039 share values must have the same length" unless share_lengths.length == 1

        if (direct_hit = shares.find { |share| share.x == x_coordinate })
          return direct_hit.data
        end

        log_prod = shares.sum { |share| self.class.log_table[share.x ^ x_coordinate] }
        result = "\x00".b * share_lengths.first

        shares.each do |share|
          log_basis_eval = (
            log_prod -
            self.class.log_table[share.x ^ x_coordinate] -
            shares.sum { |other| other == share ? 0 : self.class.log_table[share.x ^ other.x] }
          ) % 255

          result = result.bytes.zip(share.data.bytes).map do |intermediate, share_byte|
            term =
              if share_byte.zero?
                0
              else
                self.class.exp_table[(self.class.log_table[share_byte] + log_basis_eval) % 255]
              end
            intermediate ^ term
          end.pack("C*")
        end

        result
      end

      def create_digest(random_data, shared_secret)
        OpenSSL::HMAC.digest("SHA256", random_data, shared_secret).byteslice(0, DIGEST_LENGTH_BYTES)
      end

      def decrypt(encrypted_master_secret, passphrase, iteration_exponent, identifier, extendable)
        raise Errors::InvalidSlip39ShareError, "SLIP-0039 master secret must have even byte length" if encrypted_master_secret.bytesize.odd?

        left = encrypted_master_secret.byteslice(0, encrypted_master_secret.bytesize / 2)
        right = encrypted_master_secret.byteslice(encrypted_master_secret.bytesize / 2, encrypted_master_secret.bytesize / 2)
        salt = slip39_salt(identifier, extendable)

        (ROUND_COUNT - 1).downto(0) do |round|
          feistel = OpenSSL::PKCS5.pbkdf2_hmac(
            [round].pack("C") + passphrase,
            salt + right,
            (BASE_ITERATION_COUNT << iteration_exponent) / ROUND_COUNT,
            left.bytesize,
            "sha256"
          )
          left, right = right, xor_bytes(left, feistel)
        end

        right + left
      end

      def slip39_salt(identifier, extendable)
        return "".b if extendable

        CUSTOMIZATION_STRING_ORIG + [identifier].pack("n")
      end

      def xor_bytes(left, right)
        left.bytes.zip(right.bytes).map { |a, b| a ^ b }.pack("C*")
      end

      def validate_passphrase!(passphrase)
        return if passphrase.bytes.all? { |byte| byte.between?(32, 126) }

        raise Errors::InvalidSlip39ShareError, "SLIP-0039 passphrase must contain only printable ASCII characters"
      end

      def verify_checksum(data, customization)
        polymod(customization.bytes + data) == 1
      end

      def polymod(values)
        generators = [
          0xE0E040,
          0x1C1C080,
          0x3838100,
          0x7070200,
          0xE0E0009,
          0x1C0C2412,
          0x38086C24,
          0x3090FC48,
          0x21B1F890,
          0x3F3F120
        ]
        checksum = 1

        values.each do |value|
          top = checksum >> 20
          checksum = ((checksum & 0xFFFFF) << 10) ^ value
          10.times do |index|
            checksum ^= generators[index] if ((top >> index) & 1) == 1
          end
        end

        checksum
      end

      def customization_string(extendable)
        extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG
      end

      def int_from_indices(indices)
        indices.reduce(0) { |value, index| (value * RADIX) + index }
      end

      def int_to_indices(value, length, radix_bits)
        mask = (1 << radix_bits) - 1
        (0...length).map do |offset|
          shift = (length - offset - 1) * radix_bits
          (value >> shift) & mask
        end
      end

      def bits_to_bytes(bit_count)
        (bit_count + 7) / 8
      end

      def bits_to_words(bit_count)
        (bit_count + RADIX_BITS - 1) / RADIX_BITS
      end
    end
  end
end
