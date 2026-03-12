# frozen_string_literal: true

require "securerandom"
require "openssl"

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Generates SLIP-0039 share mnemonics from a master secret.
      class Generator
        include Protocol

        def initialize(wordlist:, customization_string:, cipher:, random_bytes: SecureRandom.method(:random_bytes))
          @wordlist = wordlist
          @customization_string = customization_string
          @cipher = cipher
          @random_bytes = random_bytes
          @encoder = Encoder.new(wordlist: wordlist, customization_string: customization_string)
        end

        def generate(master_secret:, group_threshold:, groups:, passphrase:, extendable:, iteration_exponent:)
          validate_passphrase!(passphrase)
          validate_master_secret!(master_secret)
          validate_groups!(group_threshold, groups)

          identifier = random_identifier
          ciphertext = @cipher.encrypt(master_secret, passphrase.b, iteration_exponent, identifier, extendable)
          group_shares = split_secret(group_threshold, groups.length, ciphertext)

          structured_groups = groups.map.with_index do |group_config, group_index|
            member_threshold = group_config.fetch(:member_threshold)
            member_count = group_config.fetch(:member_count)
            member_shares = split_secret(member_threshold, member_count, group_shares.fetch(group_index).data)

            share_objects = member_shares.map.with_index do |share, member_index|
              Share.new(
                identifier: identifier,
                extendable: extendable,
                iteration_exponent: iteration_exponent,
                group_index: group_index,
                group_threshold: group_threshold,
                group_count: groups.length,
                index: member_index,
                member_threshold: member_threshold,
                value: share.data
              )
            end

            {
              member_threshold: member_threshold,
              member_count: member_count,
              shares: share_objects.map { |share| @encoder.mnemonic_for_share(share) }
            }
          end

          GeneratedSet.new(
            identifier: identifier,
            extendable: extendable,
            iteration_exponent: iteration_exponent,
            group_threshold: group_threshold,
            groups: groups,
            mnemonic_groups: structured_groups.map { |group| group.fetch(:shares) }
          )
        end

        private

        def validate_passphrase!(passphrase)
          return if passphrase.bytes.all? { |byte| byte.between?(32, 126) }

          raise Errors::InvalidSlip39ConfigurationError,
                "SLIP-0039 passphrase must contain only printable ASCII characters"
        end

        def validate_master_secret!(master_secret)
          unless Constants::SLIP39_SECRET_LENGTHS.include?(master_secret.bytesize)
            raise Errors::InvalidSlip39ConfigurationError,
                  "SLIP-0039 master secret must be #{Constants::SLIP39_SECRET_LENGTHS.inspect} bytes"
          end
        end

        def validate_groups!(group_threshold, groups)
          raise Errors::InvalidSlip39ConfigurationError, "SLIP-0039 groups must not be empty" if groups.empty?
          raise Errors::InvalidSlip39ConfigurationError, "SLIP-0039 group threshold must be positive" if group_threshold < 1
          if group_threshold > groups.length
            raise Errors::InvalidSlip39ConfigurationError,
                  "SLIP-0039 group threshold must not exceed the number of groups"
          end

          groups.each do |group|
            member_threshold = group.fetch(:member_threshold)
            member_count = group.fetch(:member_count)

            if member_threshold < 1
              raise Errors::InvalidSlip39ConfigurationError,
                    "SLIP-0039 member threshold must be positive"
            end

            if member_threshold > member_count
              raise Errors::InvalidSlip39ConfigurationError,
                    "SLIP-0039 member threshold must not exceed member count"
            end

            if member_count > MAX_SHARE_COUNT
              raise Errors::InvalidSlip39ConfigurationError,
                    "SLIP-0039 member count must not exceed #{MAX_SHARE_COUNT}"
            end

            if member_threshold == 1 && member_count > 1
              raise Errors::InvalidSlip39ConfigurationError,
                    "SLIP-0039 does not allow member threshold 1 with multiple shares"
            end
          end
        end

        def random_identifier
          identifier_bytes = @random_bytes.call(BitPacking.bits_to_bytes(ID_LENGTH_BITS))
          identifier_bytes.unpack1("H*").to_i(16) & ((1 << ID_LENGTH_BITS) - 1)
        end

        def split_secret(threshold, share_count, shared_secret)
          raise Errors::InvalidSlip39ConfigurationError, "SLIP-0039 threshold must be positive" if threshold < 1
          if threshold > share_count
            raise Errors::InvalidSlip39ConfigurationError,
                  "SLIP-0039 threshold must not exceed share count"
          end
          if share_count > MAX_SHARE_COUNT
            raise Errors::InvalidSlip39ConfigurationError,
                  "SLIP-0039 share count must not exceed #{MAX_SHARE_COUNT}"
          end

          return (0...share_count).map { |index| RawShare.new(x: index, data: shared_secret) } if threshold == 1

          random_share_count = threshold - 2
          shares = (0...random_share_count).map do |index|
            RawShare.new(x: index, data: @random_bytes.call(shared_secret.bytesize))
          end

          random_part = @random_bytes.call(shared_secret.bytesize - DIGEST_LENGTH_BYTES)
          digest = OpenSSL::HMAC.digest("SHA256", random_part, shared_secret).byteslice(0, DIGEST_LENGTH_BYTES)
          base_shares = shares + [
            RawShare.new(x: DIGEST_INDEX, data: digest + random_part),
            RawShare.new(x: SECRET_INDEX, data: shared_secret)
          ]

          (random_share_count...share_count).each do |index|
            shares << RawShare.new(x: index, data: Interpolation.interpolate(base_shares, index))
          end

          shares
        end
      end
    end
  end
end
