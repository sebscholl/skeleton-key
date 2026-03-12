# frozen_string_literal: true

require "set"

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Decodes flat SLIP-0039 share strings into validated grouped share objects.
      class Decoder
        include Protocol

        def initialize(word_index:, customization_string:)
          @word_index = word_index
          @customization_string = customization_string
        end

        def decode(mnemonics)
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

        private

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

          id_exp_int = BitPacking.int_from_indices(indices.first(ID_EXP_LENGTH_WORDS), RADIX)
          identifier = id_exp_int >> (EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS)
          extendable = ((id_exp_int >> ITERATION_EXP_LENGTH_BITS) & 1) == 1
          iteration_exponent = id_exp_int & ((1 << ITERATION_EXP_LENGTH_BITS) - 1)

          unless Checksum.verify(indices, @customization_string.call(extendable))
            raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 checksum"
          end

          share_params_int = BitPacking.int_from_indices(indices[ID_EXP_LENGTH_WORDS, 2], RADIX)
          group_index, group_threshold_minus_one, group_count_minus_one, index, member_threshold_minus_one =
            BitPacking.int_to_indices(share_params_int, 5, 4)

          if group_count_minus_one < group_threshold_minus_one
            raise Errors::InvalidSlip39ShareError, "SLIP-0039 group threshold cannot exceed group count"
          end

          value_indices = indices[(ID_EXP_LENGTH_WORDS + 2)...-CHECKSUM_LENGTH_WORDS]
          value_byte_count = BitPacking.bits_to_bytes(RADIX_BITS * value_indices.length - padding_length)
          value_int = BitPacking.int_from_indices(value_indices, RADIX)
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
            @word_index.fetch(word.downcase)
          rescue KeyError
            raise Errors::InvalidSlip39ShareError, "invalid SLIP-0039 mnemonic word: #{word}"
          end
        end
      end
    end
  end
end
