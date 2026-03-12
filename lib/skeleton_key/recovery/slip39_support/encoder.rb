# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Encodes structured SLIP-0039 shares back into mnemonic word strings.
      class Encoder
        include Protocol

        def initialize(wordlist:, customization_string:)
          @wordlist = wordlist
          @customization_string = customization_string
        end

        def mnemonic_for_share(share)
          share_data = encode_id_exp(share) + encode_share_params(share) + encode_value(share.value)
          checksum = Checksum.create(share_data, @customization_string.call(share.extendable))
          (share_data + checksum).map { |index| @wordlist.fetch(index) }.join(" ")
        end

        private

        def encode_id_exp(share)
          id_exp_int = share.identifier << (ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS)
          id_exp_int += (share.extendable ? 1 : 0) << ITERATION_EXP_LENGTH_BITS
          id_exp_int += share.iteration_exponent
          BitPacking.int_to_indices(id_exp_int, ID_EXP_LENGTH_WORDS, RADIX_BITS)
        end

        def encode_share_params(share)
          value = share.group_index
          value = (value << 4) + (share.group_threshold - 1)
          value = (value << 4) + (share.group_count - 1)
          value = (value << 4) + share.index
          value = (value << 4) + (share.member_threshold - 1)
          BitPacking.int_to_indices(value, 2, 10)
        end

        def encode_value(bytes)
          word_count = BitPacking.bits_to_words(bytes.bytesize * 8, RADIX_BITS)
          value_int = bytes.unpack1("H*").to_i(16)
          BitPacking.int_to_indices(value_int, word_count, RADIX_BITS)
        end
      end
    end
  end
end
