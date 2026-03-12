# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Protocol constants shared by the SLIP-0039 recovery helpers.
      #
      # These values are scoped to the SLIP-0039 implementation and should not
      # leak into unrelated recovery or derivation code.
      module Protocol
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
      end
    end
  end
end
