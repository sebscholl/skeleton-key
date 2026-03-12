# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # RS1024 checksum implementation for SLIP-0039 mnemonics.
      module Checksum
        GENERATORS = [
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
        ].freeze

        module_function

        def create(data, customization)
          values = customization.bytes + data + [0] * Protocol::CHECKSUM_LENGTH_WORDS
          checksum = polymod(values) ^ 1
          Protocol::CHECKSUM_LENGTH_WORDS.times.map do |offset|
            shift = 10 * (Protocol::CHECKSUM_LENGTH_WORDS - offset - 1)
            (checksum >> shift) & 1023
          end
        end

        def verify(data, customization)
          polymod(customization.bytes + data) == 1
        end

        def polymod(values)
          checksum = 1

          values.each do |value|
            top = checksum >> 20
            checksum = ((checksum & 0xFFFFF) << 10) ^ value
            10.times do |index|
              checksum ^= GENERATORS[index] if ((top >> index) & 1) == 1
            end
          end

          checksum
        end
      end
    end
  end
end
