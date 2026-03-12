# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Integer and byte packing helpers used by SLIP-0039 parsing and recovery.
      module BitPacking
        module_function

        def int_from_indices(indices, radix)
          indices.reduce(0) { |value, index| (value * radix) + index }
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

        def bits_to_words(bit_count, radix_bits)
          (bit_count + radix_bits - 1) / radix_bits
        end

        def xor_bytes(left, right)
          left.bytes.zip(right.bytes).map { |a, b| a ^ b }.pack("C*")
        end
      end
    end
  end
end
