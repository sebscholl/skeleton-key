# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      # Minimal `(x, data)` tuple used during interpolation.
      RawShare = Struct.new(:x, :data, keyword_init: true)

      ##
      # Parsed SLIP-0039 share metadata and value payload.
      #
      # Each share is self-describing. Recovery groups are reconstructed from
      # these fields rather than from caller-supplied nested input.
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
        # Parameters that must match across every share in a recovery set.
        #
        # @return [Array<Integer, Boolean>]
        def common_parameters
          [identifier, extendable, iteration_exponent, group_threshold, group_count]
        end

        # Parameters that must match within a single mnemonic group.
        #
        # @return [Array<Integer, Boolean>]
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
    end
  end
end
