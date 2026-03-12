# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Return object for generated SLIP-0039 shares.
      class GeneratedSet
        attr_reader :identifier, :extendable, :iteration_exponent, :group_threshold, :groups, :mnemonic_groups

        def initialize(identifier:, extendable:, iteration_exponent:, group_threshold:, groups:, mnemonic_groups:)
          @identifier = identifier
          @extendable = extendable
          @iteration_exponent = iteration_exponent
          @group_threshold = group_threshold
          @groups = groups
          @mnemonic_groups = mnemonic_groups
        end

        # Returns every generated share in a single flat array.
        #
        # @return [Array<String>]
        def all_shares
          mnemonic_groups.flatten
        end

        # Returns a simple threshold-satisfying recovery subset by taking the
        # first required members from the first required groups.
        #
        # @return [Array<String>]
        def recovery_set
          mnemonic_groups.first(group_threshold).each_with_index.flat_map do |shares, index|
            shares.first(groups.fetch(index).fetch(:member_threshold))
          end
        end
      end
    end
  end
end
