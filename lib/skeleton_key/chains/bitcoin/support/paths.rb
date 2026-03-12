# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Bitcoin
      module Support
        module Paths
          module_function

          def build_derived_path(change:, index:, hardened_change:, hardened_index:)
            rendered_change = hardened_change ? "#{change}'" : change.to_s
            rendered_index = hardened_index ? "#{index}'" : index.to_s

            if legacy_root_branch?
              "m/#{rendered_change}/#{rendered_index}"
            else
              "m/#{purpose}'/#{coin_type}'/#{account_index}'/#{rendered_change}/#{rendered_index}"
            end
          end

          def branch_derived_path(change:, hardened_change:)
            rendered_change = hardened_change ? "#{change}'" : change.to_s

            if legacy_root_branch?
              "m/#{rendered_change}"
            else
              "m/#{purpose}'/#{coin_type}'/#{account_index}'/#{rendered_change}"
            end
          end
        end
      end
    end
  end
end
