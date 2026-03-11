# frozen_string_literal: true

module SkeletonKey
  module Solana
    module Support
      extend Utils::Encoding

      module_function

      def to_address(public_key_bytes)
        Codecs::Base58.encode(public_key_bytes)
      end
    end
  end
end
