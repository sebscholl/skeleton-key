module SkeletonKey
  module Derivation
    # Represents a BIP32/44-style derivation path.
    #
    # Internally, each index is stored as a 32-bit integer.
    # If the "hardened flag" (0x80000000) is set, the index is considered hardened.
    # Logical values (purpose, coin_type, etc.) mask off this flag using INDEX_MASK (0x7fffffff).
    #
    # Example:
    #   path = Path.new("m/44'/0'/0'/0/5")
    #   path.purpose        # => 44
    #   path.hardened?(0)   # => true
    #   path.parts[0]       # => 2147483692 (raw index with hardened bit set)
    #   path.to_s           # => "m/44'/0'/0'/0/5"
    #
    class Path
      # Set if an index is hardened (2^31)
      HARDENED_FLAG = 0x80000000

      # Mask for stripping hardened flag
      INDEX_MASK    = 0x7FFFFFFF

      # Order of components in the path
      ORDERED_KEYS  = %i[purpose coin_type account_index change address_index].freeze

      # The full path string (e.g. "m/44'/0'/0'/0/0")
      # @return [String]
      attr_reader :original_path

      # Encoded path components as integers (with hardened flag set if applicable)
      # @return [Array<Integer>]
      attr_reader :parts

      # @param path_str [String] BIP32 path string (e.g. "m/44'/0'/0'/0/0")
      def initialize(path_str)
        @original_path = path_str
        @parts = parse(path_str)

        # Parse and set individual components
        @purpose, @coin_type, @account_index, @change, @address_index = parts
      end

      # Determines if a component at the given index is hardened.
      #
      # @param index [Integer] index in the path array (0-based)
      # @return [Boolean] true if hardened
      # @raise [RuntimeError] if index is out of bounds
      def hardened?(idx)
        raise "Index out of bounds" if idx < 0 || idx >= parts.size

        (parts[idx] & HARDENED_FLAG) != 0
      end

      # Converts the internal representation back to a canonical string
      #
      # @return [String] e.g. "m/44'/0'/0'/0/0"
      def to_s
        parts.each_with_index.reduce('m') do |acc, (part, idx)|
          decoded = decode(part)
          "#{acc}/#{hardened?(idx) ? "#{decoded}'" : decoded}"
        end
      end

      ORDERED_KEYS.each do |attr|
        # Accessor that returns the index without the hardened flag
        #
        # @return [Integer] the index without hardened flag
        define_method(attr) do
          instance_variable_get("@#{attr}") & INDEX_MASK
        end
      end

      private

      # Parse a BIP32 path string into an array of indices
      # @param path_str [String] BIP32 path string (e.g. "m/44'/0'/0'/0/0")
      # @return [Array<Integer>] Array of indices
      def parse(path_str)
        raise "Invalid path format" unless path_str.start_with?("m/")

        path_str.split("/").drop(1).map { |part| encode_index(part) }
      end

      # Parses the path part and hardens it accordingly
      #
      # @param idx_str [String] index string (e.g. "44" or "0'")
      # @return [Integer] the encoded index
      def encode_index(idx_str)
        index = idx_str.to_i
        hardened = idx_str.end_with?("'")
        encode(index, hardened: hardened)
      end

      # Adds the hardened flag to an index if specified
      #
      # @param idx [Integer] the index
      # @param hardened [Boolean] whether to harden the index
      # @return [Integer] the encoded index
      def encode(idx, hardened: false)
        hardened ? idx | HARDENED_FLAG : idx
      end

      # Masks out the hardened flag from an encoded index
      #
      # @param raw_idx [Integer] the encoded index
      # @return [Integer] the index without hardened flag
      def decode(raw_idx)
        raw_idx & INDEX_MASK
      end
    end
  end
end
