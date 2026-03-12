# frozen_string_literal: true

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # GF(256) interpolation used to reconstruct SLIP-0039 secrets.
      module Interpolation
        module_function

        def exp_table
          @exp_table ||= begin
            exp = Array.new(255, 0)
            log = Array.new(256, 0)
            poly = 1

            255.times do |i|
              exp[i] = poly
              log[poly] = i
              poly = (poly << 1) ^ poly
              poly ^= 0x11B if (poly & 0x100) != 0
            end

            @log_table = log.freeze
            exp.freeze
          end
        end

        def log_table
          exp_table
          @log_table
        end

        def interpolate(shares, x_coordinate)
          x_values = shares.map(&:x)
          raise Errors::InvalidSlip39ShareError, "SLIP-0039 share indices must be unique" unless x_values.uniq.length == x_values.length

          share_lengths = shares.map { |share| share.data.bytesize }.uniq
          raise Errors::InvalidSlip39ShareError, "all SLIP-0039 share values must have the same length" unless share_lengths.length == 1

          if (direct_hit = shares.find { |share| share.x == x_coordinate })
            return direct_hit.data
          end

          log_prod = shares.sum { |share| log_table[share.x ^ x_coordinate] }
          result = "\x00".b * share_lengths.first

          shares.each do |share|
            log_basis_eval = (
              log_prod -
              log_table[share.x ^ x_coordinate] -
              shares.sum { |other| other == share ? 0 : log_table[share.x ^ other.x] }
            ) % 255

            result = result.bytes.zip(share.data.bytes).map do |intermediate, share_byte|
              term =
                if share_byte.zero?
                  0
                else
                  exp_table[(log_table[share_byte] + log_basis_eval) % 255]
                end
              intermediate ^ term
            end.pack("C*")
          end

          result
        end
      end
    end
  end
end
