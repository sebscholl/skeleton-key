# frozen_string_literal: true

require "openssl"

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Reconstructs SLIP-0039 group fragments and encrypted master secrets.
      class SecretRecovery
        include Protocol

        def recover_encrypted_master_secret(groups)
          raise Errors::InvalidSlip39ShareError, "the set of SLIP-0039 shares is empty" if groups.empty?

          params = groups.values.first.first
          if groups.length < params.group_threshold
            raise Errors::InvalidSlip39ShareError,
                  "insufficient number of mnemonic groups: requires #{params.group_threshold}"
          end

          if groups.length != params.group_threshold
            raise Errors::InvalidSlip39ShareError,
                  "wrong number of mnemonic groups: expected #{params.group_threshold}, got #{groups.length}"
          end

          group_shares = groups.map do |group_index, shares|
            if shares.length != shares.first.member_threshold
              raise Errors::InvalidSlip39ShareError,
                    "wrong number of mnemonics for group #{group_index}: expected #{shares.first.member_threshold}, got #{shares.length}"
            end

            RawShare.new(
              x: group_index,
              data: recover_secret(
                shares.first.member_threshold,
                shares.map { |share| RawShare.new(x: share.index, data: share.value) }
              )
            )
          end

          ciphertext = recover_secret(params.group_threshold, group_shares)
          {
            identifier: params.identifier,
            extendable: params.extendable,
            iteration_exponent: params.iteration_exponent,
            ciphertext: ciphertext
          }
        end

        private

        def recover_secret(threshold, shares)
          return shares.first.data if threshold == 1

          shared_secret = Interpolation.interpolate(shares, SECRET_INDEX)
          digest_share = Interpolation.interpolate(shares, DIGEST_INDEX)
          digest = digest_share.byteslice(0, DIGEST_LENGTH_BYTES)
          random_part = digest_share.byteslice(DIGEST_LENGTH_BYTES, digest_share.bytesize - DIGEST_LENGTH_BYTES)

          unless digest == create_digest(random_part, shared_secret)
            raise Errors::InvalidSlip39ShareError, "invalid digest of the shared secret"
          end

          shared_secret
        end

        def create_digest(random_data, shared_secret)
          OpenSSL::HMAC.digest("SHA256", random_data, shared_secret).byteslice(0, DIGEST_LENGTH_BYTES)
        end
      end
    end
  end
end
