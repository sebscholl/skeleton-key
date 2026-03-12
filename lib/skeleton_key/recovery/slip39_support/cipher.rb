# frozen_string_literal: true

require "openssl"

module SkeletonKey
  module Recovery
    module Slip39Support
      ##
      # Feistel cipher used to encrypt and decrypt SLIP-0039 master secrets.
      class Cipher
        include Protocol

        def initialize(customization_string_orig:)
          @customization_string_orig = customization_string_orig
        end

        # Encrypts a master secret into an encrypted master secret payload.
        #
        # @param master_secret [String] even-length byte string
        # @param passphrase [String] printable ASCII passphrase bytes
        # @param iteration_exponent [Integer]
        # @param identifier [Integer]
        # @param extendable [Boolean]
        # @return [String]
        def encrypt(master_secret, passphrase, iteration_exponent, identifier, extendable)
          raise Errors::InvalidSlip39ConfigurationError, "SLIP-0039 master secret must have even byte length" if master_secret.bytesize.odd?

          left = master_secret.byteslice(0, master_secret.bytesize / 2)
          right = master_secret.byteslice(master_secret.bytesize / 2, master_secret.bytesize / 2)
          salt = slip39_salt(identifier, extendable)

          ROUND_COUNT.times do |round|
            feistel = OpenSSL::PKCS5.pbkdf2_hmac(
              [round].pack("C") + passphrase,
              salt + right,
              (BASE_ITERATION_COUNT << iteration_exponent) / ROUND_COUNT,
              left.bytesize,
              "sha256"
            )
            left, right = right, BitPacking.xor_bytes(left, feistel)
          end

          right + left
        end

        # Decrypts an encrypted master secret into the original master secret.
        #
        # @param encrypted_master_secret [String] even-length byte string
        # @return [String]
        def decrypt(encrypted_master_secret, passphrase, iteration_exponent, identifier, extendable)
          raise Errors::InvalidSlip39ShareError, "SLIP-0039 master secret must have even byte length" if encrypted_master_secret.bytesize.odd?

          left = encrypted_master_secret.byteslice(0, encrypted_master_secret.bytesize / 2)
          right = encrypted_master_secret.byteslice(encrypted_master_secret.bytesize / 2, encrypted_master_secret.bytesize / 2)
          salt = slip39_salt(identifier, extendable)

          (ROUND_COUNT - 1).downto(0) do |round|
            feistel = OpenSSL::PKCS5.pbkdf2_hmac(
              [round].pack("C") + passphrase,
              salt + right,
              (BASE_ITERATION_COUNT << iteration_exponent) / ROUND_COUNT,
              left.bytesize,
              "sha256"
            )
            left, right = right, BitPacking.xor_bytes(left, feistel)
          end

          right + left
        end

        private

        def slip39_salt(identifier, extendable)
          return "".b if extendable

          @customization_string_orig + [identifier].pack("n")
        end
      end
    end
  end
end
