# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Derivation::SLIP10 do
  let(:seed) { "\x11".b * 32 }
  let(:key) do
    OpenSSL::PKey.read([described_class::ED25519_PKCS8_PREFIX + seed.unpack1("H*")].pack("H*"))
  end

  describe ".raw_private_key" do
    it "extracts the seed from PKCS#8 DER when raw accessors are unavailable" do
      der_only_key = Struct.new(:private_to_der, :public_to_der).new(key.private_to_der, key.public_to_der)

      expect(described_class.raw_private_key(der_only_key)).to eq(seed)
    end
  end

  describe ".raw_public_key" do
    it "extracts the Ed25519 public key from SPKI DER when raw accessors are unavailable" do
      der_only_key = Struct.new(:private_to_der, :public_to_der).new(key.private_to_der, key.public_to_der)
      expected_public_key = key.public_to_der.byteslice(-described_class::ED25519_SPKI_PUBLIC_KEY_SIZE, described_class::ED25519_SPKI_PUBLIC_KEY_SIZE)

      expect(described_class.raw_public_key(der_only_key)).to eq(expected_public_key)
    end
  end
end
