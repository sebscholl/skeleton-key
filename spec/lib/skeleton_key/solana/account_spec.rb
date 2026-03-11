# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Solana::Account do
  let(:seed_hex) { "13e3e43b779fc6cda3bd9a1e762768dd3e273389adb81787adbe880341609e88".ljust(128, "0") }
  let(:seed_bytes) { [seed_hex].pack("H*") }

  subject(:account) { described_class.new(seed: seed_bytes) }

  describe "#path" do
    it "uses the standard Solana account path prefix" do
      expect(account.path).to eq("m/44'/501'/0'")
    end
  end

  describe "#address" do
    it "derives the default Solana address at m/44'/501'/0'/0'" do
      derived = account.address

      aggregate_failures do
        expect(derived[:path]).to eq("m/44'/501'/0'/0'")
        expect(derived[:private_key].length).to eq(64)
        expect(derived[:public_key].length).to eq(64)
        expect(SkeletonKey::Codecs::Base58.decode(derived[:address]).unpack1("H*")).to eq(derived[:public_key])
      end
    end

    it "can derive deeper hardened children deterministically" do
      first = account.address(change: 0, index: 7)
      second = described_class.new(seed: seed_bytes).address(change: 0, index: 7)

      expect(first).to eq(second)
      expect(first[:path]).to eq("m/44'/501'/0'/0'/7'")
    end

    it "derives different addresses for different account branches" do
      other_account = described_class.new(seed: seed_bytes, account_index: 1)

      expect(account.address[:address]).not_to eq(other_account.address[:address])
    end
  end

  describe "#initialize" do
    it "raises a typed error for unsupported purposes" do
      expect do
        described_class.new(seed: seed_bytes, purpose: 32)
      end.to raise_error(SkeletonKey::Errors::UnsupportedPurposeError, /unsupported purpose: 32/)
    end
  end
end
