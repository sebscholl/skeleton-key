# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Chains::Solana::Account do
  let(:seed_hex) { "13e3e43b779fc6cda3bd9a1e762768dd3e273389adb81787adbe880341609e88".ljust(128, "0") }
  let(:seed_bytes) { [seed_hex].pack("H*") }

  subject(:account) { described_class.new(seed: seed_bytes) }

  describe "#path" do
    it "uses the standard Solana account path prefix" do
      expect(account.path).to eq("m/44'/501'/0'")
    end

    it "returns nil in Solana CLI no-path mode" do
      no_path_account = described_class.new(seed: seed_bytes, derivation_path: nil)

      expect(no_path_account.path).to be_nil
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

    it "matches the no-path Solana CLI mode when derivation_path is nil" do
      derived = described_class.new(seed: seed_bytes, derivation_path: nil).address

      aggregate_failures do
        expect(derived[:path]).to be_nil
        expect(derived[:private_key]).to eq(seed_hex[0, 64])
        expect(derived[:public_key]).to eq("40b2fd1cd81946fa2dcd08f7e3855cbc0ecfcd2448c4e9a4729c3f66018fdd6a")
        expect(derived[:address]).to eq("5MZPgxin4yK3ggjMhHaymF3SC16jD7iBPYpU9yTtszhP")
        expect(derived[:chain_code]).to be_nil
      end
    end

    it "rejects child derivation in Solana CLI no-path mode" do
      no_path_account = described_class.new(seed: seed_bytes, derivation_path: nil)

      expect do
        no_path_account.address(change: 0)
      end.to raise_error(SkeletonKey::Errors::InvalidPathFormatError, /does not support child derivation/)
    end
  end

  describe "#initialize" do
    it "raises a typed error for unsupported purposes" do
      expect do
        described_class.new(seed: seed_bytes, purpose: 32)
      end.to raise_error(SkeletonKey::Errors::UnsupportedPurposeError, /unsupported purpose: 32/)
    end

    it "raises a typed error when no-path mode is used with account overrides" do
      expect do
        described_class.new(seed: seed_bytes, account_index: 1, derivation_path: nil)
      end.to raise_error(SkeletonKey::Errors::InvalidPathFormatError, /incompatible with purpose, coin_type, or account_index/)
    end

    it "raises a typed error when no-path mode is requested for a short seed" do
      expect do
        described_class.new(seed: "\x01".b * 16, derivation_path: nil)
      end.to raise_error(SkeletonKey::Errors::InvalidSeedError, /requires at least 32 seed bytes/)
    end
  end
end
