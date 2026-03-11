# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Seed do
  let(:fixture_rows) { JSON.load_file(SkeletonKey::ROOT + "/spec/fixtures/recovery/bip39_golden_master.json").fetch("list") }

  describe ".import" do
    it "imports a mnemonic string as a standard BIP39 seed" do
      row = fixture_rows.first

      seed = described_class.import(row.fetch("bip39_mnemonic"))

      expect(seed.hex).to eq(row.fetch("bip39_seed"))
    end

    it "imports a Mnemonic object as a standard BIP39 seed" do
      row = fixture_rows[1]
      mnemonic = SkeletonKey::Recovery::Bip39.new(row.fetch("bip39_mnemonic"))

      seed = described_class.import(mnemonic)

      expect(seed.hex).to eq(row.fetch("bip39_seed"))
    end
  end
end
