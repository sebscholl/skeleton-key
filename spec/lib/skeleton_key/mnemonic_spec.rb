# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Mnemonic do
  let(:fixture_rows) { JSON.load_file(SkeletonKey::ROOT + "/spec/fixtures/mnemonics.json").fetch("list") }

  describe ".import" do
    it "imports a mnemonic string" do
      phrase = fixture_rows.first.fetch("bip39_mnemonic")

      mnemonic = described_class.import(phrase)

      expect(mnemonic.phrase).to eq(phrase)
    end

    it "raises a typed error for unsupported mnemonic input" do
      expect { described_class.import(%w[not a string]) }.to raise_error(SkeletonKey::Errors::InvalidMnemonicError)
    end
  end

  describe "#seed" do
    it "recreates the expected BIP39 seed for each fixture mnemonic" do
      fixture_rows.each do |row|
        mnemonic = described_class.new(row.fetch("bip39_mnemonic"))

        expect(mnemonic.seed.hex).to eq(row.fetch("bip39_seed"))
      end
    end

    it "normalizes repeated whitespace before deriving the seed" do
      phrase = fixture_rows.first.fetch("bip39_mnemonic").split(" ").join("  ")

      expect(described_class.new(phrase).seed.hex).to eq(fixture_rows.first.fetch("bip39_seed"))
    end
  end

  describe "#initialize" do
    it "raises a typed error for an unsupported word count" do
      expect { described_class.new("one two three four") }.to raise_error(SkeletonKey::Errors::InvalidMnemonicError)
    end

    it "raises a typed error for a mnemonic with words outside the BIP39 wordlist" do
      phrase = fixture_rows.first.fetch("bip39_mnemonic").sub(/\A\S+/, "notaword")

      expect { described_class.new(phrase) }.to raise_error(SkeletonKey::Errors::InvalidMnemonicError)
    end

    it "raises a typed error for a mnemonic with an invalid checksum" do
      words = fixture_rows.first.fetch("bip39_mnemonic").split(" ")
      replacement = described_class.wordlist.find do |candidate|
        next false if candidate == words.last

        mutated = words[0...-1] + [candidate]
        begin
          described_class.new(mutated.join(" "))
          false
        rescue SkeletonKey::Errors::InvalidMnemonicError
          true
        end
      end

      expect(replacement).not_to be_nil
      words[-1] = replacement

      expect { described_class.new(words.join(" ")) }.to raise_error(SkeletonKey::Errors::InvalidMnemonicError)
    end
  end
end
