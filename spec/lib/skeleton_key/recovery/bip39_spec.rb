# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Recovery::Bip39 do
  let(:fixture_rows) { load_fixture("recovery/bip39_golden_master").fetch("list") }
  let(:generation_fixture) { load_fixture("recovery/bip39_generation_golden_master") }
  let(:generation_rows) { generation_fixture.fetch("vectors") }

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

  describe ".generate" do
    it "covers three password and three non-password vectors for each supported mnemonic length" do
      grouped_rows = generation_rows.group_by { |row| row.fetch("word_count") }

      SkeletonKey::Constants::MNEMONIC_WORD_COUNTS.each do |word_count|
        rows = grouped_rows.fetch(word_count)
        without_passphrase, with_passphrase = rows.partition { |row| row.fetch("passphrase").empty? }

        expect(without_passphrase.length).to be >= 3
        expect(with_passphrase.length).to be >= 3
      end
    end

    it "generates mnemonics at each supported BIP39 length" do
      SkeletonKey::Constants::MNEMONIC_WORD_COUNTS.each do |word_count|
        mnemonic = described_class.generate(word_count: word_count)

        expect(mnemonic).to be_a(described_class)
        expect(mnemonic.words.length).to eq(word_count)
      end
    end

    it "matches the external generation vectors for explicit entropy" do
      generation_rows.each do |row|
        entropy = [row.fetch("entropy")].pack("H*")
        mnemonic = described_class.generate(word_count: row.fetch("word_count"), entropy: entropy)

        expect(mnemonic.phrase).to eq(row.fetch("mnemonic"))
        expect(mnemonic.seed(passphrase: row.fetch("passphrase")).hex).to eq(row.fetch("seed"))
      end
    end

    it "round-trips deterministic entropy across every supported entropy length" do
      SkeletonKey::Constants::ENTROPY_LENGTHS.each do |byte_length|
        entropy = (0...byte_length).to_a.pack("C*")

        mnemonic = described_class.from_entropy(entropy)

        expect(mnemonic.words.length).to eq((byte_length * 8 * 33) / (32 * 11))
        expect(described_class.new(mnemonic.phrase).phrase).to eq(mnemonic.phrase)
      end
    end

    it "matches the external generation vectors when converting entropy directly" do
      generation_rows.each do |row|
        mnemonic = described_class.from_entropy(row.fetch("entropy"))

        expect(mnemonic.words.length).to eq(row.fetch("word_count"))
        expect(mnemonic.phrase).to eq(row.fetch("mnemonic"))
        expect(mnemonic.seed(passphrase: row.fetch("passphrase")).hex).to eq(row.fetch("seed"))
      end
    end

    it "raises a typed error for unsupported BIP39 word counts" do
      expect do
        described_class.generate(word_count: 14)
      end.to raise_error(SkeletonKey::Errors::InvalidMnemonicConfigurationError)
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

    it "recreates the external generation-vector seeds with the fixture passphrase" do
      generation_rows.each do |row|
        mnemonic = described_class.new(row.fetch("mnemonic"))

        expect(mnemonic.seed(passphrase: row.fetch("passphrase")).hex).to eq(row.fetch("seed"))
      end
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
