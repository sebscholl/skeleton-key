# frozen_string_literal: true

require "spec_helper"
require "digest"

RSpec.describe SkeletonKey::Recovery::Slip39 do
  let(:vectors) { load_fixture("recovery/slip39_golden_master").fetch("vectors") }

  def deterministic_random(seed)
    counter = 0

    lambda do |length|
      output = +"".b
      while output.bytesize < length
        counter_bytes = [counter >> 32, counter & 0xFFFF_FFFF].pack("N2")
        output << Digest::SHA256.digest(seed.b + counter_bytes)
        counter += 1
      end
      output.byteslice(0, length)
    end
  end

  describe ".recover" do
    it "recovers the expected master secret from each external SLIP-0039 recovery set" do
      vectors.each do |vector|
        recovered = described_class.recover(vector.fetch("recovery_set"), passphrase: vector.fetch("passphrase"))

        expect(recovered.hex).to eq(vector.fetch("master_secret"))
      end
    end

    it "does not recover when provided fewer than the required member threshold" do
      vectors.each do |vector|
        insufficient_set = vector.fetch("insufficient_recovery_set")

        expect do
          described_class.recover(insufficient_set, passphrase: vector.fetch("passphrase"))
        end.to raise_error(SkeletonKey::Errors::InvalidSlip39ShareError)
      end
    end

    it "rejects shares with words outside the SLIP-0039 wordlist" do
      share = vectors.first.fetch("recovery_set").first.sub(/\A\S+/, "notaword")

      expect do
        described_class.recover([share] + vectors.first.fetch("recovery_set")[1..], passphrase: vectors.first.fetch("passphrase"))
      end.to raise_error(SkeletonKey::Errors::InvalidSlip39ShareError)
    end

    it "rejects shares with an invalid checksum" do
      words = vectors.first.fetch("recovery_set").first.split(" ")
      replacement = described_class.wordlist.find do |candidate|
        next false if candidate == words.last

        mutated = words[0...-1] + [candidate]
        begin
          described_class.recover([mutated.join(" ")] + vectors.first.fetch("recovery_set")[1..], passphrase: vectors.first.fetch("passphrase"))
          false
        rescue SkeletonKey::Errors::InvalidSlip39ShareError
          true
        end
      end

      expect(replacement).not_to be_nil
      words[-1] = replacement

      expect do
        described_class.recover([words.join(" ")] + vectors.first.fetch("recovery_set")[1..], passphrase: vectors.first.fetch("passphrase"))
      end.to raise_error(SkeletonKey::Errors::InvalidSlip39ShareError)
    end
  end

  describe ".generate" do
    it "matches the external single-group and multi-group generation vectors" do
      vectors.each do |vector|
        generated = described_class.generate(
          master_secret: vector.fetch("master_secret"),
          groups: vector.fetch("groups").map { |group| group.transform_keys(&:to_sym) },
          group_threshold: vector.fetch("group_threshold"),
          passphrase: vector.fetch("passphrase"),
          extendable: vector.fetch("extendable"),
          iteration_exponent: vector.fetch("iteration_exponent"),
          random_bytes: deterministic_random(vector.fetch("random_seed"))
        )

        expect(generated.mnemonic_groups).to eq(vector.fetch("mnemonic_groups"))
        expect(generated.recovery_set).to eq(vector.fetch("recovery_set"))
      end
    end

    it "supports the simple single-group DX for threshold-based generation" do
      generated = described_class.generate(
        master_secret: "00" * 16,
        member_threshold: 2,
        member_count: 3,
        random_bytes: deterministic_random("simple-single-group")
      )

      expect(generated.groups).to eq([{ member_threshold: 2, member_count: 3 }])
      expect(generated.mnemonic_groups.length).to eq(1)
      expect(generated.mnemonic_groups.first.length).to eq(3)
      expect(described_class.recover(generated.recovery_set).bytes.bytesize).to eq(16)
    end

    it "raises a typed error for invalid generation parameters" do
      expect do
        described_class.generate(master_secret: "00" * 16, member_threshold: 1, member_count: 3)
      end.to raise_error(SkeletonKey::Errors::InvalidSlip39ConfigurationError)
    end
  end
end
