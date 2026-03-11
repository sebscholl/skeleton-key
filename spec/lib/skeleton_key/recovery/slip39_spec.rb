# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Recovery::Slip39 do
  let(:vectors) { JSON.load_file(SkeletonKey::ROOT + "/spec/fixtures/recovery/slip39_golden_master.json").fetch("vectors") }

  describe ".recover" do
    it "recovers the expected master secret from each external SLIP-0039 recovery set" do
      vectors.each do |vector|
        recovered = described_class.recover(vector.fetch("recovery_set"), passphrase: vector.fetch("passphrase"))

        expect(recovered.hex).to eq(vector.fetch("master_secret"))
      end
    end

    it "does not recover when provided fewer than the required member threshold" do
      vectors.each do |vector|
        insufficient_set = vector.fetch("recovery_set")[0, vector.fetch("member_threshold") - 1]

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
end
