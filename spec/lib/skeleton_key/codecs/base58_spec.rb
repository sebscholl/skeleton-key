# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Codecs::Base58 do
  let(:decode_vectors) { load_fixture("codecs/base58check_decode_golden_master") }
  let(:invalid_vectors) { load_fixture("codecs/invalid_strings_golden_master") }

  describe ".encode" do
    it "matches raw base58 encoding for the base58check vectors" do
      decode_vectors["valid_cases"].each do |entry|
        bytes = [entry["decoded_hex"]].pack("H*")
        expect(described_class.encode(bytes)).to eq(entry["encoded"]), entry["label"]
      end
    end
  end

  describe ".decode" do
    it "matches raw base58 decoding for the base58check vectors" do
      decode_vectors["valid_cases"].each do |entry|
        expect(described_class.decode(entry["encoded"]).unpack1("H*")).to eq(entry["decoded_hex"]), entry["label"]
      end
    end

    it "rejects malformed base58 strings" do
      invalid_vectors["base58check"]["malformed_cases"].each do |entry|
        expect do
          described_class.decode(entry["encoded"])
        end.to raise_error(SkeletonKey::Errors::InvalidBase58Error), entry["label"]
      end
    end
  end
end
