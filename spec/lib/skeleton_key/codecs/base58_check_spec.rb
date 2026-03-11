# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Codecs::Base58Check do
  let(:encode_vectors) { load_fixture("codecs/base58check_encode_golden_master") }
  let(:decode_vectors) { load_fixture("codecs/base58check_decode_golden_master") }
  let(:invalid_vectors) { load_fixture("codecs/invalid_strings_golden_master") }

  describe ".encode" do
    it "matches the golden encode vectors" do
      encode_vectors["cases"].each do |entry|
        payload = [entry["payload_hex"]].pack("H*")
        expect(described_class.encode(payload)).to eq(entry["encoded"]), entry["label"]
      end
    end
  end

  describe ".decode" do
    it "matches the golden decode vectors" do
      decode_vectors["valid_cases"].each do |entry|
        expect(described_class.decode(entry["encoded"]).unpack1("H*")).to eq(entry["payload_hex"]), entry["label"]
      end
    end

    it "rejects malformed base58 strings" do
      invalid_vectors["base58check"]["malformed_cases"].each do |entry|
        expect do
          described_class.decode(entry["encoded"])
        end.to raise_error(SkeletonKey::Errors::InvalidBase58Error), entry["label"]
      end
    end

    it "rejects checksum-invalid base58check strings" do
      invalid_vectors["base58check"]["checksum_failure_cases"].each do |entry|
        expect do
          described_class.decode(entry["encoded"])
        end.to raise_error(SkeletonKey::Errors::InvalidChecksumError), entry["label"]
      end
    end
  end
end
