# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Codecs::Bech32 do
  let(:encode_vectors) { load_fixture("codecs/bech32_encode_golden_master") }
  let(:decode_vectors) { load_fixture("codecs/bech32_decode_golden_master") }
  let(:convert_bits_vectors) { load_fixture("codecs/convert_bits_golden_master") }
  let(:invalid_vectors) { load_fixture("codecs/invalid_strings_golden_master") }

  describe ".encode" do
    it "matches the golden encode vectors" do
      encode_vectors["cases"].each do |entry|
        expect(
          described_class.encode(
            entry["hrp"],
            entry["data"],
            described_class::Encoding.const_get(entry["encoding"].upcase)
          )
        ).to eq(entry["encoded"]), entry["label"]
      end
    end
  end

  describe ".decode" do
    it "matches the golden decode vectors" do
      decode_vectors["valid_cases"].each do |entry|
        hrp, data, encoding = described_class.decode(entry["encoded"])

        aggregate_failures(entry["label"]) do
          expect(hrp).to eq(entry["decoded_hrp"])
          expect(data).to eq(entry["decoded_data"])
          expect(encoding).to eq(described_class::Encoding.const_get(entry["decoded_spec"].upcase))
        end
      end
    end

    it "rejects invalid bech32 strings" do
      invalid_vectors["bech32"].each do |entry|
        expect do
          described_class.decode(entry["encoded"])
        end.to raise_error(SkeletonKey::Errors::InvalidBech32Error), entry["label"]
      end
    end
  end

  describe ".convert_bits" do
    it "matches the valid convert_bits vectors" do
      convert_bits_vectors["valid_cases"].each do |entry|
        expect(
          described_class.convert_bits(
            entry["input"],
            entry["from_bits"],
            entry["to_bits"],
            entry["pad"]
          )
        ).to eq(entry["output"]), entry["label"]
      end
    end

    it "rejects invalid convert_bits vectors" do
      convert_bits_vectors["invalid_cases"].each do |entry|
        expect do
          described_class.convert_bits(
            entry["input"],
            entry["from_bits"],
            entry["to_bits"],
            entry["pad"]
          )
        end.to raise_error(SkeletonKey::Errors::InvalidConvertBitsError), entry["label"]
      end
    end
  end
end
