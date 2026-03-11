# frozen_string_literal: true

require "skeleton_key/derivation/path"

RSpec.describe SkeletonKey::Derivation::Path do
  let(:path_str) { "m/44'/0'/0'/1/5" }

  subject(:path) { described_class.new(path_str) }

  describe "#initialize" do
    it "parses the path string" do
      expect(path.parts.size).to eq(5)
      expect(path.original_path).to eq(path_str)
    end
  end

  describe "#parts" do
    it "encodes hardened components with HARDENED_FLAG" do
      expect(path.parts[0]).to eq(44 | described_class::HARDENED_FLAG) # 44'
      expect(path.parts[1]).to eq(0  | described_class::HARDENED_FLAG) # 0'
      expect(path.parts[2]).to eq(0  | described_class::HARDENED_FLAG) # 0'
      expect(path.parts[3]).to eq(1)                                   # change
      expect(path.parts[4]).to eq(5)                                   # address
    end
  end

  describe "#purpose / #coin_type / #account_index / #change / #address_index" do
    it "returns the logical index values (masking hardened flag)" do
      expect(path.purpose).to eq(44)
      expect(path.coin_type).to eq(0)
      expect(path.account_index).to eq(0)
      expect(path.change).to eq(1)
      expect(path.address_index).to eq(5)
    end
  end

  describe "#hardened?" do
    it "detects hardened indices correctly" do
      expect(path.hardened?(0)).to be true   # 44'
      expect(path.hardened?(1)).to be true   # 0'
      expect(path.hardened?(2)).to be true   # 0'
      expect(path.hardened?(3)).to be false  # 1
      expect(path.hardened?(4)).to be false  # 5
    end

    it "raises on out-of-bounds index" do
      expect { path.hardened?(10) }.to raise_error(SkeletonKey::Errors::IndexOutOfBoundsError, /index out of bounds/i)
    end
  end

  describe "#to_s" do
    it "round-trips back to the original string" do
      original = "m/44'/0'/0'/1/5"
      path = described_class.new(original)
      expect(path.to_s).to eq(original)
    end

    it "handles non-hardened only paths" do
      original = "m/0/1/2/3/4"
      path = described_class.new(original)
      expect(path.to_s).to eq(original)
      expect(path.parts.all? { |i| (i & described_class::HARDENED_FLAG).zero? }).to be true
    end

    it "handles hardened-only paths" do
      original = "m/1'/2'/3'"
      path = described_class.new(original)
      expect(path.to_s).to eq(original)
      expect(path.parts.all? { |i| (i & described_class::HARDENED_FLAG) != 0 }).to be true
    end
  end

  describe "invalid path strings" do
    it "raises if missing m/" do
      expect { described_class.new("44'/0'/0'") }.to raise_error(SkeletonKey::Errors::InvalidPathFormatError, /invalid path format/i)
    end
  end
end
