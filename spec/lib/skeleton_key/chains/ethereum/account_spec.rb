# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Chains::Ethereum::Account do
  describe "#initialize" do
    it "raises a typed error for unsupported purposes" do
      expect do
        described_class.new(seed: ("\x01" * 64).b, purpose: 49)
      end.to raise_error(SkeletonKey::Errors::UnsupportedPurposeError, /unsupported purpose: 49/)
    end
  end
end
