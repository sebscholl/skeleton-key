# frozen_string_literal: true

require "spec_helper"

RSpec.describe SkeletonKey::Bitcoin::Account do
  describe "#initialize" do
    it "raises a typed error for unsupported purposes" do
      expect do
        described_class.new(seed: ("\x01" * 64).b, purpose: 60)
      end.to raise_error(SkeletonKey::Errors::UnsupportedPurposeNetworkError, /purpose=60, network=mainnet/)
    end
  end
end
