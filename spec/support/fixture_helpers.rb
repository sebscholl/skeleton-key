
require "json"

module FixtureHelpers
  def load_fixture(file_key)
    JSON.load_file(SkeletonKey::ROOT + "/spec/fixtures/#{file_key}.json")
  end
end

RSpec.configure do |config|
  config.include FixtureHelpers
end
