# frozen_string_literal: true

require "bundler/setup"
require "skeleton_key"

# Support files
require_relative "support/fixture_helpers"

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  # Run specs in random order to surface order dependencies.
  config.order = :random
  Kernel.srand config.seed

  # Enable persistence of example status (passed/failed) across test runs
  config.example_status_persistence_file_path = ".rspec_status"
end
