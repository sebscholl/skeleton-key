
module SkeletonKey
  class Keyring
    # Initializes a new Keyring with an optional seed
    #
    # @param seed [String, Seed, Array<Integer>, nil] the seed to initialize the Keyring with (optional)
    # @return [Keyring] the initialized Keyring
    def initialize(seed: nil)
      @seed = Seed.import(seed)
    end

    def bitcoin
      @bitcoin ||= SkeletonKey::Bitcoin::Key.new(@seed.hex)
    end
  end
end
