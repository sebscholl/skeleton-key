# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Bitcoin
      module Support
        module Versioning
          VERSION_BYTES = {
            mainnet: {
              bip44: { xpub: 0x0488B21E, xprv: 0x0488ADE4 },
              bip49: { ypub: 0x049D7CB2, yprv: 0x049D7878 },
              bip84: { zpub: 0x04B24746, zprv: 0x04B2430C }
            },
            testnet: {
              bip44: { tpub: 0x043587CF, tprv: 0x04358394 },
              bip49: { upub: 0x044A5262, uprv: 0x044A4E28 },
              bip84: { vpub: 0x045F1CF6, vprv: 0x045F18BC }
            }
          }.freeze

          module_function

          def version_byte(network:, purpose:, private: false)
            version = if private
              private_version_byte(network: network, purpose: purpose)
            else
              public_version_byte(network: network, purpose: purpose)
            end

            [version].pack("N")
          end

          def version_bytes(network:, purpose:)
            case [purpose, network]
            when [32, :mainnet] then VERSION_BYTES[:mainnet][:bip44]
            when [32, :testnet] then VERSION_BYTES[:testnet][:bip44]
            when [141, :mainnet] then VERSION_BYTES[:mainnet][:bip84]
            when [141, :testnet] then VERSION_BYTES[:testnet][:bip84]
            when [44, :mainnet] then VERSION_BYTES[:mainnet][:bip44]
            when [44, :testnet] then VERSION_BYTES[:testnet][:bip44]
            when [49, :mainnet] then VERSION_BYTES[:mainnet][:bip49]
            when [49, :testnet] then VERSION_BYTES[:testnet][:bip49]
            when [84, :mainnet] then VERSION_BYTES[:mainnet][:bip84]
            when [84, :testnet] then VERSION_BYTES[:testnet][:bip84]
            else
              raise Errors::UnsupportedPurposeNetworkError.new(purpose: purpose, network: network)
            end
          end

          def public_version_byte(network:, purpose:)
            case [purpose, network]
            when [32, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xpub]
            when [32, :testnet] then VERSION_BYTES[:testnet][:bip44][:tpub]
            when [141, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zpub]
            when [141, :testnet] then VERSION_BYTES[:testnet][:bip84][:vpub]
            when [44, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xpub]
            when [44, :testnet] then VERSION_BYTES[:testnet][:bip44][:tpub]
            when [49, :mainnet] then VERSION_BYTES[:mainnet][:bip49][:ypub]
            when [49, :testnet] then VERSION_BYTES[:testnet][:bip49][:upub]
            when [84, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zpub]
            when [84, :testnet] then VERSION_BYTES[:testnet][:bip84][:vpub]
            else
              raise Errors::UnsupportedPurposeNetworkError.new(purpose: purpose, network: network)
            end
          end

          def private_version_byte(network:, purpose:)
            case [purpose, network]
            when [32, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xprv]
            when [32, :testnet] then VERSION_BYTES[:testnet][:bip44][:tprv]
            when [141, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zprv]
            when [141, :testnet] then VERSION_BYTES[:testnet][:bip84][:vprv]
            when [44, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xprv]
            when [44, :testnet] then VERSION_BYTES[:testnet][:bip44][:tprv]
            when [49, :mainnet] then VERSION_BYTES[:mainnet][:bip49][:yprv]
            when [49, :testnet] then VERSION_BYTES[:testnet][:bip49][:uprv]
            when [84, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zprv]
            when [84, :testnet] then VERSION_BYTES[:testnet][:bip84][:vprv]
            else
              raise Errors::UnsupportedPurposeNetworkError.new(purpose: purpose, network: network)
            end
          end
        end
      end
    end
  end
end
