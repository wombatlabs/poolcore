#pragma once

#include "btc.h"                // Pull in all of Bitcoin’s types (SHA-256d base)
#include "poolinstances/stratumWorkStorage.h"

namespace FB {

  //--------------------------------------------------------------------------------
  // Proto (chain logic + AuxPoW) for Fractal Bitcoin
  //--------------------------------------------------------------------------------
  class Proto {
  public:
    static constexpr const char* TickerName = "FB";

    // We use Bitcoin’s 256-bit hash types directly:
    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using AddressTy   = BTC::Proto::AddressTy;

    // Because FB’s PoW is SHA-256d just like BTC, we can alias:
    using PureBlockHeader = BTC::Proto::BlockHeader;
    using BlockHeader     = PureBlockHeader;  // we’ll extend it in C++ below

    using TxIn          = BTC::Proto::TxIn;
    using TxOut         = BTC::Proto::TxOut;
    using TxWitness     = BTC::Proto::TxWitness;
    using Transaction   = BTC::Proto::Transaction;
    using Block         = BTC::Proto::BlockTy<FB::Proto>;

    // AuxPoW fields must be injected into our block header. We wrap the parent header / Merkle branches:
    struct AuxPoWBlockHeader : public PureBlockHeader {
      static const int32_t VERSION_AUXPOW = (1 << 8);

      // Parent‐chain/Coinbase merger fields (exact same names as DOGE’s AuxPoW):
      Transaction       parentCoinbaseTx;      // the child’s coinbase is built into this
      uint256           hashBlock;             // the parent header’s hashed bytes
      xvector<uint256>  merkleBranch;          // Merkle branch from parent coinbase → parent merkle root
      int               index;                 // index in that Merkle
      xvector<uint256>  chainMerkleBranch;     // if FB itself were merged under something else; usually empty
      int               chainIndex;            // index in chain merkle
      PureBlockHeader   parentBlock;           // full parent header (to re-verify parent’s PoW)
    };

    // Override checkConsensus to inspect VERSION_AUXPOW bit:
    static CCheckStatus checkConsensus(const AuxPoWBlockHeader &hdr,
                                       BTC::Proto::CheckConsensusCtx &ctx,
                                       BTC::Proto::ChainParams &chainParams)
    {
      // If AuxPoW bit is flipped, verify parent header’s PoW; otherwise, verify this header directly.
      if (hdr.nVersion & AuxPoWBlockHeader::VERSION_AUXPOW) {
        return BTC::Proto::checkConsensus(hdr.parentBlock, ctx, chainParams);
      } else {
        return BTC::Proto::checkConsensus((PureBlockHeader&)hdr, ctx, chainParams);
      }
    }

    static CCheckStatus checkConsensus(const Block &block,
                                       BTC::Proto::CheckConsensusCtx &ctx,
                                       BTC::Proto::ChainParams &chainParams)
    {
      return checkConsensus(block.header, ctx, chainParams);
    }

    static double getDifficulty(const AuxPoWBlockHeader &hdr) {
      return BTC::difficultyFromBits(hdr.nBits, 29);
    }

    static double expectedWork(const AuxPoWBlockHeader &hdr,
                               const BTC::Proto::CheckConsensusCtx &ctx)
    {
      return getDifficulty(hdr);
    }

    static bool decodeHumanReadableAddress(const std::string &hrAddress,
                                           const std::vector<uint8_t> &pubkeyAddressPrefix,
                                           AddressTy &address)
    {
      return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address);
    }
  };

  //--------------------------------------------------------------------------------
  // Stratum logic for FB
  //--------------------------------------------------------------------------------
  class Stratum {
  public:
    static constexpr double DifficultyFactor = 1.0;       // same scaling as BTC
    static constexpr bool MergedMiningSupport = true;     // FB supports AuxPoW

    // Work type: primary = FB (SHA-256d)
    using FBWork = BTC::WorkTy<FB::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

    static FBWork* newPrimaryWork(int64_t stratumId,
                                  PoolBackend *backend,
                                  size_t backendIdx,
                                  const CMiningConfig &miningCfg,
                                  const std::vector<uint8_t> &miningAddress,
                                  const std::string &coinbaseMessage,
                                  CBlockTemplate &blockTemplate,
                                  std::string &error)
    {
      if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB";
        return nullptr;
      }
      auto workPtr = std::make_unique<FBWork>(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
      );
      return workPtr->loadFromTemplate(blockTemplate, error) ? workPtr.release() : nullptr;
    }

    // FB is never a “secondary” when merged under something else. We only want FB as primary:
    static StratumSingleWork* newSecondaryWork(int64_t, PoolBackend*, size_t, const CMiningConfig&, const std::vector<uint8_t>&, const std::string&, CBlockTemplate&, std::string&) {
      return nullptr;
    }

    static StratumMergedWork* newMergedWork(int64_t, StratumSingleWork*, std::vector<StratumSingleWork*>&, const CMiningConfig&, std::string&) {
      return nullptr;
    }

    // Decode / config re-use BTC’s logic exactly:
    static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) {
      return BTC::Stratum::decodeStratumMessage(msg, in, size);
    }
    static void miningConfigInitialize(CMiningConfig &miningCfg, rapidjson::Value &instanceCfg) {
      BTC::Stratum::miningConfigInitialize(miningCfg, instanceCfg);
    }
    static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) {
      BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
    }
    static void workerConfigOnSubscribe(CWorkerConfig &workerCfg,
                                        CMiningConfig &miningCfg,
                                        CStratumMessage &msg,
                                        xmstream &out,
                                        std::string &subscribeInfo)
    {
      BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
    }
    static void buildSendTargetMessage(xmstream &stream, double difficulty) {
      BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor);
    }
  };

} // namespace FB
