#pragma once

#include "blockmaker/btc.h"
#include "poolinstances/stratumWorkStorage.h"

namespace FB {

  //--------------------------------------------------------------------------------
  // AuxPoW‐extended header for Fractal Bitcoin (same as in our previous version)
  //--------------------------------------------------------------------------------
  struct AuxPoWBlockHeader : public BTC::Proto::BlockHeader {
    static const int32_t VERSION_AUXPOW = (1 << 8);

    BTC::Proto::Transaction       parentCoinbaseTx;
    uint256                       hashBlock;
    xvector<uint256>              merkleBranch;
    int                           index;
    xvector<uint256>              chainMerkleBranch;
    int                           chainIndex;
    BTC::Proto::BlockHeader       parentBlock;
  };

  //--------------------------------------------------------------------------------
  // Proto: chain logic + AuxPoW checks (unchanged from earlier)
  //--------------------------------------------------------------------------------
  class Proto {
  public:
    static constexpr const char* TickerName = "FB";

    using BlockHeader       = AuxPoWBlockHeader;
    using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
    using ChainParams       = BTC::Proto::ChainParams;
    using BlockHashTy       = BTC::Proto::BlockHashTy;
    using TxHashTy          = BTC::Proto::TxHashTy;
    using AddressTy         = BTC::Proto::AddressTy;
    using TxIn        = BTC::Proto::TxIn;
    using TxOut       = BTC::Proto::TxOut;
    using TxWitness   = BTC::Proto::TxWitness;
    using Transaction = BTC::Proto::Transaction;
    using Block       = BTC::Proto::BlockTy<FB::Proto>;

    static CCheckStatus checkConsensus(const BlockHeader &hdr,
                                       CheckConsensusCtx      &ctx,
                                       ChainParams           &chainParams)
    {
      if (hdr.nVersion & AuxPoWBlockHeader::VERSION_AUXPOW) {
        return BTC::Proto::checkConsensus(hdr.parentBlock, ctx, chainParams);
      } else {
        return BTC::Proto::checkConsensus((BTC::Proto::BlockHeader&)hdr, ctx, chainParams);
      }
    }

    static CCheckStatus checkConsensus(const Block &block,
                                       CheckConsensusCtx &ctx,
                                       ChainParams       &chainParams)
    {
      return checkConsensus(block.header, ctx, chainParams);
    }

    static double getDifficulty(const BlockHeader &hdr) {
      return BTC::difficultyFromBits(hdr.nBits, 29);
    }

    static double expectedWork(const BlockHeader &hdr,
                               const CheckConsensusCtx & /*ctx*/ )
    {
      return getDifficulty(hdr);
    }

    static bool decodeHumanReadableAddress(const std::string         &hrAddress,
                                           const std::vector<uint8_t> &pubkeyAddressPrefix,
                                           AddressTy                 &address)
    {
      return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address);
    }
  };

  //--------------------------------------------------------------------------------
  // Stratum logic for FB (with AuxPoW, mirror of doge.h but namespaced to FB)
  //--------------------------------------------------------------------------------
  class Stratum {
  public:
    static constexpr double DifficultyFactor    = 1.0;   // same as BTC
    static constexpr bool   MergedMiningSupport = true;  // FB uses AuxPoW

    // The type of “work” for FB: pure SHA256d (BTC::WorkTy) but with FB::Proto:
    using FBWork = BTC::WorkTy<FB::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

    //———————————————————————————————————————————————————————————————————————————————
    // 1) newPrimaryWork: called by PoolCore when it gets a new getblocktemplate
    //———————————————————————————————————————————————————————————————————————————————
    static FBWork* newPrimaryWork(int64_t               stratumId,
                                  PoolBackend          *backend,
                                  size_t                backendIdx,
                                  const CMiningConfig  &miningCfg,
                                  const std::vector<uint8_t> &miningAddress,
                                  const std::string    &coinbaseMessage,
                                  CBlockTemplate       &blockTemplate,
                                  std::string          &error)
    {
      if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB";
        return nullptr;
      }
      auto ptr = std::make_unique<FBWork>(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
      );
      return ptr->loadFromTemplate(blockTemplate, error) ? ptr.release() : nullptr;
    }

    //———————————————————————————————————————————————————————————————————————————————
    // 2) FB is never used as a “secondary” under another primary—so reject secondaryWork:
    //———————————————————————————————————————————————————————————————————————————————
    static StratumSingleWork* newSecondaryWork(int64_t, PoolBackend*, size_t, const CMiningConfig&, const std::vector<uint8_t>&, const std::string&, CBlockTemplate&, std::string&) {
      return nullptr;
    }

    //———————————————————————————————————————————————————————————————————————————————
    // 3) We don’t build FB under yet another chain, so mergedWork = nullptr:
    //———————————————————————————————————————————————————————————————————————————————
    static StratumMergedWork* newMergedWork(int64_t, StratumSingleWork*, std::vector<StratumSingleWork*>&, const CMiningConfig&, std::string&) {
      return nullptr;
    }

    //———————————————————————————————————————————————————————————————————————————————
    // 4) Standard BTC decode + config delegates:
    //———————————————————————————————————————————————————————————————————————————————
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

    //———————————————————————————————————————————————————————————————————————————————
    // 5) Required by StratumInstance<X>::onStratumMiningConfigure(...)
    //———————————————————————————————————————————————————————————————————————————————
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
      BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }

    //———————————————————————————————————————————————————————————————————————————————
    // 6) Declare buildChainMap (so fb.cpp’s definition matches). This is used when
    //    PoolCore tries to merge FB with any “secondary” chains (if that ever happens).
    //———————————————————————————————————————————————————————————————————————————————
    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                           uint32_t                       &nonce,
                                           unsigned                       &virtualHashesNum);

    //———————————————————————————————————————————————————————————————————————————————
    // 7) Declare the nested MergedWork class, exactly as fb.cpp implements it.
    //    (Every field below is referenced in fb.cpp, so it must be declared here.)
    //———————————————————————————————————————————————————————————————————————————————
    class MergedWork : public StratumMergedWork {
    public:
      // Constructor signature must match fb.cpp exactly:
      MergedWork(uint64_t                stratumWorkId,
                 StratumSingleWork      *primaryWork,
                 std::vector<StratumSingleWork*> &secondaries,
                 std::vector<int>       &chainMap,
                 uint32_t                auxNonce,
                 unsigned                virtualHashesNum,
                 const CMiningConfig    &miningCfg);

      // prepareForSubmit must be declared to match fb.cpp:
      bool prepareForSubmit(const CWorkerConfig &workerCfg,
                            const CStratumMessage &msg) override;

    private:
      // 7.a) Primary work’s header + Merkle + consensus context (pure FB/Bitcoin header):
      AuxPoWBlockHeader                 FBHeader_;
      std::vector<uint256>              FBMerklePath_;
      BTC::Proto::CheckConsensusCtx     FBConsensusCtx_;
      BTC::Proto::Transaction           FBLegacyCoinbase_;
      BTC::Proto::Transaction           FBWitnessCoinbase_;
      CMiningConfig                     MiningCfg_;

      // 7.b) Space for each “secondary” AuxPoW (if FB were merged under something else):
      std::vector<AuxPoWBlockHeader>    FBSecondaryHeaders_;
      std::vector<BTC::Proto::Transaction> FBCoinbaseTx_;
      std::vector<BTC::Proto::Transaction> FBWitnessTx_;

      // 7.c) WorkMap to place children inside Merkle, and nonce:
      std::vector<int>                  FBWorkMap_;
      uint32_t                          FBNNonce_;
    };

  }; // class Stratum

  //--------------------------------------------------------------------------------
  // A small helper so FabricData_ can refer to FB::X (just like DOGE::X, BTC::X, etc.)
  //--------------------------------------------------------------------------------
  struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;
  };

} // namespace FB
