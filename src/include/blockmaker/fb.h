#pragma once

#include "blockmaker/btc.h"                // Bring in Bitcoin’s base SHA256d types
#include "poolinstances/stratumWorkStorage.h"

namespace FB {

  //================================================================================
  // AuxPoW‐extended header for Fractal Bitcoin (inherits Bitcoin’s BlockHeader)
  //================================================================================
  struct AuxPoWBlockHeader : public BTC::Proto::BlockHeader {
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // These fields are used when FB is merged‐mined under a parent chain
    BTC::Proto::Transaction       parentCoinbaseTx;
    uint256                       hashBlock;
    xvector<uint256>              merkleBranch;
    int                           index;
    xvector<uint256>              chainMerkleBranch;
    int                           chainIndex;
    BTC::Proto::BlockHeader       parentBlock;
  };

  //================================================================================
  // Proto: chain logic + AuxPoW consensus checking
  //================================================================================
  class Proto {
  public:
    static constexpr const char* TickerName = "FB";

    // These must match what BTC::WorkTy<> expects:
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

    //————————————————————————————————————————————————————————————————————————————————————
    // If AuxPoW bit is set (nVersion & 0x100), verify `parentBlock`’s PoW via BTC::checkConsensus.
    // Otherwise, verify this header’s PoW normally (Bitcoin‐style).
    //————————————————————————————————————————————————————————————————————————————————————
    static CCheckStatus checkConsensus(const BlockHeader &hdr,
                                       CheckConsensusCtx      &ctx,
                                       ChainParams           &chainParams)
    {
      if (hdr.nVersion & AuxPoWBlockHeader::VERSION_AUXPOW) {
        return BTC::Proto::checkConsensus(hdr.parentBlock, ctx, chainParams);
      } else {
        // Cast away AuxPoW extras and check the “pure” Bitcoin header:
        return BTC::Proto::checkConsensus(
                 (BTC::Proto::BlockHeader&)hdr,
                 ctx,
                 chainParams
               );
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
                               const CheckConsensusCtx & /*ctx*/)
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

  //================================================================================
  // Stratum: how PoolCore builds/submits FB work (pure SHA256d + AuxPoW)
  //================================================================================
  class Stratum {
  public:
    static constexpr double DifficultyFactor    = 1.0;    // same scaling as BTC
    static constexpr bool   MergedMiningSupport = true;   // FB supports AuxPoW (merged mining)

    // “Primary” work for FB: it is Bitcoin‐style (EWorkBitcoin), so use BTC::WorkTy<FB::Proto,...>
    using FBWork = BTC::WorkTy<FB::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

    //————————————————————————————————————————————————————————————————————————————————————
    // 1) Called when PoolCore gets a new getblocktemplate for FB:
    //    Reject if WorkType != EWorkBitcoin.
    //————————————————————————————————————————————————————————————————————————————————————
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

    //————————————————————————————————————————————————————————————————————————————————————
    // 2) FB itself is never a “secondary” under another primary—always primary or AuxPoW parent.
    //————————————————————————————————————————————————————————————————————————————————————
    static StratumSingleWork* newSecondaryWork(int64_t, PoolBackend*, size_t, const CMiningConfig&, const std::vector<uint8_t>&, const std::string&, CBlockTemplate&, std::string&) {
      return nullptr;
    }

    //————————————————————————————————————————————————————————————————————————————————————
    // 3) We don’t merge FB under yet another chain, so no mergedWork builder is required here.
    //————————————————————————————————————————————————————————————————————————————————————
    static StratumMergedWork* newMergedWork(int64_t, StratumSingleWork*, std::vector<StratumSingleWork*>&, const CMiningConfig&, std::string&) {
      return nullptr;
    }

    //————————————————————————————————————————————————————————————————————————————————————
    // 4) The following just reuse BTC’s decode + config logic unchanged:
    //————————————————————————————————————————————————————————————————————————————————————
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

    //————————————————————————————————————————————————————————————————————————————————————
    // 5) Required by StratumInstance<FB::X>::onStratumMiningConfigure(…)
    //    PoolCore will call this to set up version‐rolling on the worker. Delegate to BTC.
    //————————————————————————————————————————————————————————————————————————————————————
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
      BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }

    //————————————————————————————————————————————————————————————————————————————————————
    // 6) Declare buildChainMap so fb.cpp’s definition matches this signature exactly.
    //    (Used if FB is ever merged under some other chain; FB itself supports AuxPoW.)
    //————————————————————————————————————————————————————————————————————————————————————
    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                           uint32_t                       &nonce,
                                           unsigned                       &virtualHashesNum);

    //————————————————————————————————————————————————————————————————————————————————————
    // 7) The nested MergedWork class must be declared here with the exact same signatures
    //    and member‐variable names/types that fb.cpp expects. Otherwise, fb.cpp definitions
    //    will not match and you’ll get “no declaration matches…” errors.
    //————————————————————————————————————————————————————————————————————————————————————
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

      // prepareForSubmit must match fb.cpp’s implementation signature:
      bool prepareForSubmit(const CWorkerConfig &workerCfg,
                            const CStratumMessage &msg) override;

    private:
      //
      // 7.a) Primary (FB) header and Merkle path:
      //      We store the “pure” Bitcoin header here (no AuxPoW fields); fb.cpp will flip
      //      the VERSION_AUXPOW bit when constructing the merged‐mined child header.
      //
      BTC::Proto::BlockHeader         FBHeader_;
      std::vector<uint256>            FBMerklePath_;
      BTC::Proto::CheckConsensusCtx   FBConsensusCtx_;
      BTC::CoinbaseTx                 FBLegacyCoinbase_;
      BTC::CoinbaseTx                 FBWitnessCoinbase_;
      CMiningConfig                   MiningCfg_;

      //
      // 7.b) For each “secondary” AuxPoW chain under FB, store its AuxPoW header data:
      //
      std::vector<AuxPoWBlockHeader>  FBSecondaryHeaders_;
      std::vector<BTC::CoinbaseTx>    FBCoinbaseTransactions_;
      std::vector<BTC::CoinbaseTx>    FBWitnesses_;

      //
      // 7.c) A map of which child goes where in the Merkle tree, and the AuxPoW nonce:
      //
      std::vector<int>                FBWorkMap_;
      uint32_t                        FBNNonce_;
    };

  }; // class Stratum

  //================================================================================
  // Helper so FabricData_ can refer to FB::X (just like BTC::X, DOGE::X, etc.)
  //================================================================================
  struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;
  };

} // namespace FB

namespace BTC {
  template<>
  struct Io<FB::AuxPoWBlockHeader> {
    static inline void serialize(xmstream &dst, const FB::AuxPoWBlockHeader &data) {
      // 1) Pure Bitcoin header
      BTC::serialize(dst, *(BTC::Proto::BlockHeader*)&data);
      // 2) AuxPoW fields if VERSION_AUXPOW is set
      if (data.nVersion & FB::AuxPoWBlockHeader::VERSION_AUXPOW) {
        BTC::serialize(dst, data.parentCoinbaseTx);
        BTC::serialize(dst, data.hashBlock);
        BTC::serialize(dst, data.merkleBranch);
        BTC::serialize(dst, data.index);
        BTC::serialize(dst, data.chainMerkleBranch);
        BTC::serialize(dst, data.chainIndex);
        BTC::serialize(dst, data.parentBlock);
      }
    }
    static inline void unserialize(xmstream &src, FB::AuxPoWBlockHeader &data) {
      /* Unused by mining path; stub if needed */
    }
  };
} // namespace BTC
