#pragma once

#include "blockmaker/btc.h"                // Bitcoin’s SHA256d base types
#include "poolinstances/stratumWorkStorage.h"

namespace FB {

  //==============================================================================
  // AuxPoW‐extended header for Fractal Bitcoin (inherits Bitcoin::BlockHeader)
  //==============================================================================
  struct AuxPoWBlockHeader : public BTC::Proto::BlockHeader {
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // AuxPoW fields (same structure as DOGE’s AuxPoWBlockHeader, but namespaced to FB):
    BTC::Proto::Transaction       parentCoinbaseTx;
    uint256                       hashBlock;
    xvector<uint256>              merkleBranch;
    int                           index;
    xvector<uint256>              chainMerkleBranch;
    int                           chainIndex;
    BTC::Proto::BlockHeader       parentBlock;
  };

  //==============================================================================
  // Proto: chain logic + AuxPoW consensus checking
  //==============================================================================
  class Proto {
  public:
    static constexpr const char* TickerName = "FB";

    // These aliases must match what BTC::WorkTy<> expects:
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

    //──────────────────────────────────────────────────────────────────────────────
    // If AuxPoW bit is set, verify parent’s PoW; else verify this header’s PoW.
    //──────────────────────────────────────────────────────────────────────────────
    static CCheckStatus checkConsensus(const BlockHeader &hdr,
                                       CheckConsensusCtx      &ctx,
                                       ChainParams           &chainParams)
    {
      if (hdr.nVersion & AuxPoWBlockHeader::VERSION_AUXPOW) {
        return BTC::Proto::checkConsensus(hdr.parentBlock, ctx, chainParams);
      } else {
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

  //==============================================================================
  // Stratum: how PoolCore builds/submits FB work (SHA256d + AuxPoW)
  //==============================================================================
  class Stratum {
  public:
    static constexpr double DifficultyFactor    = 1.0;    // same as Bitcoin
    static constexpr bool   MergedMiningSupport = true;   // FB supports AuxPoW

    using FBWork = BTC::WorkTy<FB::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

    //──────────────────────────────────────────────────────────────────────────────
    // 1) Called when PoolCore gets a new getblocktemplate for FB:
    //──────────────────────────────────────────────────────────────────────────────
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

    //──────────────────────────────────────────────────────────────────────────────
    // 2) FB itself is never a “secondary”—we only want FB as primary for AuxPoW.
    //──────────────────────────────────────────────────────────────────────────────
    static StratumSingleWork* newSecondaryWork(int64_t, PoolBackend*, size_t, const CMiningConfig&, const std::vector<uint8_t>&, const std::string&, CBlockTemplate&, std::string&) {
      return nullptr;
    }

    //──────────────────────────────────────────────────────────────────────────────
    // 3) We never merge FB under another chain, so return nullptr.
    //──────────────────────────────────────────────────────────────────────────────
    static StratumMergedWork* newMergedWork(int64_t, StratumSingleWork*, std::vector<StratumSingleWork*>&, const CMiningConfig&, std::string&) {
      return nullptr;
    }

    //──────────────────────────────────────────────────────────────────────────────
    // 4) Reuse BTC’s decode + config logic:
    //──────────────────────────────────────────────────────────────────────────────
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

    //──────────────────────────────────────────────────────────────────────────────
    // 5) Required by StratumInstance<FB::X>::onStratumMiningConfigure(...)
    //──────────────────────────────────────────────────────────────────────────────
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
      BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }

    //──────────────────────────────────────────────────────────────────────────────
    // 6) Declare buildChainMap (must match fb.cpp exactly)
    //──────────────────────────────────────────────────────────────────────────────
    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                           uint32_t                       &nonce,
                                           unsigned                       &virtualHashesNum);

    //──────────────────────────────────────────────────────────────────────────────
    // 7) Declare nested MergedWork class, matching fb.cpp definitions exactly.
    //──────────────────────────────────────────────────────────────────────────────
    class MergedWork : public StratumMergedWork {
    public:
      // Constructor signature:
      MergedWork(uint64_t                  stratumWorkId,
                 StratumSingleWork        *primaryWork,
                 std::vector<StratumSingleWork*> &secondaries,
                 std::vector<int>         &chainMap,
                 uint32_t                  auxNonce,
                 unsigned                  virtualHashesNum,
                 const CMiningConfig      &miningCfg);

      // Must override:
      bool prepareForSubmit(const CWorkerConfig &workerCfg,
                            const CStratumMessage &msg) override;

    private:
      // 7.a) Primary (FB) header and Merkle path (pure Bitcoin header):
      BTC::Proto::BlockHeader       FBHeader_;
      std::vector<uint256>          FBMerklePath_;
      BTC::Proto::CheckConsensusCtx FBConsensusCtx_;
      BTC::CoinbaseTx               FBLegacyCoinbase_;
      BTC::CoinbaseTx               FBWitnessCoinbase_;
      CMiningConfig                 MiningCfg_;

      // 7.b) For each secondary chain under FB (if FB is merged under something else):
      std::vector<AuxPoWBlockHeader> FBSecondaryHeaders_;
      std::vector<BTC::CoinbaseTx>    FBCoinbaseTransactions_;
      std::vector<BTC::CoinbaseTx>    FBWitnesses_;

      // 7.c) WorkMap (which index each child occupies) and the AuxPoW nonce:
      std::vector<int>               FBWorkMap_;
      uint32_t                       FBNNonce_;
    };

  }; // class Stratum

  //==============================================================================
  // Helper so FabricData_ can refer to FB::X (just like DOGE::X, BTC::X, etc.)
  //==============================================================================
  struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;
  };

} // namespace FB


//===============================================================================
// Provide an inline Io<> specialization for FB::AuxPoWBlockHeader.
// Placing it here ensures any TU (fabric.cpp, etc.) sees it.
//===============================================================================
namespace BTC {

  template<>
  struct Io<FB::AuxPoWBlockHeader> {
    // Serialize “pure” Bitcoin header, then (if AuxPoW) serialize the extra fields.
    static inline void serialize(xmstream &dst, const FB::AuxPoWBlockHeader &data) {
      // 1) Write 80‐byte Bitcoin header (version, prevHash, merkleRoot, time, bits, nonce)
      BTC::serialize(dst, *(BTC::Proto::BlockHeader*)&data);

      // 2) If AuxPoW bit is set, write AuxPoW fields:
      if (data.nVersion & FB::AuxPoWBlockHeader::VERSION_AUXPOW) {
        // 2.a) Parent‐chain coinbase
        BTC::serialize(dst, data.parentCoinbaseTx);
        // 2.b) Parent header’s hash, merkle branch, index
        BTC::serialize(dst, data.hashBlock);
        BTC::serialize(dst, data.merkleBranch);
        BTC::serialize(dst, data.index);
        // 2.c) Chain‐merkle branch and index (if FB itself were merged under another chain)
        BTC::serialize(dst, data.chainMerkleBranch);
        BTC::serialize(dst, data.chainIndex);
        // 2.d) Full parent header (to re‐verify parent PoW)
        BTC::serialize(dst, data.parentBlock);
      }
    }

    // Unserialize is unused by PoolCore’s mining flow, so stubbed out:
    static inline void unserialize(xmstream &src, FB::AuxPoWBlockHeader &data) {
      // (Empty – not needed for mining submission.)
    }
  };

} // namespace BTC
