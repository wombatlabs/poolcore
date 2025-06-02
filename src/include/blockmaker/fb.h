#pragma once

#include "blockmaker/btc.h"                // Bitcoin (SHA256d) base types
#include "poolinstances/stratumWorkStorage.h"

namespace FB {

  //==============================================================================
  // AuxPoW‐extended header for Fractal Bitcoin (inherits Bitcoin::BlockHeader)
  //==============================================================================
  struct AuxPoWBlockHeader : public BTC::Proto::BlockHeader {
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // These fields hold the AuxPoW payload if VERSION_AUXPOW is set:
    BTC::Proto::Transaction       parentCoinbaseTx;
    uint256                       hashBlock;
    xvector<uint256>              merkleBranch;
    int                           index;
    xvector<uint256>              chainMerkleBranch;
    int                           chainIndex;
    BTC::Proto::BlockHeader       parentBlock;
  };

  //==============================================================================
  // Proto: FB chain logic + AuxPoW consensus checking
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
    // If AuxPoW bit is set, verify parent’s PoW under BTC; otherwise, verify “pure” FB header under BTC.
    //──────────────────────────────────────────────────────────────────────────────
    static CCheckStatus checkConsensus(const BlockHeader &hdr,
                                       CheckConsensusCtx      &ctx,
                                       ChainParams           &chainParams)
    {
      if (hdr.nVersion & AuxPoWBlockHeader::VERSION_AUXPOW) {
        // The AuxPoW payload’s parentBlock must pass Bitcoin’s consensus:
        return BTC::Proto::checkConsensus(hdr.parentBlock, ctx, chainParams);
      } else {
        // No AuxPoW: just treat this as a regular Bitcoin header
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
      // Same as Bitcoin: difficulty = difficultyFromBits(nBits, 29)
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
  // Stratum: how PoolCore builds and submits FB work (SHA256d + AuxPoW)
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
      // FB’s “pure” work must be Bitcoin‐style (EWorkBitcoin):
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
    // 2) FB never acts as a “secondary” under another chain at this stage.
    //──────────────────────────────────────────────────────────────────────────────
    static StratumSingleWork* newSecondaryWork(int64_t, PoolBackend*, size_t, const CMiningConfig&, const std::vector<uint8_t>&, const std::string&, CBlockTemplate&, std::string&) {
      return nullptr;
    }

    //──────────────────────────────────────────────────────────────────────────────
    // 3) We don’t merge FB under anything else, so no merged‐work builder is needed.
    //──────────────────────────────────────────────────────────────────────────────
    static StratumMergedWork* newMergedWork(int64_t, StratumSingleWork*, std::vector<StratumSingleWork*>&, const CMiningConfig&, std::string&) {
      return nullptr;
    }

    //──────────────────────────────────────────────────────────────────────────────
    // 4) All the rest (decode, config, version rolling) is delegated to BTC’s Stratum:
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
    // 5) Called by StratumInstance<FB::X>::onStratumMiningConfigure:
    //──────────────────────────────────────────────────────────────────────────────
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
      BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }

    //──────────────────────────────────────────────────────────────────────────────
    // 6) buildChainMap: how to slot each FB secondary under one “tree” (if FB were merged under something else).
    //──────────────────────────────────────────────────────────────────────────────
    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                           uint32_t                       &nonce,
                                           unsigned                       &virtualHashesNum);

    //──────────────────────────────────────────────────────────────────────────────
    // 7) The nested MergedWork class—must exactly match fb.cpp’s definitions.
    //──────────────────────────────────────────────────────────────────────────────
    class MergedWork : public StratumMergedWork {
    public:
      // 7.a) Constructor signature (7 arguments, in this exact order):
      MergedWork(uint64_t                    stratumWorkId,
                 StratumSingleWork          *primaryWork,
                 std::vector<StratumSingleWork*> &secondaries,
                 std::vector<int>           &chainMap,
                 uint32_t                    auxNonce,
                 unsigned                    virtualHashesNum,
                 const CMiningConfig        &miningCfg);

      // 7.b) Override prepareForSubmit (same signature as BTC).
      bool prepareForSubmit(const CWorkerConfig &workerCfg,
                            const CStratumMessage &msg) override;

    private:
      // 7.c) Primary (FB) header, Merkle path, consensus context, coinbases:
      BTC::Proto::BlockHeader       FBHeader_;
      std::vector<uint256>          FBMerklePath_;
      BTC::Proto::CheckConsensusCtx FBConsensusCtx_;
      BTC::CoinbaseTx               FBLegacyCoinbase_;
      BTC::CoinbaseTx               FBWitnessCoinbase_;
      CMiningConfig                 MiningCfg_;

      // 7.d) For each secondary under FB (if we ever merged FB under another chain):
      std::vector<AuxPoWBlockHeader> FBSecondaryHeaders_;
      std::vector<BTC::CoinbaseTx>    FBCoinbaseTransactions_;
      std::vector<BTC::CoinbaseTx>    FBWitnesses_;

      // 7.e) WorkMap (which Merkle leaf each child occupies) + AuxPoW nonce:
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
// Putting this here (in fb.h) ensures fabric.cpp (and any TU) sees it.
//===============================================================================
namespace BTC {

  template<>
  struct Io<FB::AuxPoWBlockHeader> {
    // Serialize “pure” 80‐byte Bitcoin header, then (if AuxPoW bit) serialize AuxPoW fields:
    static inline void serialize(xmstream &dst, const FB::AuxPoWBlockHeader &data) {
      // 1) Write the six fields of a Bitcoin header (version, prevHash, merkleRoot, time, bits, nonce)
      BTC::serialize(dst, *(BTC::Proto::BlockHeader*)&data);

      // 2) If AuxPoW is set, write the extra AuxPoW payload in this order:
      if (data.nVersion & FB::AuxPoWBlockHeader::VERSION_AUXPOW) {
        // 2.a) Parent‐chain coinbase transaction
        BTC::serialize(dst, data.parentCoinbaseTx);
        // 2.b) Parent header’s hash, its Merkle‐branch, and index
        BTC::serialize(dst, data.hashBlock);
        BTC::serialize(dst, data.merkleBranch);
        BTC::serialize(dst, data.index);
        // 2.c) Chain‐merkle branch (if FB itself were merged under another chain)
        BTC::serialize(dst, data.chainMerkleBranch);
        BTC::serialize(dst, data.chainIndex);
        // 2.d) Finally, the full parent header (so the pool can re‐verify parent’s PoW)
        BTC::serialize(dst, data.parentBlock);
      }
    }

    // Unserialize is never used in PoolCore’s mining path, so we stub it out:
    static inline void unserialize(xmstream &src, FB::AuxPoWBlockHeader &data) {
      // (Unused in mining flow; left empty.)
    }
  };

} // namespace BTC
