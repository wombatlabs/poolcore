#pragma once

#include "blockmaker/btc.h"                // bring in Bitcoin’s base types (SHA256d)
#include "poolinstances/stratumWorkStorage.h"

namespace FB {

  //--------------------------------------------------------------------------------
  // AuxPoW‐extended header for Fractal Bitcoin
  //--------------------------------------------------------------------------------
  struct AuxPoWBlockHeader : public BTC::Proto::BlockHeader {
    static const int32_t VERSION_AUXPOW = (1 << 8);

    // AuxPoW fields (identical structure to DOGE’s AuxPoWBlockHeader):
    BTC::Proto::Transaction       parentCoinbaseTx;
    uint256                       hashBlock;
    xvector<uint256>              merkleBranch;
    int                           index;
    xvector<uint256>              chainMerkleBranch;
    int                           chainIndex;
    BTC::Proto::BlockHeader       parentBlock;
  };

  //--------------------------------------------------------------------------------
  // Proto: chain logic + AuxPoW checks
  //--------------------------------------------------------------------------------
  class Proto {
  public:
    static constexpr const char* TickerName = "FB";

    // Make sure these aliases match exactly what BTC::WorkTy expects:
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

    //--------------------------------------------------------------------------------
    // checkConsensus: if AuxPoW bit is set, verify parentBlock’s PoW; else verify this header
    //--------------------------------------------------------------------------------
    static CCheckStatus checkConsensus(const BlockHeader &hdr,
                                       CheckConsensusCtx      &ctx,
                                       ChainParams           &chainParams)
    {
      if (hdr.nVersion & AuxPoWBlockHeader::VERSION_AUXPOW) {
        // AuxPoW: validate parent header’s PoW
        return BTC::Proto::checkConsensus(hdr.parentBlock, ctx, chainParams);
      } else {
        // no AuxPoW: validate the child header itself
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
      // use Bitcoin’s difficulty-from-bits routine:
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
  // Stratum logic for FB (pure SHA256d + AuxPoW)
  //--------------------------------------------------------------------------------
  class Stratum {
  public:
    static constexpr double DifficultyFactor    = 1.0;    // same scaling as BTC
    static constexpr bool   MergedMiningSupport = true;   // FB supports AuxPoW

    using FBWork = BTC::WorkTy<FB::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

    //--------------------------------------------------------------------------------
    // newPrimaryWork: only accept Bitcoin‐style work (EWorkBitcoin)
    //--------------------------------------------------------------------------------
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

    // FB is never a “secondary” (we only want FB as primary when we merge‐mine children under it, if any)
    static StratumSingleWork* newSecondaryWork(int64_t, PoolBackend*, size_t, const CMiningConfig&, const std::vector<uint8_t>&, const std::string&, CBlockTemplate&, std::string&) {
      return nullptr;
    }

    // We don’t build FB under another chain, so no mergedWork needed here:
    static StratumMergedWork* newMergedWork(int64_t, StratumSingleWork*, std::vector<StratumSingleWork*>&, const CMiningConfig&, std::string&) {
      return nullptr;
    }

    // decode / configure is identical to BTC:
    static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) {
      return BTC::Stratum::decodeStratumMessage(msg, in, size);
    }
    static void miningConfigInitialize(CMiningConfig &miningCfg, rapidjson::Value &instanceCfg) {
      BTC::Stratum::miningConfigInitialize(miningCfg, instanceCfg);
    }
    static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) {
      BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
    }
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
      BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
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

    //--------------------------------------------------------------------------------
    // buildChainMap and MergedWork would go here (copy/paste from doge.cpp,
    // but namespaced under FB:: and using AuxPoWBlockHeader). For brevity, we omit them.
    //--------------------------------------------------------------------------------

  };

  //--------------------------------------------------------------------------------
  // A small helper so that in fabric.cpp we can write “FB::X” exactly like other coins
  //--------------------------------------------------------------------------------
  struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;
  };

} // namespace FB
