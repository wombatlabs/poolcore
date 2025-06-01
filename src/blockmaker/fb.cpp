// fb.cpp
// “Fractal Bitcoin” (FB) auxiliary‐PoW code.
// Stubs out Merkle‐tree (“virtualHash”) logic so that this will compile.
//

#include "blockmaker/fb.h"
#include "blockmaker/serializeJson.h"
#include <loguru.hpp>

namespace FB {

//////////////////////////
// ─── FB::Stratum::buildChainMap ─────────────────────────────────────────────
//
//    Always force exactly one “virtual hash” per secondary, so:
//
//      nonce = 0; virtualHashesNum = 1;
//      chainMap = [0, 0, … (one entry per secondary) …]
//
std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork *> &secondary,
                       uint32_t &nonce,
                       unsigned &virtualHashesNum)
{
    // Force exactly one "virtual hash" slot per secondary (slot 0)
    nonce = 0;
    virtualHashesNum = 1;

    std::vector<int> result;
    result.resize(secondary.size(), 0);
    return result;
}

//////////////////////////
// ─── FB::Proto::checkConsensusInitialize & checkConsensus ───────────────────
//
//   For AUXPOW we delegate to BTC if the header has VERSION_AUXPOW.
//
void Proto::checkConsensusInitialize(CheckConsensusCtx &ctx)
{
    // nothing to do here
}

CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header,
                                   CheckConsensusCtx &ctx,
                                   Proto::ChainParams &chainParams)
{
    if (header.nVersion & BlockHeader::VERSION_AUXPOW) {
        // if AuxPoW bit is set, validate parent via BTC consensus
        return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
    } else {
        return BTC::Proto::checkConsensus(header, ctx, chainParams);
    }
}

CCheckStatus Proto::checkConsensus(const Proto::Block &block,
                                   CheckConsensusCtx &ctx,
                                   Proto::ChainParams &chainParams)
{
    return checkConsensus(block.header, ctx, chainParams);
}

//////////////////////////
// ─── FB::Stratum::newPrimaryWork & newSecondaryWork ─────────────────────────
//
//   FB is always SHA‐256 under the hood, so we only accept EWorkBitcoin.  Exactly
//   the same logic for primary & secondary: build an FBWork, loadFromTemplate.
//
Stratum::FbWork *
Stratum::newPrimaryWork(int64_t                 stratumId,
                        PoolBackend            *backend,
                        size_t                  backendIdx,
                        const CMiningConfig    &miningCfg,
                        const std::vector<uint8_t> &miningAddress,
                        const std::string      &coinbaseMessage,
                        CBlockTemplate         &blockTemplate,
                        std::string            &error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }
    auto *work = new Stratum::FbWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    );
    if (!work->loadFromTemplate(blockTemplate, error)) {
        delete work;
        return nullptr;
    }
    return work;
}

StratumSingleWork *
Stratum::newSecondaryWork(int64_t                 stratumId,
                          PoolBackend             *backend,
                          size_t                   backendIdx,
                          const CMiningConfig     &miningCfg,
                          const std::vector<uint8_t> &miningAddress,
                          const std::string       &coinbaseMessage,
                          CBlockTemplate          &blockTemplate,
                          std::string             &error)
{
    // FB’s secondaries are always SHA‐256 as well:
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB secondary";
        return nullptr;
    }

    // Same as primary:
    auto *work = new Stratum::FbWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    );
    if (!work->loadFromTemplate(blockTemplate, error)) {
        delete work;
        return nullptr;
    }
    return work;
}

//////////////////////////
// ─── FB::Stratum::MergedWork constructor ───────────────────────────────────
//
//   We inherit from StratumMergedWork (base = a “primary” BTC‐type work, ID, etc.).
//   Then we would normally build a Merkle‐of‐aux‐headers for FB.  Here we stub
//   out the actual Merkle‐tree—just allocate arrays of the right size, log, and quit.
//
Stratum::MergedWork::MergedWork(uint64_t                      stratumWorkId,
                                StratumSingleWork           *primaryWork,
                                std::vector<StratumSingleWork *> &second,
                                std::vector<int>            &chainMap,
                                uint32_t                      mmNonce,
                                unsigned                      virtualHashesNum,
                                const CMiningConfig         &miningCfg)
    : StratumMergedWork(stratumWorkId, primaryWork, second.empty() ? nullptr : second[0], miningCfg)
{
    size_t secCount = second.size();
    LOG_F(INFO,
          "[FB::MergedWork] starting: secCount=%zu, virtualHashesNum=%u",
          secCount, virtualHashesNum);

    if (secCount == 0 || virtualHashesNum == 0 || secCount > 128) {
        // Nothing to do; we still have a valid StratumMergedWork base
        return;
    }

    // Allocate our FB‐specific buffers (we’ll never actually fill them in this stub).
    LOG_F(INFO,
          "[FB::MergedWork] allocating FBHeaders_ for %zu sub‐headers, FBHeaderHashes_ for %u leaves",
          secCount, virtualHashesNum);

    FBHeaders_.resize(secCount);
    FBLegacy_.resize(secCount);
    FBWitness_.resize(secCount);
    FBHeaderHashes_.resize(virtualHashesNum, uint256());

    // In a real implementation you would now:
    //   1) copy each “secondary” header into FBHeaders_[i]
    //   2) copy the coinbase‐TX or its serialized data into FBLegacy_[i]
    //   3) set up witness data in FBWitness_[i]
    //
    //   Then compute “virtualHashesNum” many DoubleSHA256’s of a suitable header
    //   (e.g. using CCryptoKey or CHash256), fill FBHeaderHashes_[i], build a
    //   MerkleTree, fill FBHeaderMerkle_, FBBranches_, FBProofs_, etc.
    //
    // Since this is just a “stub to make it compile,” all of that is skipped.

    // ────────────────────────────────────────────────────────────────────────
    //   If you do have a version of poolcommon/cryptoHash.h (defining CCryptoKey),
    //   or a CHash256 (from Bitcoin Core), you can re‐insert the real code here.
    // ────────────────────────────────────────────────────────────────────────
}

FB::Proto::BlockHashTy
Stratum::MergedWork::shareHash()
{
    // Just return the primary’s work‐header hash.
    if (baseWork()) {
        return baseWork()->Header.GetHash();
    }
    return Proto::BlockHashTy{};
}

std::string
Stratum::MergedWork::blockHash(size_t workIdx)
{
    if (workIdx == 0 && baseWork()) {
        return baseWork()->Header.GetHash().ToString();
    } else if (workIdx - 1 < FBHeaders_.size()) {
        return FBHeaders_[workIdx - 1].GetHash().ToString();
    }
    return std::string{};
}

void
Stratum::MergedWork::mutate()
{
    // Bump time in the base header and re‐build the BTC notify message
    BaseHeader_.nTime = static_cast<uint32_t>(time(nullptr));
    BTC::Stratum::Work::buildNotifyMessageImpl(
        this,
        BaseHeader_,
        BaseHeader_.nVersion,
        BaseLegacy_,
        BaseMerklePath_,
        MiningCfg_,
        true,
        NotifyMessage_
    );
}

void
Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork)
{
    BTC::Stratum::Work::buildNotifyMessageImpl(
        this,
        BaseHeader_,
        BaseHeader_.nVersion,
        BaseLegacy_,
        BaseMerklePath_,
        MiningCfg_,
        resetPreviousWork,
        NotifyMessage_
    );
}

bool
Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                      const CStratumMessage &msg)
{
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
              BaseHeader_,
              BaseHeader_.nVersion,
              BaseLegacy_,
              BaseWitness_,
              BaseMerklePath_,
              workerCfg,
              MiningCfg_,
              msg
          )) {
        return false;
    }

    // In a real implementation we’d check each FBHeaders_[i] against FB consensus:
    // for (size_t i = 0; i < FBHeaders_.size(); i++) { … }

    return true;
}

void
Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
    if (workIdx == 0 && baseWork()) {
        baseWork()->buildBlockImpl(BaseHeader_, BaseWitness_, blockHexData);
    } else {
        auto *fw = fbWork(workIdx - 1);
        if (fw) {
            fw->buildBlockImpl(
                FBHeaders_[workIdx - 1],
                FBWitness_[workIdx - 1],
                blockHexData
            );
        }
    }
}

CCheckStatus
Stratum::MergedWork::checkConsensus(size_t workIdx)
{
    if (workIdx == 0 && baseWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(BaseHeader_, BaseConsensusCtx_);
    } else {
        auto *fw = fbWork(workIdx - 1);
        if (fw) {
            return FB::Stratum::FbWork::checkConsensusImpl(
                       FBHeaders_[workIdx - 1],
                       BaseConsensusCtx_
                   );
        }
    }
    return CCheckStatus();
}

} // namespace FB

//
// ─── EXPLICIT Io<T> SPECIALIZATION FOR FB::Proto::BlockHeader ───────────────
//
//   We need to tell BTC::Io how to serialize FB::Proto::BlockHeader.  This part
//   is essentially identical to the one in FRAC (or BTC FUllAuxPoW) – no change
//   needed here, as long as fb.h declares BlockHeader and its members.
//
namespace BTC {

template<>
inline void Io<FB::Proto::BlockHeader>::serialize(xmstream &s, const FB::Proto::BlockHeader &h)
{
    // 1) Serialize the six‐field “pure” header exactly as BTC does:
    Io<FB::Proto::PureBlockHeader>::serialize(s, h);

    // 2) Then serialize all the AuxPoW fields in FB’s BlockHeader:
    Io<FB::Proto::Transaction>::serialize(s, h.ParentBlockCoinbaseTx);
    Io<uint256>::serialize(s, h.HashBlock);
    Io<xvector<uint256>>::serialize(s, h.MerkleBranch);
    Io<int>::serialize(s, h.Index);
    Io<xvector<uint256>>::serialize(s, h.ChainMerkleBranch);
    Io<int>::serialize(s, h.ChainIndex);
    Io<FB::Proto::PureBlockHeader>::serialize(s, h.ParentBlock);
}

} // namespace BTC
