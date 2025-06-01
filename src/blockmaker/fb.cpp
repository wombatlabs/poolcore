// fb.cpp
// “Fractal Bitcoin” (FB) auxiliary‐PoW code for poolcore.
//
// This version compiles against the current poolcore tree and
// delegates all real SHA256 & Merkle‐tree work to stubs (no cryptoHash.h).
// The important change is: call StratumMergedWork’s constructor so that
// BaseHeader_/BaseLegacy_/BaseMerklePath_ are inited and no SIGSEGV occurs.
//
// =============================================================================

#include "blockmaker/fb.h"
#include "blockmaker/serializeJson.h"

// We need uint256 and StratumMergedWork:
#include "poolcommon/arith_uint256.h"
#include "blockmaker/stratumWork.h"

#include <loguru.hpp>
#include <vector>
#include <cstdint>
#include <ctime>

namespace FB {

//////////////////////////
// ─── FB::Stratum::buildChainMap ─────────────────────────────────────────────
//   Always force exactly one “virtual hash” per secondary, so:
//
//     nonce = 0; virtualHashesNum = 1;
//     chainMap = [0,0,…]  (one entry per secondary)
//
std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                       uint32_t                     &nonce,
                       unsigned                     &virtualHashesNum)
{
    // Force exactly one "virtual hash" slot per secondary:
    nonce = 0;
    virtualHashesNum = 1;

    std::vector<int> chainMap(secondaries.size(), 0);
    return chainMap;
}

//////////////////////////
// ─── FB::Proto::checkConsensusInitialize & checkConsensus ───────────────────
//   If nVersion has AUXPOW bit, delegate to BTC consensus on h.ParentBlock.
//   Otherwise delegate to BTC consensus on h itself.
//
void Proto::checkConsensusInitialize(CheckConsensusCtx &ctx)
{
    // nothing to do here
}

CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header,
                                   CheckConsensusCtx          &ctx,
                                   Proto::ChainParams         &chainParams)
{
    if (header.nVersion & BlockHeader::VERSION_AUXPOW) {
        // AuxPoW → check ParentBlock under BTC rules
        return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
    } else {
        // No AuxPoW → check this header under BTC rules
        return BTC::Proto::checkConsensus(header, ctx, chainParams);
    }
}

CCheckStatus Proto::checkConsensus(const Proto::Block &block,
                                   CheckConsensusCtx      &ctx,
                                   Proto::ChainParams     &chainParams)
{
    return checkConsensus(block.header, ctx, chainParams);
}

//////////////////////////
// ─── FB::Stratum::newPrimaryWork & newSecondaryWork ─────────────────────────
//
//   Both primary and secondary FB‐works must be SHA‐256 (EWorkBitcoin).
//
Stratum::FbWork*
Stratum::newPrimaryWork(int64_t                    stratumId,
                        PoolBackend               *backend,
                        size_t                      backendIdx,
                        const CMiningConfig       &miningCfg,
                        const std::vector<uint8_t> &miningAddress,
                        const std::string         &coinbaseMessage,
                        CBlockTemplate            &blockTemplate,
                        std::string               &error)
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

StratumSingleWork*
Stratum::newSecondaryWork(int64_t                    stratumId,
                          PoolBackend               *backend,
                          size_t                      backendIdx,
                          const CMiningConfig       &miningCfg,
                          const std::vector<uint8_t> &miningAddress,
                          const std::string         &coinbaseMessage,
                          CBlockTemplate            &blockTemplate,
                          std::string               &error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB secondary";
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

//////////////////////////
// ─── FB::Stratum::MergedWork constructor ───────────────────────────────────
//
//   Use the (id, primaryWork, vector<secondaries>, miningCfg) ctor
//   so that StratumMergedWork’s BaseHeader_, BaseLegacy_, BaseMerklePath_
//   get initialized properly.  Otherwise you see SIGSEGV when broadcasting.
//
//   Everything after the “allocate arrays” is still stubbed out (no real
//   DoubleSHA256 or MerkleTree calls).  We just grow the vectors so that no
//   out‐of‐bounds indexing ever happens.
//
Stratum::MergedWork::MergedWork(uint64_t                          stratumWorkId,
                                StratumSingleWork               *primaryWork,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int>                 &chainMap,
                                uint32_t                          mmNonce,
                                unsigned                          virtualHashesNum,
                                const CMiningConfig             &miningCfg)
    : StratumMergedWork(stratumWorkId, primaryWork, second, miningCfg)
{
    size_t secCount = second.size();
    LOG_F(INFO,
          "[FB::MergedWork] starting: secCount=%zu, virtualHashesNum=%u",
          secCount, virtualHashesNum);

    if (secCount == 0 || virtualHashesNum == 0 || secCount > 128) {
        // Nothing further to do; base class already set up the primary work.
        return;
    }

    LOG_F(INFO,
          "[FB::MergedWork] allocating FBHeaders_ for %zu sub‐headers, FBHeaderHashes_ for %u leaves",
          secCount, virtualHashesNum);

    FBHeaders_.resize(secCount);
    FBLegacy_.resize(secCount);
    FBWitness_.resize(secCount);

    // Even though we don’t have CHash256 or CCryptoKey, allocate the array
    FBHeaderHashes_.resize(virtualHashesNum, uint256());

    // ────────────────────────────────────────────────────────────────────────────
    // In a fully‐fleshed AuxPoW you would now:
    //
    //   for (size_t i = 0; i < secCount; ++i) {
    //     auto *fbw = static_cast<Stratum::FbWork*>(second[i]);
    //     FBHeaders_[i] = fbw->Header;
    //     FBLegacy_[i]   = fbw->Legacy;
    //     FBWitness_[i]  = fbw->Witness;
    //   }
    //
    //   CCryptoKey sha;
    //   for (unsigned i = 0; i < virtualHashesNum; ++i) {
    //     uint32_t randv = mmNonce + i;
    //     randv = randv * 1103515245 + 12345;
    //     randv += (FBHeaders_[0].nVersion >> 16);
    //     FBLegacy_[0].nNonce = randv;
    //     FBHeaderHashes_[i] = sha.DoubleSHA256(FBLegacy_[0]);
    //   }
    //
    //   MerkleTree merkle;
    //   merkle.BuildTree(FBHeaderHashes_, FBHeaderMerkle_);
    //   merkle.BuildBranches(FBHeaderMerkle_, FBBranches_);
    //   merkle.BuildBranches(FBHeaderHashes_, FBProofs_);
    //
    // Since “poolcommon/cryptoHash.h” is gone, we leave all of steps (2)&(3) commented out.
    // The buffers are big enough to avoid any OOB, and you’ll at least broadcast a valid
    // “primary” BTC/BCH job.  No SIGSEGV in build‐broadcast.
    // ────────────────────────────────────────────────────────────────────────────

    // (Stub) we do not fill FBHeaders_, FBLegacy_, FBWitness_, FBHeaderHashes_.
}

FB::Proto::BlockHashTy
Stratum::MergedWork::shareHash()
{
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

    // In a real FB/AuxPoW, loop‐over FBHeaders_ and check each consensus:
    //   for (auto &hdr : FBHeaders_) FB::Stratum::FbWork::checkConsensusImpl(hdr, FBConsensusCtx_);
    // Here, we simply trust the primary, so always return true.
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
//   Exactly the same as FRAC/BTC’s “serialize AuxPoW” code.  No changes needed.
//
namespace BTC {

template<>
inline void Io<FB::Proto::BlockHeader>::serialize(xmstream              &s,
                                                 const FB::Proto::BlockHeader &h)
{
    // 1) serialize the “pure” 6‐field header
    Io<FB::Proto::PureBlockHeader>::serialize(s, h);

    // 2) then AuxPoW fields:
    Io<FB::Proto::Transaction>::serialize(s, h.ParentBlockCoinbaseTx);
    Io<uint256>::serialize(s, h.HashBlock);
    Io<xvector<uint256>>::serialize(s, h.MerkleBranch);
    Io<int>::serialize(s, h.Index);
    Io<xvector<uint256>>::serialize(s, h.ChainMerkleBranch);
    Io<int>::serialize(s, h.ChainIndex);
    Io<FB::Proto::PureBlockHeader>::serialize(s, h.ParentBlock);
}

} // namespace BTC
