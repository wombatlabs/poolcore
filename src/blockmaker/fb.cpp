// fb.cpp
// “Fractal Bitcoin” (FB) auxiliary‐PoW code for poolcore.
//
// This version calls the correct StratumMergedWork constructor so that
// BaseHeader_/BaseLegacy_/BaseMerklePath_ are initialized, avoiding a crash.
//
// The raw Merkle‐tree / DoubleSHA256 parts are still stubbed out.
// Once you locate your SHA256 helper (e.g. CHash256 or CCryptoKey), you
// can re‐enable the “real” auxiliary‐header hashing below.
//
// =============================================================================

#include "blockmaker/fb.h"
#include "blockmaker/serializeJson.h"
#include <loguru.hpp>

namespace FB {

//////////////////////////
// ─── FB::Stratum::buildChainMap ─────────────────────────────────────────────
//
//   Always force exactly one “virtual hash” per secondary, so:
//
//     nonce = 0; virtualHashesNum = 1;
//     chainMap = [0,0,…]  (one entry per secondary)
//
std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork *> &secondary,
                       uint32_t                     &nonce,
                       unsigned                     &virtualHashesNum)
{
    // Force exactly one "virtual hash" slot per secondary:
    nonce = 0;
    virtualHashesNum = 1;

    std::vector<int> result(secondary.size(), 0);
    return result;
}

//////////////////////////
// ─── FB::Proto::checkConsensusInitialize & checkConsensus ───────────────────
//
//   If nVersion has AUXPOW bit, delegate to BTC consensus on h.ParentBlock.
//   Otherwise delegate to BTC consensus on h itself.
//
void Proto::checkConsensusInitialize(CheckConsensusCtx &ctx)
{
    // nothing needed here
}

CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header,
                                   CheckConsensusCtx          &ctx,
                                   Proto::ChainParams         &chainParams)
{
    if (header.nVersion & BlockHeader::VERSION_AUXPOW) {
        return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
    } else {
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
Stratum::FbWork *
Stratum::newPrimaryWork(int64_t                   stratumId,
                        PoolBackend              *backend,
                        size_t                     backendIdx,
                        const CMiningConfig      &miningCfg,
                        const std::vector<uint8_t> &miningAddress,
                        const std::string        &coinbaseMessage,
                        CBlockTemplate           &blockTemplate,
                        std::string              &error)
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
Stratum::newSecondaryWork(int64_t                   stratumId,
                          PoolBackend              *backend,
                          size_t                     backendIdx,
                          const CMiningConfig      &miningCfg,
                          const std::vector<uint8_t> &miningAddress,
                          const std::string        &coinbaseMessage,
                          CBlockTemplate           &blockTemplate,
                          std::string              &error)
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
//   Use the (id, primaryWork, vector<secondaries>, miningCfg) constructor
//   so that StratumMergedWork’s BaseHeader_, BaseLegacy_, BaseMerklePath_
//   get initialized properly.  Otherwise you see SIGSEGV at broadcast.
//
//   Everything after the “allocate arrays” is still stubbed out (no real
//   DoubleSHA256 or MerkleTree calls).
//
Stratum::MergedWork::MergedWork(uint64_t                          stratumWorkId,
                                StratumSingleWork               *primaryWork,
                                std::vector<StratumSingleWork *> &second,
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
        // Nothing further to do.  Base class has set up the “primary” work already.
        return;
    }

    LOG_F(INFO,
          "[FB::MergedWork] allocating FBHeaders_ for %zu sub‐headers, FBHeaderHashes_ for %u leaves",
          secCount, virtualHashesNum);

    FBHeaders_.resize(secCount);
    FBLegacy_.resize(secCount);
    FBWitness_.resize(secCount);
    FBHeaderHashes_.resize(virtualHashesNum, uint256());

    //
    // ────────────────────────────────────────────────────────────────────────────
    //   In a “real” FB/AuxPoW implementation you would now:
    //     1) cast second[i] to Stratum::FbWork* and copy .Header into FBHeaders_[i],
    //        copy coinbase‐TX into FBLegacy_[i], and any witness into FBWitness_[i].
    //     2) Compute “virtualHashesNum” many DoubleSHA256’s of a header variant:
    //          CCryptoKey sha;
    //          for (unsigned i = 0; i < virtualHashesNum; i++) {
    //              uint32_t randv = mmNonce + i;
    //              randv = randv * 1103515245 + 12345;
    //              randv += (FBHeaders_[0].nVersion >> 16);
    //              FBLegacy_[0].nNonce = randv;
    //              FBHeaderHashes_[i] = sha.DoubleSHA256(FBLegacy_[0]);
    //          }
    //     3) Build a MerkleTree on FBHeaderHashes_:
    //          MerkleTree merkle;
    //          merkle.BuildTree(FBHeaderHashes_, FBHeaderMerkle_);
    //          merkle.BuildBranches(FBHeaderMerkle_, FBBranches_);
    //          merkle.BuildBranches(FBHeaderHashes_, FBProofs_);
    //
    //   Since poolcommon/cryptoHash.h does not exist in your tree, we leave
    //   all of steps (2) & (3) entirely commented/stubbed out.  The arrays are
    //   allocated so that no one crashes on “out of bounds,” and the job will
    //   broadcast a valid primary header at least.
    // ────────────────────────────────────────────────────────────────────────────
    //
    // (Stub) Do not fill in FBHeaders_, FBLegacy_, FBWitness_, FBHeaderHashes_.
    //
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

    // In a real FB/AuxPoW, loop‐over FBHeaders_ and check consensus on each.
    // Here we just trust the primary.
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
inline void Io<FB::Proto::BlockHeader>::serialize(xmstream &s,
                                                 const FB::Proto::BlockHeader &h)
{
    // 1) six‐field “pure” header
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
