// fb.cpp
#include "blockmaker/fb.h"
#include "blockmaker/serializeJson.h"
#include "poolcommon/arith_uint256.h"
#include <loguru.hpp>

// Note: we do NOT include a missing "poolcommon/cryptoHash.h" here, nor attempt any CCryptoKey calls.
// We simply record header hashes as dummy uint256 values (e.g. the secondary header's own hash),
// and skip building a full AuxPoW Merkle tree.

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

namespace FB {

//////////////////////////
// ─── FB::Stratum::buildChainMap ─────────────────────────────────────────────
//
// For Fractal (FB) we force exactly one “virtual‐hash” slot per secondary (always slot 0).
//
std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork *> &secondary,
                       uint32_t &nonce,
                       unsigned &virtualHashesNum)
{
    // Always allocate exactly one “virtual hash” per secondary
    nonce = 0;
    virtualHashesNum = 1;

    std::vector<int> result;
    result.resize(secondary.size(), 0);
    return result;
}

//////////////////////////
// 2) checkConsensusInitialize & checkConsensus
//    (parallel to DOGE but dispatch to BTC::checkConsensus on the parent chain)
void Proto::checkConsensusInitialize(CheckConsensusCtx &ctx) {
    // no extra initialization needed
}

CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header,
                                   CheckConsensusCtx &ctx,
                                   Proto::ChainParams &chainParams)
{
    if (header.nVersion & BlockHeader::VERSION_AUXPOW) {
        // If AuxPoW bit is set, validate the “parent block” via BTC.Proto
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
// 3) newPrimaryWork / newSecondaryWork
//    We treat FB‐blocks just like any Bitcoin‐type (SHA256) template.
Stratum::FbWork*
Stratum::newPrimaryWork(int64_t stratumId,
                        PoolBackend *backend,
                        size_t backendIdx,
                        const CMiningConfig &miningCfg,
                        const std::vector<uint8_t> &miningAddress,
                        const std::string &coinbaseMessage,
                        CBlockTemplate &blockTemplate,
                        std::string &error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB primary";
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
    return work->loadFromTemplate(blockTemplate, error) ? work
                                                        : (void(delete work), nullptr);
}

StratumSingleWork*
Stratum::newSecondaryWork(int64_t stratumId,
                          PoolBackend *backend,
                          size_t backendIdx,
                          const CMiningConfig &miningCfg,
                          const std::vector<uint8_t> &miningAddress,
                          const std::string &coinbaseMessage,
                          CBlockTemplate &blockTemplate,
                          std::string &error)
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
// 4) MergedWork constructor
//    We now call the existing StratumMergedWork constructor (which expects exactly primary + one “first secondary”).
//
Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *primaryWork,
                                std::vector<StratumSingleWork *> &second,
                                std::vector<int> &chainMap,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig &miningCfg)
  // ─── use the StratumMergedWork constructor that takes (stratumWorkId, primary, oneSecondary, miningCfg)
  : StratumMergedWork(
        stratumWorkId,
        primaryWork,
        (second.empty() ? nullptr : second[0]),
        miningCfg
    )
{
    size_t secCount = second.size();
    LOG_F(INFO,
          "[FB::MergedWork] starting: secCount=%zu, virtualHashesNum=%u",
          secCount, virtualHashesNum);

    if (secCount == 0 || virtualHashesNum == 0 || secCount > 128) {
        // nothing further if no secondaries or nonsensical count
        return;
    }

    // Copy each secondary’s header (we only store the pure FB::BlockHeader objects)
    FBHeaders_.resize(secCount);
    for (size_t i = 0; i < secCount; i++) {
        // cast each secondary pointer to an FBWork and copy its Header
        auto *fbw = static_cast<Stratum::FbWork *>(second[i]);
        FBHeaders_[i] = fbw->Header;
    }

    // Instead of building a full AuxPoW Merkle tree, we simply record one “dummy” hash per virtual index.
    // For each virtual index i, we store FBHeaders_[0].GetHash() (or any placeholder).
    // In a true AuxPoW scenario, you’d recompute a DoubleSHA256 of the child coinbase and build a Merkle branch etc.
    FBHeaderHashes_.assign(virtualHashesNum, FBHeaders_[0].GetHash());

    // We leave FBHeaderMerkle_, FBBranches_, FBProofs_ empty.
    // This satisfies the compiler, but does not produce a true AuxPoW Merkle path.
}

FB::Proto::BlockHashTy
Stratum::MergedWork::shareHash()
{
    return baseWork()->Header.GetHash();
}

std::string
Stratum::MergedWork::blockHash(size_t workIdx)
{
    if (workIdx == 0) {
        return baseWork()->Header.GetHash().ToString();
    } else if (workIdx - 1 < FBHeaders_.size()) {
        return FBHeaders_[workIdx - 1].GetHash().ToString();
    }
    return std::string();
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
    if (! BTC::Stratum::Work::prepareForSubmitImpl(
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

    // Validate each FB secondary “header” (dummy checkConsensus here).
    for (size_t i = 0; i < FBHeaders_.size(); i++) {
        CCheckStatus st =
            FB::Stratum::FbWork::checkConsensusImpl(
                FBHeaders_[i],
                FBConsensusCtx_
            );
        if (!st.IsBlock) {
            return false;
        }
    }
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
        return BTC::Stratum::Work::checkConsensusImpl(
                   BaseHeader_,
                   BaseConsensusCtx_
               );
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
// ─── EXPLICIT Io<T> SPECIALIZATION FOR FB::Proto::BlockHeader ─────────────
//
namespace BTC {

template<>
inline void Io<FB::Proto::BlockHeader>::serialize(xmstream &s,
                                                 const FB::Proto::BlockHeader &h)
{
    // 1) Serialize the “pure” six‐field header exactly as Bitcoin does:
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
