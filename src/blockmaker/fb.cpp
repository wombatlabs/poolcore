#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "poolcommon/arith_uint256.h"
#include <loguru.hpp>

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

namespace FB {

//////////////////////////
// ─── FB::Stratum::buildChainMap ─────────────────────────────────────────────
std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork *> &secondary,
                       uint32_t &nonce,
                       unsigned &virtualHashesNum)
{
    // Force exactly one "virtual hash" slot per secondary (slot 0)
    nonce = 0;
    virtualHashesNum = 1;

    std::vector<int> result;
    result.resize(secondary.size());
    std::fill(result.begin(), result.end(), 0);
    return result;
}

//////////////////////////
// 2) checkConsensusInitialize & checkConsensus – parallel to DOGE but calling BTC
void Proto::checkConsensusInitialize(CheckConsensusCtx &ctx) {
    // nothing to do
}

CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header,
                                   CheckConsensusCtx &ctx,
                                   Proto::ChainParams &chainParams)
{
    if (header.nVersion & BlockHeader::VERSION_AUXPOW) {
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
Stratum::FbWork* Stratum::newPrimaryWork(int64_t stratumId,
                                           PoolBackend *backend,
                                           size_t backendIdx,
                                           const CMiningConfig &miningCfg,
                                           const std::vector<uint8_t> &miningAddress,
                                           const std::string &coinbaseMessage,
                                           CBlockTemplate &blockTemplate,
                                           std::string &error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }
    auto *work = new Stratum::FbWork(stratumId,
                                       blockTemplate.UniqueWorkId,
                                       backend,
                                       backendIdx,
                                       miningCfg,
                                       miningAddress,
                                       coinbaseMessage);
    return work->loadFromTemplate(blockTemplate, error) ? work
                                                        : (void(delete work), nullptr);
}

StratumSingleWork* Stratum::newSecondaryWork(int64_t stratumId,
                                            PoolBackend* backend,
                                            size_t backendIdx,
                                            const CMiningConfig& miningCfg,
                                            const std::vector<uint8_t>& miningAddress,
                                            const std::string& coinbaseMessage,
                                            CBlockTemplate& blockTemplate,
                                            std::string& error)
{
    // FB’s block templates will always be SHA-256 work:
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB secondary";
        return nullptr;
    }

    // Exactly the same as newPrimaryWork(): construct a FbWork,
    // load it from the template, and return it (or delete+fail).
    auto* work = new Stratum::FbWork(
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
// 4) MergedWork constructor  virtual overrides
// ─── FB::Stratum::MergedWork::MergedWork ────────────────────────────────────
Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *primaryWork,
                                std::vector<StratumSingleWork *> &second,
                                std::vector<int> &chainMap,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig &miningCfg)
    : StratumSingleWork(stratumWorkId, primaryWork->ServerJobId_)
{
    size_t secCount = second.size();
    LOG_F(INFO, "[FB::MergedWork] starting: secCount=%zu, virtualHashesNum=%u (no.name)",
          secCount, virtualHashesNum);

    if (secCount == 0 || virtualHashesNum == 0 || secCount > 128) {
        return;
    }

    LOG_F(INFO, "[FB::MergedWork]  allocating FBHeaders_ for %zu sub-headers, FBHeaderHashes_ for %u leaves (no.name)",
          secCount, virtualHashesNum);

    FBHeaders_.resize(secCount);
    FBLegacy_.resize(secCount);
    FBWitness_.resize(secCount);
    FBHeaderHashes_.resize(virtualHashesNum, uint256());

    // Build Fractal/AuxPoW header set for each secondary:
    for (size_t i = 0; i < secCount; i++) {
        auto *work = static_cast<Stratum::FBWork *>(second[i]);
        FBHeaders_[i] = work->Header;
        FBLegacy_[i] = work->Legacy;
        FBWitness_[i] = work->Witness;
    }

    // Build Merkle tree of FB header hashes:
    CCryptoKey sha;
    for (unsigned i = 0; i < virtualHashesNum; i++) {
        // Each index: recompute hash based on mmNonce and index
        unsigned idx = i;
        uint32_t randv = static_cast<uint32_t>(mmNonce + idx);
        randv = randv * 1103515245 + 12345;
        randv += (FBHeaders_[0].nVersion >> 16);
        FBLegacy_[0].nNonce = randv;
        FBHeaderHashes_[i] = sha.DoubleSHA256(FBLegacy_[0]);
    }

    MerkleTree merkle;
    merkle.BuildTree(FBHeaderHashes_, FBHeaderMerkle_);
    merkle.BuildBranches(FBHeaderMerkle_, FBBranches_);
    merkle.BuildBranches(FBHeaderHashes_, FBProofs_);
}

FB::Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    return baseWork()->Header.GetHash();
}

std::string Stratum::MergedWork::blockHash(size_t workIdx) {
    if (workIdx == 0) {
        return baseWork()->Header.GetHash().ToString();
    } else if (workIdx - 1 < FBHeaders_.size()) {
        return FBHeaders_[workIdx - 1].GetHash().ToString();
    } else {
        return std::string();
    }
}

void Stratum::MergedWork::mutate() {
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

void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork) {
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

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
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

    for (size_t i = 0; i < FBHeaders_.size(); i++) {
        CCheckStatus st = FB::Stratum::FbWork::checkConsensusImpl(
                             FBHeaders_[i],
                             FBConsensusCtx_
                         );
        if (!st.IsBlock) {
            return false;
        }
    }
    return true;
}

void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
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

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
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

//
// 5) newMergedWork / miningConfigInitialize / workerConfigInitialize (already in header)
//    – no further definitions needed here in the cpp because they’re static inline.

} // namespace FB

//
// ─── EXPLICIT Io<T> SPECIALIZATION FOR FB::Proto::BlockHeader ─────────────
//
namespace BTC {

template<>
inline void Io<FB::Proto::BlockHeader>::serialize(xmstream &s, const FB::Proto::BlockHeader &h)
{
    // 1) Serialize the six-field “pure” header exactly as BTC does:
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
