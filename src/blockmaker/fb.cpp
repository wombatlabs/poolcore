#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "poolcommon/arith_uint256.h"
#include "poolcommon/cryptoHash.h"    // for DoubleSHA256
#include "poolcommon/cryptoKey.h"     // for CCryptoKey
#include <loguru.hpp>

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

namespace FB {

//////////////////////////
// ─── FB::Stratum::buildChainMap ─────────────────────────────────────────────
// (exactly one “virtual‐hash” slot per secondary)
std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork *> &secondary,
                       uint32_t &nonce,
                       unsigned &virtualHashesNum)
{
    nonce = 0;
    virtualHashesNum = 1;

    std::vector<int> result(secondary.size(), 0);
    return result;
}

//////////////////////////
// ─── FB::Proto::checkConsensusInitialize & checkConsensus ───────────────────
// (no extra initialization needed; delegate to BTC for AuxPoW)
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
// ─── FB::Stratum::newPrimaryWork / newSecondaryWork ─────────────────────────
// (identical to other merged‐mining coins, just constructing FbWork)
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
    auto *work = new Stratum::FbWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    );

    return work->loadFromTemplate(blockTemplate, error)
             ? work
             : (delete work, nullptr);
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
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FB secondary";
        return nullptr;
    }

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
// ─── FB::Stratum::MergedWork::MergedWork ────────────────────────────────────
// (must call StratumMergedWork as base, then extract “base” BTC data,
//  build each FB coinbase with zero extra‐nonce, compute virtual header hashes,
//  build FB chain merkle root, rewrite BTC coinbase to embed AuxPoW,
//  then build FB merkle tree)
Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *primaryWork,
                                std::vector<StratumSingleWork *> &second,
                                std::vector<int> &chainMap,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig &miningCfg)
    : StratumMergedWork(stratumWorkId, primaryWork, second, miningCfg)
{
    // 1) Extract “base” BTC objects from primaryWork:
    auto *base = static_cast<BTC::Stratum::Work*>(Works_[0].Work);
    BaseHeader_       = base->Header;
    BaseMerklePath_   = base->MerklePath;
    BaseConsensusCtx_ = base->ConsensusCtx_;

    // 2) Prepare FB secondary arrays
    size_t secCount = second.size();
    LOG_F(INFO,
          "[FB::MergedWork] starting: secCount=%zu, virtualHashesNum=%u (no.name)",
          secCount, virtualHashesNum);

    if (secCount == 0 || virtualHashesNum == 0 || secCount > 128) {
        return;
    }

    LOG_F(INFO,
          "[FB::MergedWork] allocating FBHeaders_ for %zu sub-headers, FBHeaderHashes_ for %u leaves (no.name)",
          secCount, virtualHashesNum);

    FBHeaders_.resize(secCount);
    FBLegacy_.resize(secCount);
    FBWitness_.resize(secCount);
    FBHeaderHashes_.resize(virtualHashesNum, uint256());
    FBWorkMap_.assign(chainMap.begin(), chainMap.end());

    // Build a “zero‐extra‐nonce” coinbase/witness for each FB secondary
    for (size_t i = 0; i < secCount; ++i) {
        auto *work = static_cast<Stratum::FbWork *>(second[i]);
        FBHeaders_[i] = work->Header;

        // Use an empty‐extra‐nonce configuration here:
        CMiningConfig emptyCfg = miningCfg;
        emptyCfg.FixedExtraNonceSize   = 0;
        emptyCfg.MutableExtraNonceSize = 0;

        work->buildCoinbaseTx(
            nullptr,
            0,
            emptyCfg,
            FBLegacy_[i],
            FBWitness_[i]
        );
    }

    // 3) Compute each FB “virtual header hash”
    CCryptoKey sha;
    for (unsigned i = 0; i < virtualHashesNum; ++i) {
        int idx = FBWorkMap_[i];
        uint32_t randv = mmNonce;
        randv = randv * 1103515245 + 12345;
        randv += static_cast<uint32_t>(FBHeaders_[idx].nVersion >> 16);
        FBLegacy_[idx].nNonce = randv;
        FBHeaderHashes_[i] = sha.DoubleSHA256(FBLegacy_[idx]);
    }

    // 4) Build the FB chain merkle root (and reverse endianness)
    uint256 chainMerkleRoot = calculateMerkleRoot(
        &FBHeaderHashes_[0],
        FBHeaderHashes_.size()
    );
    std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

    // 5) Rewrite the BTC coinbase to embed AuxPoW header:
    {
        uint8_t buffer[1024];
        xmstream coinbaseMsg(buffer, sizeof(buffer));
        coinbaseMsg.reset();
        coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        coinbaseMsg.write(chainMerkleRoot.begin(), chainMerkleRoot.size());
        coinbaseMsg.write<uint32_t>(virtualHashesNum);
        coinbaseMsg.write<uint32_t>(mmNonce);

        base->buildCoinbaseTx(
            coinbaseMsg.data(),
            coinbaseMsg.sizeOf(),
            miningCfg,
            BaseLegacy_,
            BaseWitness_
        );
    }

    // Capture the FB consensus context from the first secondary (AuxPoW)
    FBConsensusCtx_ = fbWork(0)->ConsensusCtx_;

    // 6) Build FB merkle tree branches/proofs
    MerkleTree merkle;
    merkle.BuildTree(FBHeaderHashes_, FBHeaderMerkle_);
    merkle.BuildBranches(FBHeaderMerkle_, FBBranches_);
    merkle.BuildBranches(FBHeaderHashes_, FBProofs_);
}

// ─── FB::Stratum::MergedWork::shareHash ────────────────────────────────────────
FB::Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    return baseWork()->Header.GetHash();
}

// ─── FB::Stratum::MergedWork::blockHash ───────────────────────────────────────
std::string Stratum::MergedWork::blockHash(size_t workIdx) {
    if (workIdx == 0) {
        return baseWork()->Header.GetHash().ToString();
    } else if (workIdx - 1 < FBHeaders_.size()) {
        return FBHeaders_[workIdx - 1].GetHash().ToString();
    } else {
        return std::string();
    }
}

// ─── FB::Stratum::MergedWork::mutate ───────────────────────────────────────────
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

// ─── FB::Stratum::MergedWork::buildNotifyMessage ──────────────────────────────
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

// ─── FB::Stratum::MergedWork::prepareForSubmit ─────────────────────────────────
bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
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

    for (size_t i = 0; i < FBHeaders_.size(); ++i) {
        CCheckStatus st = Stratum::FbWork::checkConsensusImpl(
                             FBHeaders_[i],
                             FBConsensusCtx_
                         );
        if (!st.IsBlock) {
            return false;
        }
    }
    return true;
}

// ─── FB::Stratum::MergedWork::buildBlock ───────────────────────────────────────
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

// ─── FB::Stratum::MergedWork::checkConsensus ──────────────────────────────────
CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
    if (workIdx == 0 && baseWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(
                   BaseHeader_,
                   BaseConsensusCtx_
               );
    } else {
        auto *fw = fbWork(workIdx - 1);
        if (fw) {
            return Stratum::FbWork::checkConsensusImpl(
                       FBHeaders_[workIdx - 1],
                       BaseConsensusCtx_
                   );
        }
    }
    return CCheckStatus();
}

} // namespace FB

//
// ─── EXPLICIT Io<T> SPECIALIZATION FOR FB::Proto::BlockHeader ────────────────
namespace BTC {

template<>
inline void Io<FB::Proto::BlockHeader>::serialize(xmstream &s,
                                                 const FB::Proto::BlockHeader &h)
{
    // 1) Serialize the “pure” header exactly as BTC does:
    Io<FB::Proto::PureBlockHeader>::serialize(s, h);

    // 2) Then serialize all the AuxPoW fields:
    Io<FB::Proto::Transaction>::serialize(s, h.ParentBlockCoinbaseTx);
    Io<uint256>::serialize(s, h.HashBlock);
    Io<xvector<uint256>>::serialize(s, h.MerkleBranch);
    Io<int>::serialize(s, h.Index);
    Io<xvector<uint256>>::serialize(s, h.ChainMerkleBranch);
    Io<int>::serialize(s, h.ChainIndex);
    Io<FB::Proto::PureBlockHeader>::serialize(s, h.ParentBlock);
}

} // namespace BTC
