// fb.cpp

#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

static unsigned merklePathSize(unsigned count)
{
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h)
{
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1u << h);
}

namespace FB {

std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                        uint32_t &nonce,
                                        unsigned &virtualHashesNum)
{
    std::vector<int> result(secondary.size());
    std::vector<int> chainMap;
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
                Stratum::FbWork *work = static_cast<Stratum::FbWork*>(secondary[workIdx]);
                uint32_t chainId = work->Header.nVersion >> 16;
                uint32_t indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);

                if (chainMap[indexInMerkle] == 0) {
                    chainMap[indexInMerkle] = 1;
                    result[workIdx] = static_cast<int>(indexInMerkle);
                } else {
                    finished = false;
                    break;
                }
            }

            if (finished) break;
        }

        if (finished) break;
    }

    return (finished ? result : std::vector<int>());
}

//------------------------------------------------------------------------------
// MergedWork
//------------------------------------------------------------------------------
Stratum::MergedWork::MergedWork(uint64_t                    stratumWorkId,
                                StratumSingleWork          *first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int>           &mmChainId,
                                uint32_t                    mmNonce,
                                unsigned                    virtualHashesNum,
                                const CMiningConfig        &miningCfg)
  : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // 1) Capture primary (BTC) header, Merkle path, and consensus context.
    BTCHeader_       = btcWork()->Header;
    BTCMerklePath_   = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

    // 2) Resize FB vectors
    FBHeader_.resize(second.size());
    FBLegacy_.resize(second.size());
    FBWitness_.resize(second.size());
    FBHeaderHashes_.resize(virtualHashesNum, uint256());
    FBWorkMap_.assign(mmChainId.begin(), mmChainId.end());
    fbRoot_.resize(second.size());
    fbMerklePaths_.reserve(virtualHashesNum);

    // 3) Pull each secondary FB work’s coinbase Tx and Merkle path
    for (size_t i = 0; i < second.size(); i++) {
        Stratum::FbWork *fw = static_cast<Stratum::FbWork*>(second[i]);

        // Move legacy & witness coinbase Tx out of the secondary work
        FBLegacy_[i]  = std::move(fw->CBTxLegacy_);
        FBWitness_[i] = std::move(fw->CBTxWitness_);

        // Copy the Merkle path from this FB work
        fbMerklePaths_.push_back(fw->MerklePath);

        // Record the “root node” for each FB chain if needed
        fbRoot_[i] = fw->RootNode_;
    }

    // 4) Build each FB header’s static fields and compute its Merkle root
    for (size_t idx = 0; idx < FBHeader_.size(); idx++) {
        Stratum::FbWork *fw = fbWork(idx);
        Proto::BlockHeader &header = FBHeader_[idx];
        BTC::CoinbaseTx     &legacy = FBLegacy_[idx];
        BTC::CoinbaseTx     &witness = FBWitness_[idx];

        // Start from the FB work’s template header
        header = fw->Header;

        // Prepare “static” FB coinbase (no extra‐nonce) so we can calculate Merkle root
        CMiningConfig emptyCfg = miningCfg;
        emptyCfg.FixedExtraNonceSize   = 0;
        emptyCfg.MutableExtraNonceSize = 0;
        fw->buildCoinbaseTx(nullptr, 0, emptyCfg, legacy, witness);

        // Mark as AuxPoW
        header.nVersion |= Proto::BlockHeader::VERSION_AUXPOW;

        // Calculate the FB coinbase Tx hash (double‐SHA256)
        uint256 coinbaseHash;
        CCtxSha256 sha;
        sha256Init(&sha);
        sha256Update(&sha, legacy.Data.data(), legacy.Data.sizeOf());
        sha256Final(&sha, coinbaseHash.begin());
        sha256Init(&sha);
        sha256Update(&sha, coinbaseHash.begin(), coinbaseHash.size());
        sha256Final(&sha, coinbaseHash.begin());

        // Build FB merkle root using that coinbase hash + this work’s MerklePath
        const std::vector<uint256> &path = fbMerklePaths_[idx];
        header.hashMerkleRoot = calculateMerkleRootWithPath(
            coinbaseHash,
            (path.empty() ? nullptr : &path[0]),
            path.size(),
            static_cast<unsigned>(FBWorkMap_[idx])
        );

        // Store the final FB header hash into fbHeaderHashes_
        FBHeaderHashes_[ FBWorkMap_[idx] ] = header.GetHash();
    }

    // 5) Compute “chain‐merkle‐root” over all FBHeaderHashes_
    {
        uint256 chainMerkleRoot = calculateMerkleRoot(
            FBHeaderHashes_.data(),
            FBHeaderHashes_.size()
        );
        std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

        // 6) Build merged‐mining coinbase for the BTC primary:
        uint8_t buffer[1024];
        xmstream coinbaseMsg(buffer, sizeof(buffer));
        coinbaseMsg.reset();
        coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
        coinbaseMsg.write<uint32_t>(virtualHashesNum);
        coinbaseMsg.write<uint32_t>(mmNonce);

        // Overwrite the primary BTC coinbase by calling its buildCoinbaseTx:
        btcWork()->buildCoinbaseTx(
            coinbaseMsg.data(),
            coinbaseMsg.sizeOf(),
            miningCfg,
            BTCLegacy_,
            BTCWitness_
        );
    }

    // 7) Finally, record the FB consensus context from the first FB work
    if (!second.empty()) {
        fbConsensusCtx_ = fbWork(0)->ConsensusCtx_;
    }
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                           const CStratumMessage &msg)
{
    // 1) Let BTC primary work do its prepareForSubmit first
    if (!btcWork()->prepareForSubmitImpl(
            BTCHeader_,
            BTCLegacy_,
            BTCWitness_,
            BTCMerklePath_,
            workerCfg,
            MiningCfg_,
            msg))
    {
        return false;
    }

    // 2) Now patch in each FB auxiliary header’s AuxPoW fields and verify FB POW
    for (size_t idx = 0; idx < FBHeader_.size(); idx++) {
        // a) Deserialize ParentBlockCoinbaseTx out of BTCWitness_ stream
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, FBHeader_[idx].ParentBlockCoinbaseTx);

        // b) Zero out FB HashBlock & Index for AuxPoW verification
        FBHeader_[idx].HashBlock.SetNull();
        FBHeader_[idx].Index = 0;

        // c) Copy BTC merkle branches into FB header’s MerkleBranch
        FBHeader_[idx].MerkleBranch.resize(BTCMerklePath_.size());
        for (size_t j = 0; j < BTCMerklePath_.size(); j++) {
            FBHeader_[idx].MerkleBranch[j] = BTCMerklePath_[j];
        }

        // d) Rebuild the FB chain‐merkle branch for this index
        std::vector<uint256> path;
        buildMerklePath(
            FBHeaderHashes_.data(),
            FBHeaderHashes_.size(),
            FBWorkMap_[idx],
            path
        );
        FBHeader_[idx].ChainMerkleBranch.resize(path.size());
        for (size_t j = 0; j < path.size(); j++) {
            FBHeader_[idx].ChainMerkleBranch[j] = path[j];
        }
        FBHeader_[idx].ChainIndex = FBWorkMap_[idx];
        FBHeader_[idx].ParentBlock = BTCHeader_;

        // e) Perform FB consensus check (AuxPoW validation)
        CCheckStatus status = Proto::checkConsensus(
            FBHeader_[idx],
            fbConsensusCtx_,
            fbChainParams_
        );
        if (!status.IsBlock) {
            return false;
        }
    }

    return true;
}

double Stratum::MergedWork::expectedWork(size_t workIdx)
{
    if (workIdx == 0) {
        // Primary BTC’s expected work
        return BTC::Stratum::Work::expectedWork(BTCHeader_, BTCConsensusCtx_);
    } else {
        // FB’s expected work (AuxPoW)
        return FB::Stratum::FbWork::expectedWork(
            FBHeader_[workIdx - 1],
            fbConsensusCtx_
        );
    }
}

void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
    if (workIdx == 0 && btcWork()) {
        // Primary BTC block (serialized by BTC code)
        btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
    } else {
        // FB merged block
        size_t idx = workIdx - 1;
        fbWork(idx)->buildBlockImpl(
            FBHeader_[idx],
            FBWitness_[idx],
            blockHexData
        );
    }
}

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx)
{
    if (workIdx == 0 && btcWork()) {
        // Verify primary BTC block
        return BTC::Stratum::Work::checkConsensusImpl(
            BTCHeader_,
            BTCConsensusCtx_
        );
    } else {
        // Verify FB merged block
        size_t idx = workIdx - 1;
        return FB::Stratum::FbWork::checkConsensusImpl(
            FBHeader_[idx],
            fbConsensusCtx_
        );
    }
}

//------------------------------------------------------------------------------
// Downcast helpers
Stratum::Work* Stratum::btcWork()
{
    return static_cast<Work*>(Works_[0].Work);
}

Stratum::FbWork* Stratum::fbWork(unsigned index)
{
    // The first FB work is stored at Works_[1], second at Works_[2], etc.
    return static_cast<FbWork*>(Works_[index + 1].Work);
}

//------------------------------------------------------------------------------
// newPrimaryWork: identical pattern to DOGE/LTC, but using BTC::Work
Stratum::Work* Stratum::newPrimaryWork(int64_t                    stratumId,
                                       PoolBackend               *backend,
                                       size_t                     backendIdx,
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
    std::unique_ptr<Work> w(new Work(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    ));
    return w->loadFromTemplate(blockTemplate, error) ? w.release() : nullptr;
}

//------------------------------------------------------------------------------
// newSecondaryWork: each FB work is built from a BTC-style template
StratumSingleWork* Stratum::newSecondaryWork(int64_t                    stratumId,
                                             PoolBackend               *backend,
                                             size_t                     backendIdx,
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
    std::unique_ptr<FbWork> w(new FbWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    ));
    return w->loadFromTemplate(blockTemplate, error) ? w.release() : nullptr;
}

//------------------------------------------------------------------------------
// newMergedWork: must build chainMap before constructing MergedWork
StratumMergedWork* Stratum::newMergedWork(int64_t                    stratumId,
                                          StratumSingleWork         *first,
                                          std::vector<StratumSingleWork*> &second,
                                          const CMiningConfig       &miningCfg,
                                          std::string               &error)
{
    if (second.empty()) {
        error = "no secondary works";
        return nullptr;
    }

    uint32_t nonce    = 0;
    unsigned virtualHashesNum = 0;
    std::vector<int> chainMap = buildChainMap(second, nonce, virtualHashesNum);
    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }
    return new MergedWork(
        stratumId,
        first,
        second,
        chainMap,
        nonce,
        virtualHashesNum,
        miningCfg
    );
}

//------------------------------------------------------------------------------
// buildSendTargetMessage: identical to DOGE but FB uses its own DifficultyFactor
void Stratum::buildSendTargetMessage(xmstream &stream, double shareDiff)
{
    BTC::Stratum::buildSendTargetMessageImpl(stream, shareDiff, DifficultyFactor);
}

//------------------------------------------------------------------------------
// Io<FB::Proto::BlockHeader> specialization
void BTC::Io<FB::Proto::BlockHeader>::serialize(xmstream              &dst,
                                               const FB::Proto::BlockHeader &data)
{
    // First serialize the “pure” header (80-byte)
    BTC::serialize(dst, static_cast<const FB::Proto::PureBlockHeader&>(data));

    // If AuxPoW flag is set, serialize additional fields:
    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        BTC::serialize(dst, data.ParentBlockCoinbaseTx);
        BTC::serialize(dst, data.HashBlock);
        BTC::serialize(dst, data.MerkleBranch);
        BTC::serialize(dst, data.Index);
        BTC::serialize(dst, data.ChainMerkleBranch);
        BTC::serialize(dst, data.ChainIndex);
        BTC::serialize(dst, data.ParentBlock);
    }
}

void BTC::Io<FB::Proto::BlockHeader>::unserialize(xmstream         &src,
                                                 FB::Proto::BlockHeader &data)
{
    // First unserialize the “pure” header
    BTC::unserialize(src, static_cast<FB::Proto::PureBlockHeader&>(data));

    // If AuxPoW flag is set, unserialize additional fields:
    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        BTC::unserialize(src, data.ParentBlockCoinbaseTx);
        BTC::unserialize(src, data.HashBlock);
        BTC::unserialize(src, data.MerkleBranch);
        BTC::unserialize(src, data.Index);
        BTC::unserialize(src, data.ChainMerkleBranch);
        BTC::unserialize(src, data.ChainIndex);
        BTC::unserialize(src, data.ParentBlock);
    }
}

} // namespace FB