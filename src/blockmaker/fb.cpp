// fb.cpp
// Support for SHA256 merged mining of “Fractal Bitcoin” (FB)
// Based on doge.cpp structure but adapted to FB (ticker “FB”)

#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

// Determine the size of the merkle-path tree (h = log2(numSecondaries))
static unsigned merklePathSize(unsigned count)
{
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

// Pseudorandomly select an index in the “virtual” FB merkle tree,
// given a nonce, the chain ID, and the tree height h.
static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h)
{
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1u << h);
}

namespace FB {

//
// buildChainMap
//
// Build a “map” from each secondary FB work to a unique index in the
// merged mining tree. We try successive nonces until each secondary’s
// chain ID “falls” into a distinct slot in a virtual tree of size 2^h,
// where h grows until we find a valid assignment, or give up if h > 7.
//
std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondary,
    uint32_t &nonce,
    unsigned &virtualHashesNum)
{
    std::vector<int> result;
    result.resize(secondary.size());

    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        std::vector<int> chainMap(virtualHashesNum, -1);
        bool finished = false;

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), -1);

            for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
                FB::Stratum::FbWork *work = static_cast<FB::Stratum::FbWork*>(secondary[workIdx]);
                uint32_t chainId = (work->Header.nVersion) >> 16;
                uint32_t idx = getExpectedIndex(nonce, static_cast<int>(chainId), pathSize);

                if (chainMap[idx] < 0) {
                    chainMap[idx] = static_cast<int>(workIdx);
                    result[workIdx] = static_cast<int>(idx);
                } else {
                    finished = false;
                    break;
                }
            }

            if (finished)
                break;
        }

        if (finished)
            return result;
    }

    return std::vector<int>();
}

//
// MergedWork constructor
//
Stratum::MergedWork::MergedWork(
    uint64_t stratumWorkId,
    StratumSingleWork *first,
    std::vector<StratumSingleWork*> &second,
    std::vector<int> &mmChainId,
    uint32_t mmNonce,
    unsigned int virtualHashesNum,
    const CMiningConfig &miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // “Primary” work is always standard BTC work; record its data:
    BTCHeader_       = btcWork()->Header;
    BTCMerklePath_   = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

    // Resize FB vectors to match number of secondaries
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    // Build an array of “virtual” header hashes for FB,
    // size = 2^virtualHashesNum, initially all zero
    fbHeaderHashes_.assign(static_cast<size_t>(virtualHashesNum), uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // For each FB secondary, copy its header, merkle path, and consensus ctx
    for (size_t workIdx = 0; workIdx < second.size(); workIdx++) {
        FB::Stratum::FbWork *fw = static_cast<FB::Stratum::FbWork*>(second[workIdx]);
        fbHeaders_[workIdx]       = fw->Header;
        fbLegacy_[workIdx]        = fw->CBTxLegacy_;
        fbWitness_[workIdx]       = fw->CBTxWitness_;
        fbMerklePaths_.push_back(fw->MerklePath);
        fbConsensusCtx_.push_back(fw->ConsensusCtx_);
    }

    // Remember chain‐mapping parameters
    fbNonce_           = mmNonce;
    fbVirtualHashesNum = virtualHashesNum;
}

//
// shareHash()
//
FB::Proto::BlockHashTy Stratum::MergedWork::shareHash()
{
    // For merged mining, workers actually submit shares based on FB’s header
    return fbHeaders_[0].GetHash();
}

//
// blockHash(workIdx)
//
// Returns hex string of the block hash for primary (idx=0 → BTC) or
// any of the FB secondaries (idx ≥1 → FB). If idx≥1, offset by one.
std::string Stratum::MergedWork::blockHash(size_t workIdx)
{
    if (workIdx == 0)
        return BTCHeader_.GetHash().ToString();
    else if (workIdx - 1 < fbHeaders_.size())
        return fbHeaders_[workIdx - 1].GetHash().ToString();
    else
        return std::string();
}

//
// expectedWork(workIdx)
//
// Merge the expected work: primary (idx=0) uses BTC’s difficulty;
// secondaries (FB) use FB’s difficulty (same as BTC’s difficultyFromBits).
double Stratum::MergedWork::expectedWork(size_t workIdx)
{
    if (workIdx == 0)
        return BTC::difficultyFromBits(BTCHeader_.nBits, 29);
    else
        return BTC::difficultyFromBits(fbHeaders_[workIdx - 1].nBits, 29);
}

//
// prepareForSubmit
//  
// Build a correct “submit” payload by filling in asicBoost bits, coinbase,
// merkle paths, etc. for BTC first, then FB secondaries.
//
bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg)
{
    // 1) Build primary BTC data
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
            BTCHeader_,
            JobVersion_,
            CBTxLegacy_,
            CBTxWitness_,
            BTCMerklePath_,
            workerCfg,
            this->MiningCfg_,
            msg))
    {
        return false;
    }

    // 2) Build FB merkle root(s) for secondaries, given nonce+chainMap
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        // Fill the FB header’s nonce field so its GetHash() matches share
        fbHeaders_[workIdx].nNonce = fbNonce_;

        // Compute FB Merkle root for this workIdx:
        std::vector<uint256> path;
        buildMerklePath(fbHeaderHashes_, fbWorkMap_[workIdx], path);
        if (!FB::Stratum::HeaderBuilder::build(
                fbHeaders_[workIdx],
                nullptr,
                fbLegacy_[workIdx],
                path,
                fbRootNodes_[workIdx]))
        {
            return false;
        }
    }

    // 3) Finally, call FB::Prepare::prepare on secondaries
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        if (!FB::Stratum::Prepare::prepare(
                fbHeaders_[workIdx],
                0,                     // no asicBoost for FB
                fbLegacy_[workIdx],
                fbWitness_[workIdx],
                fbMerklePaths_[workIdx],
                workerCfg,
                this->MiningCfg_,
                msg))
        {
            return false;
        }
    }

    return true;
}

//
// newMergedWork
//
// Create a new merged work object, given one primary (BTC) and N secondaries (FB).
// Returns nullptr + error if something goes wrong (e.g. no secondaries).
//
StratumMergedWork* Stratum::newMergedWork(
    int64_t stratumId,
    StratumSingleWork *primaryWork,
    std::vector<StratumSingleWork*> &secondaryWorks,
    const CMiningConfig &miningCfg,
    std::string &error
) {
    if (secondaryWorks.empty()) {
        error = "no secondary works";
        return nullptr;
    }

    // 1) Build chainMap (vector of indices) and find nonce + virtualHashesNum
    uint32_t nonce = 0;
    unsigned virtualHashesNum = 0;
    std::vector<int> chainMap = buildChainMap(secondaryWorks, nonce, virtualHashesNum);

    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }

    // 2) Create the MergedWork object
    return new MergedWork(
        static_cast<uint64_t>(stratumId),
        primaryWork,
        secondaryWorks,
        chainMap,
        nonce,
        virtualHashesNum,
        miningCfg
    );
}

//
// buildSendTargetMessage
//
// FB’s difficulty factor is the same as BTC’s (65536). reuse the BTC impl.
//
void Stratum::buildSendTargetMessage(xmstream &stream, double difficulty)
{
    BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor);
}

//
// Helper: cast StratumSingleWork* → actual BTC::Stratum::Work*
//
BTC::Stratum::Work* Stratum::btcWork()
{
    return static_cast<BTC::Stratum::Work*>(FirstWork_);
}

//
// Helper: cast StratumSingleWork* → actual FB::Stratum::FbWork*
//
Stratum::FbWork* Stratum::fbWork(unsigned index)
{
    return static_cast<Stratum::FbWork*>(SecondaryWorks_[index]);
}

//
// newPrimaryWork
//
// Create a new primary “FB” work slot, but actually this is BTC work in
// merged context (primary is always BTC for FB merged mining). In fb.h,
// this function is declared to return BTC::Stratum::Work*.
//
BTC::Stratum::Work* Stratum::newPrimaryWork(
    int64_t stratumId,
    PoolBackend *backend,
    size_t backendIdx,
    const CMiningConfig &miningCfg,
    const std::vector<uint8_t> &miningAddress,
    const std::string &coinbaseMessage,
    CBlockTemplate &blockTemplate,
    std::string &error
) {
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }

    std::unique_ptr<BTC::Stratum::Work> work(
        new BTC::Stratum::Work(
            stratumId,
            blockTemplate.UniqueWorkId,
            backend,
            backendIdx,
            miningCfg,
            miningAddress,
            coinbaseMessage
        )
    );

    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//
// newSecondaryWork
//
// Create a new FB::Stratum::FbWork (secondary). This will be used for
// each FB backend in the merged mining pool. It inherits from
// BTC::WorkTy<FB::Proto,…> under the hood.
//
Stratum::FbWork* Stratum::newSecondaryWork(
    int64_t stratumId,
    PoolBackend *backend,
    size_t backendIdx,
    const CMiningConfig &miningCfg,
    const std::vector<uint8_t> &miningAddress,
    const std::string &coinbaseMessage,
    CBlockTemplate &blockTemplate,
    std::string &error
) {
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }

    std::unique_ptr<FbWork> work(
        new FbWork(
            stratumId,
            blockTemplate.UniqueWorkId,
            backend,
            backendIdx,
            miningCfg,
            miningAddress,
            coinbaseMessage
        )
    );

    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//
// Io<FB::Proto::BlockHeader>::serialize / unserialize
//
// These must be defined in the global namespace of BTC::Io as specializations.
// They mirror doge’s implementation but wrap PureBlockHeader → FB::Proto::BlockHeader.
//
namespace BTC {
    template<>
    void Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data)
    {
        // First serialize the “parent” (PureBlockHeader) fields
        serialize(dst, data.nVersion);
        serialize(dst, data.hashPrevBlock);
        serialize(dst, data.hashMerkleRoot);
        serialize(dst, data.nTime);
        serialize(dst, data.nBits);
        serialize(dst, data.nNonce);

        // Then serialize FB‐specific auxpow fields
        serialize(dst, data.ParentBlockCoinbaseTx);
        serialize(dst, data.HashBlock);
        serialize(dst, data.MerkleBranch);
        serialize(dst, data.Index);
        serialize(dst, data.ChainMerkleBranch);
        serialize(dst, data.ChainIndex);
        serialize(dst, data.ParentBlock);
    }

    template<>
    void Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &data)
    {
        // First read PureBlockHeader
        unserialize(src, data.nVersion);
        unserialize(src, data.hashPrevBlock);
        unserialize(src, data.hashMerkleRoot);
        unserialize(src, data.nTime);
        unserialize(src, data.nBits);
        unserialize(src, data.nNonce);

        // Now read FB‐specific auxpow fields
        unserialize(src, data.ParentBlockCoinbaseTx);
        unserialize(src, data.HashBlock);
        unserialize(src, data.MerkleBranch);
        unserialize(src, data.Index);
        unserialize(src, data.ChainMerkleBranch);
        unserialize(src, data.ChainIndex);
        unserialize(src, data.ParentBlock);
    }
} // namespace BTC

} // namespace FB
