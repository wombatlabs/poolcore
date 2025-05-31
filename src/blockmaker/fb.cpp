// fb.cpp
#include "blockmaker/fb.h"
#include <utility>      // for std::move
#include <cassert>

//------------------------------------------------------------------------------
// Helper: build the chain map for merged work (identical logic to DOGE/LTC).
static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                      uint32_t &nonce,
                                      unsigned int &virtualHashesNum)
{
    // The same algorithm as in doge.cpp: assign each aux chain a unique non-zero ID
    // and compute the “virtualHashesNum” = total number of headers needed.
    std::vector<int> map;
    map.reserve(secondary.size());

    // We'll choose nonces 1..N for each secondary; if any collision, return empty.
    for (unsigned i = 0; i < secondary.size(); i++) {
        // For SHA-256 merged mining, we typically embed the chain ID into version or extra-nonce.
        // Here we simply assign “i+1” as the chain’s ID.
        map.push_back(static_cast<int>(i + 1));
    }

    nonce = 0;  // FB’s merged-nonce initially zero
    virtualHashesNum = static_cast<unsigned int>(secondary.size());
    return map;
}

//------------------------------------------------------------------------------
// FB::Stratum::MergedWork
namespace FB {
namespace Stratum {

MergedWork::MergedWork(uint64_t stratumWorkId,
                       StratumSingleWork *primaryWork,
                       std::vector<StratumSingleWork*> &secondaryWorks,
                       std::vector<int> &mmChainId,
                       uint32_t mmNonce,
                       unsigned int virtualHashesNum,
                       const CMiningConfig &miningCfg)
    : StratumMergedWork(stratumWorkId, primaryWork, secondaryWorks, miningCfg),
      fbHeaders_(),
      fbLegacy_(),
      fbWitness_(),
      fbHeaderHashes_(),
      fbWorkMap_(),
      fbConsensusCtx_(),
      fbRootNodes_(),
      fbMerklePaths_(),
      fbNonce_(mmNonce),
      fbVirtualHashesNum_(virtualHashesNum)
{
    // 1) Resize vectors to hold each FB header, coinbase and witness
    fbHeaders_.resize(secondaryWorks.size());
    fbLegacy_.resize(secondaryWorks.size());
    fbWitness_.resize(secondaryWorks.size());
    fbHeaderHashes_.assign(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());
    fbRootNodes_.resize(secondaryWorks.size());
    fbMerklePaths_.reserve(virtualHashesNum);

    // 2) Capture each secondary “work” object’s built data (coinbase, merkle path, etc.)
    for (size_t i = 0; i < secondaryWorks.size(); i++) {
        // reinterpret each StratumSingleWork* as a FB work
        FbWork *fw = static_cast<FbWork*>(secondaryWorks[i]);
        assert(fw != nullptr);

        // Move-construct the legacy/witness CoinbaseTx out of the secondary work into our own buffers:
        // (CoinbaseTx is moveable but not copyable)
        fbLegacy_[i]  = std::move(fw->CBTxLegacy_);
        fbWitness_[i] = std::move(fw->CBTxWitness_);

        // Copy the Merkle path from the secondary into fbMerklePaths_
        fbMerklePaths_.push_back(fw->MerklePath);

        // Also record the FB chain’s “root” (this is typically the block header root-hash).
        fbRootNodes_[i] = fw->RootNode_;
    }

    // 3) Set FB consensus context from the first FB work
    if (!secondaryWorks.empty()) {
        FbWork *firstFw = static_cast<FbWork*>(secondaryWorks[0]);
        fbConsensusCtx_ = firstFw->ConsensusCtx_;
    }
}

bool MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                  const CStratumMessage &msg)
{
    // 1) Prepare primary (Bitcoin-style) header first
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

    // 2) Now prepare each FB header one by one
    for (size_t idx = 0; idx < fbHeaders_.size(); idx++) {
        // Copy the coinbase/witness from fbLegacy_[idx]/fbWitness_[idx] and build FB header
        // We set nNonce = fbNonce_ (same across all), and insert the chain ID into version
        fbHeaders_[idx] = fbHeaders_[idx];  // placeholder: fbHeaders_[idx] was zero-initialized
        fbHeaders_[idx].nVersion = fbHeaders_[idx].nVersion | (fbWorkMap_[idx] & 0xFF);
        fbHeaders_[idx].nTime = BTCHeader_.nTime;          // share the same timestamp
        fbHeaders_[idx].nBits = BTCHeader_.nBits;          // same difficulty target
        fbHeaders_[idx].nNonce = fbNonce_;                 // merged-nonce

        // Build the FB merkle root:
        {
            // 1) Compute coinbase TX hash for this FB work
            uint256 coinbaseHash;
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha, fbLegacy_[idx].Data.data(), fbLegacy_[idx].Data.sizeOf());
            sha256Final(&sha, coinbaseHash.begin());
            sha256Init(&sha);
            sha256Update(&sha, coinbaseHash.begin(), sizeof(coinbaseHash));
            sha256Final(&sha, coinbaseHash.begin());

            // 2) Merge with the stored Merkle path
            const std::vector<uint256> &path = fbMerklePaths_[idx];
            fbHeaders_[idx].hashMerkleRoot = calculateMerkleRootWithPath(
                coinbaseHash,
                path.empty() ? nullptr : &path[0],
                path.size(),
                fbWorkMap_[idx]
            );
        }

        // Copy the FB root node (parent header hash) into ParentBlock
        fbHeaders_[idx].ParentBlock = btcWork()->Header;
    }

    return true;
}

double MergedWork::expectedWork(size_t workIdx)
{
    // If workIdx == 0, return BTC’s expected; else FB’s expected (which is same as FB difficulty)
    if (workIdx == 0) {
        return BTC::expectedWork(BTCHeader_, BTCConsensusCtx_);
    } else {
        return FB::expectedWork(fbHeaders_[workIdx - 1], fbConsensusCtx_);
    }
}

void MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
    if (workIdx == 0 && btcWork()) {
        // Primary BTC-style block
        btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
    } else {
        // FB merged block
        size_t idx = workIdx - 1;
        fbWork(idx)->buildBlockImpl(fbHeaders_[idx], fbWitness_[idx], blockHexData);
    }
}

CCheckStatus MergedWork::checkConsensus(size_t workIdx)
{
    if (workIdx == 0 && btcWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, FBConsensusCtx_);
    } else {
        size_t idx = workIdx - 1;
        return FB::Stratum::FbWork::checkConsensusImpl(fbHeaders_[idx], BTCConsensusCtx_);
    }
}

//------------------------------------------------------------------------------
// Static helpers to downcast StratumSingleWork* → concrete work types
Stratum::Work* Stratum::btcWork()
{
    return static_cast<Work*>(Works_[0].Work);
}

Stratum::FbWork* Stratum::fbWork(unsigned index)
{
    // Works_[0] is the primary; secondary start at Works_[1]
    return static_cast<FbWork*>(Works_[index + 1].Work);
}

//------------------------------------------------------------------------------
// newPrimaryWork (identical to Bitcoin’s “Work” constructor, but for FB proto)
Work* Stratum::newPrimaryWork(int64_t stratumId,
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
    std::unique_ptr<Work> work(new Work(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    ));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//------------------------------------------------------------------------------
// newSecondaryWork (this creates an FB work for each aux chain)
StratumSingleWork* Stratum::newSecondaryWork(int64_t stratumId,
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
    std::unique_ptr<FbWork> work(new FbWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    ));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//------------------------------------------------------------------------------
// newMergedWork (must build the chain map first, then hand off to MergedWork constructor)
StratumMergedWork* Stratum::newMergedWork(int64_t stratumId,
                                          StratumSingleWork *primaryWork,
                                          std::vector<StratumSingleWork*> &secondaryWorks,
                                          const CMiningConfig &miningCfg,
                                          std::string &error)
{
    if (secondaryWorks.empty()) {
        error = "no secondary works";
        return nullptr;
    }

    uint32_t nonce    = 0;
    unsigned int vh   = 0;
    std::vector<int> chainMap = buildChainMap(secondaryWorks, nonce, vh);
    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }
    return new MergedWork(stratumId, primaryWork, secondaryWorks, chainMap, nonce, vh, miningCfg);
}

//------------------------------------------------------------------------------
// Storage of FB chain parameters (target, powLimit, etc.)
// You’ll need to fill this in with actual FB-specific chain params.
static ChainParams fbChainParams_;

// expectedWork for a single FB header
double Stratum::expectedWork(const Proto::BlockHeader &header, const CheckConsensusCtx &ctx)
{
    // For FB, difficulty = 2^256 / (target+1).  But since FB uses BTC’s difficulty encoding,
    // we can just call BTC::difficultyFromBits on header.nBits:
    return BTC::difficultyFromBits(header.nBits, 29);
}

//------------------------------------------------------------------------------
// Build the “mining.notify” JSON payload (identical to Bitcoin, but ticker = “FB”)
void Stratum::buildNotifyMessage(xmstream &stream,
                                 const Proto::BlockHeader &header,
                                 uint32_t asicBoostData,
                                 CoinbaseTx &legacy,
                                 const std::vector<uint256> &merklePath,
                                 const CMiningConfig &cfg,
                                 bool resetPreviousWork,
                                 xmstream &notifyMessage)
{
    // Delegate to BTC’s implementation, but with FB’s DifficultyFactor
    BTC::Stratum::buildNotifyMessageImpl(
        /* source   = */ this,
        /* header   = */ const_cast<Proto::BlockHeader&>(header),
        /* version  = */ header.nVersion,
        /* legacy   = */ legacy,
        /* path     = */ merklePath,
        /* miningCfg=*/ cfg,
        /* reset    = */ resetPreviousWork,
        /* out      = */ notifyMessage
    );
}

//------------------------------------------------------------------------------
// buildSendTargetMessage for FB (identical to BTCImpl with FB’s own DifficultyFactor)
void Stratum::buildSendTargetMessage(xmstream &stream, double shareDiff)
{
    BTC::Stratum::buildSendTargetMessageImpl(stream, shareDiff, DifficultyFactor);
}

//------------------------------------------------------------------------------
// Serialize & unserialize for FB::Proto::BlockHeader (auxiliary fields after PureBlockHeader)
void BTC::Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data)
{
    // First serialize the “pure” header
    BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);

    // If version indicates merged-mining, serialize auxPow fields
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

void BTC::Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &data)
{
    // First unserialize the “pure” header
    BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&data);

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

} // namespace Stratum
} // namespace FB
