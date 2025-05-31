#include "blockmaker/fb.h"
#include "poolinstances/stratumWorkStorage.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

static const unsigned char pchMergedMiningHeader[4] = {0xfa, 0xbe, 'm', 'm'};

namespace FB {
namespace Stratum {

//--------------------------------------------------------------
// buildChainMap: identical logic to doge.cpp, but using FB::Stratum::FbWork
//--------------------------------------------------------------
static std::vector<int> buildChainMap(std::vector<StratumSingleWork*>& secondary,
                                      uint32_t& mmNonce,
                                      unsigned int& virtualHashesNum)
{
    std::vector<int> chainIds;
    // Extract chain IDs from each FB work
    for (auto* w : secondary) {
        auto* fw = static_cast<FB::Stratum::FbWork*>(w->Work);
        chainIds.push_back(fw->ConsensusCtx_.chainId);
    }
    // Determine unique chain IDs
    std::vector<int> uniqueChainIds = chainIds;
    std::sort(uniqueChainIds.begin(), uniqueChainIds.end());
    uniqueChainIds.erase(std::unique(uniqueChainIds.begin(), uniqueChainIds.end()), uniqueChainIds.end());
    if (uniqueChainIds.size() != 1) {
        // Only one chain ID is supported for FB merged mining
        return {};
    }

    // virtualHashesNum = number of secondary works
    virtualHashesNum = static_cast<unsigned int>(secondary.size());
    // mmNonce can be arbitrary; FB does not use a special nonce for merged mining
    mmNonce = 0;

    return chainIds;
}

//--------------------------------------------------------------
// class MergedWork implementation (mirrors doge.cpp but swaps LTC ↔ BTC, DOGE ↔ FB)
//--------------------------------------------------------------
class MergedWork : public StratumMergedWork {
public:
    MergedWork(uint64_t stratumWorkId,
               StratumSingleWork* first,
               std::vector<StratumSingleWork*>& second,
               std::vector<int>& mmChainId,
               uint32_t mmNonce,
               unsigned int virtualHashesNum,
               const CMiningConfig& miningCfg)
        : StratumMergedWork(stratumWorkId, first, second, mmChainId, mmNonce, virtualHashesNum, miningCfg)
    {
        // Primary = BTC work
        auto* bw = static_cast<BTC::Stratum::Work*>(first->Work);
        BTCHeader_       = bw->Header;
        BTCLegacy_       = bw->CBTxLegacy_;
        BTCWitness_      = bw->CBTxWitness_;
        BTCMerklePath_   = bw->MerklePath_;
        BTCConsensusCtx_ = bw->ConsensusCtx_;

        // Secondary = FB works
        fbHeaders_.resize(second.size());
        fbLegacy_.resize(second.size());
        fbWitness_.resize(second.size());
        fbHeaderHashes_.resize(virtualHashesNum, uint256());
        fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());
        fbRoot_.resize(second.size());
        fbMerklePaths_.reserve(virtualHashesNum);

        for (size_t i = 0; i < second.size(); ++i) {
            auto* fw = static_cast<FB::Stratum::FbWork*>(second[i]->Work);
            fbHeaders_[i]       = fw->Header;
            fbLegacy_[i]        = fw->CBTxLegacy_;
            fbWitness_[i]       = fw->CBTxWitness_;
            fbRoot_[i]          = fw->RootNode_;
            for (auto& h : fw->headerHashes_) {
                fbHeaderHashes_.push_back(h);
            }
            for (auto& m : fw->MerklePath_) {
                fbMerklePaths_.push_back(m);
            }
        }

        fbNonce_             = mmNonce;
        fbVirtualHashesNum_  = virtualHashesNum;
        // All FB works share the same CheckConsensusCtx structure, so pick the first
        if (!second.empty()) {
            fbConsensusCtx_ = static_cast<FB::Stratum::FbWork*>(second[0]->Work)->ConsensusCtx_;
        }
    }

    // Prepare both BTC and FB parts for submission
    virtual bool prepareForSubmit(const CWorkerConfig& workerCfg,
                                  const CStratumMessage& msg) override
    {
        // 1) BTC part (primary)
        if (!btcWork()->prepareForSubmitImpl(
                BTCHeader_,
                0,                        // asicBoostData (not used for BTC here)
                BTCLegacy_,
                BTCWitness_,
                BTCMerklePath_,
                workerCfg,
                MiningCfg_,
                msg)) {
            return false;
        }

        // 2) FB parts (secondaries)
        for (size_t idx = 0; idx < fbHeaders_.size(); ++idx) {
            // Sync timestamp and set merged nonce
            fbHeaders_[idx].nTime  = BTCHeader_.nTime;
            fbHeaders_[idx].nNonce = fbNonce_;
            // ParentBlock = BTCHeader_ (shared branch)
            fbHeaders_[idx].ParentBlock = BTCHeader_;

            // Build FB-specific auxiliary fields (chain merkle branch, etc.)
            std::vector<uint256> path;
            buildMerklePath(fbHeaderHashes_, fbWorkMap_[idx], path);
            fbHeaders_[idx].ChainMerkleBranch.resize(path.size());
            for (size_t j = 0; j < path.size(); ++j) {
                fbHeaders_[idx].ChainMerkleBranch[j] = path[j];
            }
            fbHeaders_[idx].ChainIndex = fbWorkMap_[idx];
            fbHeaders_[idx].HashBlock   = bwHash(fbHeaders_[idx].ParentBlock);
            fbHeaders_[idx].ParentBlockCoinbaseTx = fbLegacy_[idx].Data;

            // Now call FB::Stratum::HeaderBuilder and FB::Stratum::Prepare
            if (!FB::Stratum::HeaderBuilder::build(
                    fbHeaders_[idx],
                    &(fbHeaders_[idx].nVersion),
                    fbLegacy_[idx],
                    fbMerklePaths_[idx],
                    fbRoot_[idx])) {
                return false;
            }
            if (!FB::Stratum::Prepare::prepare(
                    fbHeaders_[idx],
                    0,                         // asicBoostData (not used for FB)
                    fbLegacy_[idx],
                    fbWitness_[idx],
                    fbMerklePaths_[idx],
                    workerCfg,
                    MiningCfg_,
                    msg)) {
                return false;
            }
        }

        return true;
    }

    // Expected work: if index=0 -> BTC difficulty, else FB difficulty
    virtual double expectedWork(size_t workIdx) override
    {
        if (workIdx == 0) {
            return BTC::expectedWork(BTCHeader_, BTCConsensusCtx_);
        }
        return FB::expectedWork(fbHeaders_[workIdx - 1], fbConsensusCtx_);
    }

    // Build block hex: primary BTC if workIdx=0, else FB
    virtual void buildBlock(size_t workIdx, xmstream& blockHexData) override
    {
        if (workIdx == 0 && btcWork()) {
            btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
        } else {
            size_t idx = workIdx - 1;
            if (fbWork(idx)) {
                fbWork(idx)->buildBlockImpl(fbHeaders_[idx], fbWitness_[idx], blockHexData);
            }
        }
    }

    // Check consensus: primary BTC or FB accordingly
    virtual CCheckStatus checkConsensus(size_t workIdx) override
    {
        if (workIdx == 0 && btcWork()) {
            return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, FBConsensusCtx_);
        } else {
            size_t idx = workIdx - 1;
            if (fbWork(idx)) {
                return FB::Stratum::FbWork::checkConsensusImpl(fbHeaders_[idx], BTCConsensusCtx_);
            }
        }
        return CCheckStatus();
    }

private:
    // Helpers to downcast to underlying Work objects
    BTC::Stratum::Work* btcWork() {
        return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
    }
    FB::Stratum::FbWork* fbWork(unsigned index) {
        return static_cast<FB::Stratum::FbWork*>(Works_[index + 1].Work);
    }

    // BTC fields
    BTC::Proto::BlockHeader         BTCHeader_;
    BTC::CoinbaseTx                 BTCLegacy_;
    BTC::CoinbaseTx                 BTCWitness_;
    std::vector<uint256>            BTCMerklePath_;
    BTC::Proto::CheckConsensusCtx   BTCConsensusCtx_;

    // FB fields
    std::vector<FB::Proto::BlockHeader>    fbHeaders_;
    std::vector<BTC::CoinbaseTx>           fbLegacy_;
    std::vector<BTC::CoinbaseTx>           fbWitness_;
    std::vector<std::vector<uint256>>       fbMerklePaths_;
    std::vector<uint256>                    fbHeaderHashes_;
    std::vector<int>                        fbWorkMap_;
    std::vector<uint256>                    fbRoot_;

    uint32_t                                fbNonce_;
    unsigned int                            fbVirtualHashesNum_;
    FB::Proto::CheckConsensusCtx           fbConsensusCtx_;
};

//--------------------------------------------------------------
// newPrimaryWork: create BTC work
//--------------------------------------------------------------
Stratum::Work* Stratum::newPrimaryWork(int64_t stratumId,
                                       PoolBackend* backend,
                                       size_t backendIdx,
                                       const CMiningConfig& miningCfg,
                                       const std::vector<uint8_t>& miningAddress,
                                       const std::string& coinbaseMessage,
                                       CBlockTemplate& blockTemplate,
                                       std::string& error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }
    std::unique_ptr<BTC::Stratum::Work> work(new BTC::Stratum::Work(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//--------------------------------------------------------------
// newSecondaryWork: create FB work
//--------------------------------------------------------------
Stratum::Work* Stratum::newSecondaryWork(int64_t stratumId,
                                         PoolBackend* backend,
                                         size_t backendIdx,
                                         const CMiningConfig& miningCfg,
                                         const std::vector<uint8_t>& miningAddress,
                                         const std::string& coinbaseMessage,
                                         CBlockTemplate& blockTemplate,
                                         std::string& error)
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
        coinbaseMessage));
    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//--------------------------------------------------------------
// newMergedWork: combine one BTC primary with FB secondaries
//--------------------------------------------------------------
StratumMergedWork* Stratum::newMergedWork(int64_t stratumId,
                                          StratumSingleWork* primaryWork,
                                          std::vector<StratumSingleWork*>& secondaryWorks,
                                          const CMiningConfig& miningCfg,
                                          std::string& error)
{
    if (secondaryWorks.empty()) {
        error = "no secondary works";
        return nullptr;
    }

    uint32_t nonce = 0;
    unsigned virtualHashesNum = 0;
    std::vector<int> chainMap = buildChainMap(secondaryWorks, nonce, virtualHashesNum);
    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }

    return new MergedWork(stratumId, primaryWork, secondaryWorks, chainMap, nonce, virtualHashesNum, miningCfg);
}

//--------------------------------------------------------------
// buildSendTargetMessage: delegate to BTC implementation with FB difficulty factor
//--------------------------------------------------------------
void Stratum::buildSendTargetMessage(xmstream& stream, double shareDiff)
{
    BTC::Stratum::buildSendTargetMessageImpl(stream, shareDiff, DifficultyFactor);
}

} // namespace Stratum

struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;

    template<typename T>
    static inline void serialize(xmstream& src, const T& data) {
        BTC::Io<T>::serialize(src, data);
    }
    template<typename T>
    static inline void unserialize(xmstream& dst, T& data) {
        BTC::Io<T>::unserialize(dst, data);
    }
};

} // namespace FB

//--------------------------------------------------------------
// Io specialization for FB::Proto::BlockHeader (mirrors doge.cpp but with FB fields)
//--------------------------------------------------------------
namespace BTC {
template<>
struct Io<FB::Proto::BlockHeader> {
    static void serialize(xmstream& dst, const FB::Proto::BlockHeader& data)
    {
        // Serialize the “pure” BTC-like portion of FB header:
        BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);

        if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
            // AuxPoW fields:
            BTC::serialize(dst, data.ParentBlockCoinbaseTx);

            BTC::serialize(dst, data.HashBlock);
            BTC::serialize(dst, data.MerkleBranch);
            BTC::serialize(dst, data.Index);

            BTC::serialize(dst, data.ChainMerkleBranch);
            BTC::serialize(dst, data.ChainIndex);
            BTC::serialize(dst, data.ParentBlock);
        }
    }

    static void unserialize(xmstream& src, FB::Proto::BlockHeader& data)
    {
        // Deserialize the “pure” BTC-like portion
        BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&data);

        if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
            // AuxPoW fields:
            BTC::unserialize(src, data.ParentBlockCoinbaseTx);

            BTC::unserialize(src, data.HashBlock);
            BTC::unserialize(src, data.MerkleBranch);
            BTC::unserialize(src, data.Index);

            BTC::unserialize(src, data.ChainMerkleBranch);
            BTC::unserialize(src, data.ChainIndex);
            BTC::unserialize(src, data.ParentBlock);
        }
    }
};
} // namespace BTC

//--------------------------------------------------------------
// JSON serialization for FB::Proto::BlockHeader (mirrors doge’s serializeJsonInside)
//--------------------------------------------------------------
void serializeJsonInside(xmstream& stream, const FB::Proto::BlockHeader& header)
{
    serializeJson(stream, "version",      header.nVersion);          stream.write(',');
    serializeJson(stream, "hashPrevBlock", header.hashPrevBlock);    stream.write(',');
    serializeJson(stream, "hashMerkleRoot", header.hashMerkleRoot);  stream.write(',');
    serializeJson(stream, "time",         header.nTime);             stream.write(',');
    serializeJson(stream, "bits",         header.nBits);             stream.write(',');
    serializeJson(stream, "nonce",        header.nNonce);            stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "hashBlock",    header.HashBlock);         stream.write(',');
    serializeJson(stream, "merkleBranch", header.MerkleBranch);      stream.write(',');
    serializeJson(stream, "index",        header.Index);             stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch); stream.write(',');
    serializeJson(stream, "chainIndex",   header.ChainIndex);        stream.write(',');
    stream.write("\"parentBlock\":{");
    serializeJsonInside(stream, header.ParentBlock);
    stream.write('}');
}
