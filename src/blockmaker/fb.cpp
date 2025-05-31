// fb.cpp
// FB merged‐mining support (modeled after doge.cpp)

#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJsonInside.h"
#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

// 4‐byte merged‐mining header (same as DOGE)
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

// Compute Merkle root from an array of leaves
static uint256 CalculateMerkleRoot(const uint256* leaves, unsigned int nLeaves) {
    if (nLeaves == 0) return uint256();
    if (nLeaves == 1) return leaves[0];
    unsigned int levelCount = nLeaves;
    std::vector<uint256> level(leaves, leaves + nLeaves);
    while (levelCount > 1) {
        unsigned int nextCount = (levelCount + 1) / 2;
        for (unsigned int i = 0; i < nextCount; i++) {
            uint256 left = level[2 * i];
            uint256 right = (2 * i + 1 < levelCount) ? level[2 * i + 1] : left;
            uint256 parent = Hash(left.begin(), 32, right.begin(), 32);
            level[i] = parent;
        }
        levelCount = nextCount;
    }
    return level[0];
}

} // anonymous namespace

namespace FB {
namespace Stratum {

// Build a map of FB work ⇒ Merkle‐leaf index (mirrors doge.cpp logic)
static std::vector<int>
buildChainMap(std::vector<StratumSingleWork*>& secondary,
              uint32_t& mmNonce,
              unsigned int& virtualHashesNum)
{
    unsigned int count = secondary.size();
    std::vector<int> mapOut(count);
    std::vector<uint256> headerHashes(count);

    // 1) Gather each FB work’s header hash (pure header)
    for (unsigned int i = 0; i < count; i++) {
        auto* fw = static_cast<FB::Stratum::FbWork*>(secondary[i]->Work);
        headerHashes[i] = fw->Header.GetHash();
    }

    // 2) Choose a random mmNonce
    mmNonce = GetRand((uint32_t)count);
    virtualHashesNum = count;

    // 3) Assign each header to a Merkle‐leaf index based on hash+nonce
    for (unsigned int i = 0; i < count; i++) {
        uint32_t low = headerHashes[i].GetUint32(0);
        uint32_t idx = (low ^ mmNonce) % count;
        mapOut[i] = idx;
    }
    return mapOut;
}

//============================================================================
//=== class FB::Stratum::MergedWork ==========================================
//============================================================================
// Implements merged mining of FB underneath BTC (mirrors doge.cpp exactly).

MergedWork::MergedWork(uint64_t                    stratumWorkId,
                       StratumSingleWork          *first,
                       std::vector<StratumSingleWork*> &second,
                       std::vector<int>           &mmChainId,
                       uint32_t                    mmNonce,
                       unsigned int                virtualHashesNum,
                       const CMiningConfig        &miningCfg)
  : StratumMergedWork(stratumWorkId, first, second, miningCfg)
  , MiningCfg_(miningCfg)
  , FBNonce_(mmNonce)
  , FBVirtualHashesNum_(virtualHashesNum)
{
    // 1) Copy BTC (primary) fields
    {
        auto* bw = static_cast<BTC::Stratum::Work*>(first->Work);
        BTCHeader_       = bw->Header;
        BTCMerklePath_   = bw->MerklePath;
        BTCConsensusCtx_ = bw->ConsensusCtx;
    }

    unsigned int count = second.size();

    // 2) Resize FB arrays
    FBHeaders_.resize(count);
    FBLegacy_.resize(count);
    FBWitness_.resize(count);

    // 3) Initialize FBHeaderHashes_ and FBWorkMap_
    FBHeaderHashes_.assign(virtualHashesNum, uint256());
    FBWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 4) Build each FB coinbase + header + header‐hash
    for (unsigned int i = 0; i < count; i++) {
        auto* fw = static_cast<FB::Stratum::FbWork*>(second[i]->Work);

        // Copy the template header
        FBHeaders_[i] = fw->Header;

        // Build “merged mining” coinbase prefix (pchMergedMiningHeader ∥ Merkle‐root placeholder ∥ virtual count ∥ nonce)
        uint256 placeholderRoot = uint256(); // will be replaced below
        xmstream prefix;
        prefix.reset();
        prefix.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        prefix.write(placeholderRoot.begin(), 32);
        prefix.write<uint32_t>(virtualHashesNum);
        prefix.write<uint32_t>(mmNonce);

        // Build FB legacy coinbase
        FBLegacy_[i].Data.reset();
        FBLegacy_[i].Data = prefix;
        fw->buildCoinbaseTx(FBLegacy_[i].Data.data(),
                            FBLegacy_[i].Data.sizeOf(),
                            miningCfg,
                            /* legacy = */ false,
                            FBLegacy_[i]);

        // Build FB witness coinbase
        FBWitness_[i].Data.reset();
        FBWitness_[i].Data = prefix;
        fw->buildCoinbaseTx(FBWitness_[i].Data.data(),
                            FBWitness_[i].Data.sizeOf(),
                            miningCfg,
                            /* witness = */ true,
                            FBWitness_[i]);

        // Compute FB header’s Merkle‐root from its coinbase coin‐leaf + MerklePath
        std::vector<uint256> merkleBranch = fw->MerklePath;
        uint256 leafHash = Hash160(FBLegacy_[i].Data.data(), FBLegacy_[i].Data.sizeOf());
        FBHeaders_[i].hashMerkleRoot =
            CalculateMerkleRootFromBranch(leafHash, merkleBranch, FBWorkMap_[i]);

        // Assign header‐hash into FBHeaderHashes_
        FBHeaderHashes_[FBWorkMap_[i]] = FBHeaders_[i].GetHash();
    }

    // 5) Compute overall FB chain Merkle‐root
    {
        std::vector<uint256> leaves = FBHeaderHashes_;
        uint256 chainRoot = CalculateMerkleRoot(leaves.data(), leaves.size());

        // 6) Build BTC coinbase with merged‐mining prefix:
        xmstream prefix;
        prefix.reset();
        prefix.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        prefix.write(chainRoot.begin(), 32);
        prefix.write<uint32_t>(virtualHashesNum);
        prefix.write<uint32_t>(mmNonce);

        BTCLegacy_.Data.reset();
        BTCLegacy_.Data = prefix;
        BTCWitness_.Data.reset();
        BTCWitness_.Data = prefix;

        auto* bw = static_cast<BTC::Stratum::Work*>(first->Work);
        bw->buildCoinbaseTx(BTCLegacy_.Data.data(),
                            BTCLegacy_.Data.sizeOf(),
                            miningCfg,
                            /* legacy = */ false,
                            BTCLegacy_);
        bw->buildCoinbaseTx(BTCWitness_.Data.data(),
                            BTCWitness_.Data.sizeOf(),
                            miningCfg,
                            /* witness = */ true,
                            BTCWitness_);
    }

    // 7) Copy FB consensus context (from first FB work)
    FBConsensusCtx_ = static_cast<FB::Stratum::FbWork*>(second[0]->Work)->ConsensusCtx;
}

bool
MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                             const CStratumMessage  &msg)
{
    // 1) Primary BTC
    {
        auto* bw = static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        if (!bw->prepareForSubmitImpl(
                BTCHeader_,
                BTCHeader_.nVersion,
                BTCLegacy_,
                BTCWitness_,
                BTCMerklePath_,
                workerCfg,
                MiningCfg_,
                msg))
        {
            return false;
        }
    }

    // 2) Each FB header
    unsigned int count = FBHeaders_.size();
    for (unsigned int i = 0; i < count; i++) {
        // Deserialize ParentBlockCoinbaseTx from FBLegacy_
        XMStream &src = FBLegacy_[i].Data;
        FBHeaders_[i].parentCoinbaseTx = BTC::Proto::Transaction();
        BTC::Io<BTC::Proto::Transaction>::unserialize(src, FBHeaders_[i].parentCoinbaseTx);

        // Set merged values
        FBHeaders_[i].parentBlockHash = BTCHeader_.GetHash();
        FBHeaders_[i].nTime           = BTCHeader_.nTime;
        FBHeaders_[i].nVersion       |= FB::Proto::BlockHeader::VERSION_AUXPOW;

        // Build Merkle path for FB chain
        std::vector<uint256> chainPath =
            BuildMerklePath(FBHeaderHashes_, FBWorkMap_[i]);
        FBHeaders_[i].merkleBranch    = std::move(chainPath);
        FBHeaders_[i].chainIndex      = FBWorkMap_[i];
    }
    return true;
}

double
MergedWork::expectedWork(size_t workIdx)
{
    if (workIdx == 0) {
        return BTC::expectedWork(BTCHeader_, BTCConsensusCtx_);
    } else {
        unsigned int i = workIdx - 1;
        return FB::expectedWork(FBHeaders_[i], FBConsensusCtx_);
    }
}

void
MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
    if (workIdx == 0) {
        auto* bw = static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        bw->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
    } else {
        unsigned int i = workIdx - 1;
        auto* fw = static_cast<FB::Stratum::FbWork*>(Works_[i + 1]->Work);
        fw->buildBlockImpl(FBHeaders_[i], FBWitness_[i], blockHexData);
    }
}

CCheckStatus
MergedWork::checkConsensus(size_t workIdx)
{
    if (workIdx == 0) {
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, FBConsensusCtx_);
    } else {
        unsigned int i = workIdx - 1;
        return FB::Stratum::FbWork::checkConsensusImpl(FBHeaders_[i], BTCConsensusCtx_);
    }
}

//-------------------------------------------------------------------------
// Helpers to downcast Works_[]
BTC::Stratum::Work*
Stratum::btcWork()
{
    return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
}

FB::Stratum::FbWork*
Stratum::fbWork(unsigned index)
{
    return static_cast<FB::Stratum::FbWork*>(Works_[index + 1]->Work);
}

//-------------------------------------------------------------------------
// newPrimaryWork: same as doge but creates BTC work
BTC::Stratum::Work*
Stratum::newPrimaryWork(int64_t                    stratumId,
                        PoolBackend               *backend,
                        size_t                     backendIdx,
                        const CMiningConfig       &miningCfg,
                        const std::vector<uint8_t> &miningAddress,
                        const std::string         &coinbaseMessage,
                        CBlockTemplate            &blockTemplate,
                        std::string               &error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type (expected Bitcoin)";
        return nullptr;
    }
    std::unique_ptr<BTC::Stratum::Work> w(new BTC::Stratum::Work(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage));
    return w->loadFromTemplate(blockTemplate, error) ? w.release() : nullptr;
}

//-------------------------------------------------------------------------
// newSecondaryWork: same as doge but creates FB work
StratumSingleWork*
Stratum::newSecondaryWork(int64_t                    stratumId,
                          PoolBackend               *backend,
                          size_t                     backendIdx,
                          const CMiningConfig       &miningCfg,
                          const std::vector<uint8_t> &miningAddress,
                          const std::string         &coinbaseMessage,
                          CBlockTemplate            &blockTemplate,
                          std::string               &error)
{
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type (expected Bitcoin)";
        return nullptr;
    }
    std::unique_ptr<FB::Stratum::FbWork> w(new FB::Stratum::FbWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage));
    return w->loadFromTemplate(blockTemplate, error) ? w.release() : nullptr;
}

//-------------------------------------------------------------------------
// newMergedWork: same pattern as doge
StratumMergedWork*
Stratum::newMergedWork(int64_t                    stratumId,
                       StratumSingleWork         *primaryWork,
                       std::vector<StratumSingleWork*> &secondaryWorks,
                       const CMiningConfig       &miningCfg,
                       std::string               &error)
{
    if (secondaryWorks.empty()) {
        error = "no secondary works";
        return nullptr;
    }
    uint32_t nonce     = 0;
    unsigned int virt  = 0;
    std::vector<int>  chainMap = buildChainMap(secondaryWorks, nonce, virt);
    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }
    return new MergedWork(stratumId, primaryWork, secondaryWorks, chainMap, nonce, virt, miningCfg);
}

//-------------------------------------------------------------------------
// buildSendTargetMessage: delegate to BTC helper
void
Stratum::buildSendTargetMessage(xmstream &stream, double shareDiff)
{
    BTC::Stratum::buildSendTargetMessageImpl(stream, shareDiff, DifficultyFactor);
}

} // namespace Stratum
} // namespace FB


//==============================================================================
//=== Io<FB::Proto::BlockHeader> specialization (mirrors doge.cpp) ============
//==============================================================================

namespace BTC {
template<>
struct Io<FB::Proto::BlockHeader> {
    static void serialize(xmstream &dst, const FB::Proto::BlockHeader &data)
    {
        // Write pure BTC‐like header (80 bytes)
        BTC::serialize(dst, static_cast<const FB::Proto::PureBlockHeader&>(data));

        // If AuxPoW flag set, write AuxPoW fields:
        if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
            BTC::serialize(dst, data.parentCoinbaseTx);
            BTC::serialize(dst, data.HashBlock);
            BTC::serialize(dst, data.merkleBranch);
            BTC::serialize(dst, data.nTxIndex);
            BTC::serialize(dst, data.chainMerkleBranch);
            BTC::serialize(dst, data.chainIndex);
            BTC::serialize(dst, data.parentParentBlock);
        }
    }

    static void unserialize(xmstream &src, FB::Proto::BlockHeader &data)
    {
        // Read pure BTC‐like header
        BTC::unserialize(src, static_cast<FB::Proto::PureBlockHeader&>(data));

        if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
            BTC::unserialize(src, data.parentCoinbaseTx);
            BTC::unserialize(src, data.HashBlock);
            BTC::unserialize(src, data.merkleBranch);
            BTC::unserialize(src, data.nTxIndex);
            BTC::unserialize(src, data.chainMerkleBranch);
            BTC::unserialize(src, data.chainIndex);
            BTC::unserialize(src, data.parentParentBlock);
        }
    }
};
} // namespace BTC


//==============================================================================
//=== serializeJsonInside for FB::Proto::BlockHeader ==========================
//==============================================================================
void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header)
{
    serializeJson(stream, "version",           header.nVersion);           stream.write(',');
    serializeJson(stream, "prevBlockHash",     header.hashPrevBlock);      stream.write(',');
    serializeJson(stream, "merkleRoot",        header.hashMerkleRoot);     stream.write(',');
    serializeJson(stream, "time",              header.nTime);              stream.write(',');
    serializeJson(stream, "bits",              header.nBits);              stream.write(',');
    serializeJson(stream, "nonce",             header.nNonce);             stream.write(',');
    serializeJson(stream, "parentCoinbaseTx",  header.parentCoinbaseTx);   stream.write(',');
    serializeJson(stream, "hashBlock",         header.HashBlock);          stream.write(',');
    serializeJson(stream, "merkleBranch",      header.merkleBranch);       stream.write(',');
    serializeJson(stream, "txIndex",           header.nTxIndex);           stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.chainMerkleBranch);  stream.write(',');
    serializeJson(stream, "chainIndex",        header.chainIndex);         stream.write(',');
    stream.write("\"parentParentBlock\":{");
    serializeJsonInside(stream, header.parentParentBlock);
    stream.write('}');
}
