#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "sha256.h"                // for CCtxSha256, sha256Init, etc.
#include "blockmaker/stratumWork.h"          // for StratumMergedWork, StratumSingleWork, etc.

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

// Compute how many virtual hashes are needed to accommodate N secondaries.
// (same as DOGE’s merklePathSize logic)
static unsigned merklePathSize(unsigned count)
{
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

// Given an FB nonce and chainId, produce a pseudo-random index in [0, 2^h − 1].
static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h)
{
    uint32_t x = nNonce;
    x = x * 1103515245 + 12345;
    x += nChainId;
    x = x * 1103515245 + 12345;
    return (x % (1u << h));
}

namespace FB {

std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork*>& secondary,
                       uint32_t& nNonce,
                       unsigned& virtualHashesNum)
{
    std::vector<int> result(secondary.size(), 0);
    std::vector<int> chainMap;
    bool finished = true;

    // Try increasing path sizes until we find a collision-free assignment
    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = (1u << pathSize);
        chainMap.assign(virtualHashesNum, -1);

        for (nNonce = 0; nNonce < virtualHashesNum; nNonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), -1);

            for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
                auto* work = static_cast<FB::Stratum::FbWork*>(secondary[workIdx]);
                // Extract chainId from each FB header’s version bits
                uint32_t chainId = (work->Header.nVersion >> 16) & 0xFFFF;
                uint32_t idx    = getExpectedIndex(nNonce, chainId, pathSize);

                if (chainMap[idx] < 0) {
                    chainMap[idx] = static_cast<int>(workIdx);
                    result[workIdx] = static_cast<int>(idx);
                } else {
                    finished = false;
                    break;
                }
            }

            if (finished) {
                break;
            }
        }

        if (finished) {
            break;
        }
    }

    if (finished) {
        return result;
    } else {
        return std::vector<int>();
    }
}

////////////////////////////////////////////////////////////////////////////////
// MergedWork: handles “primary” (BTC) + one or more secondaries (FB) merges
////////////////////////////////////////////////////////////////////////////////

Stratum::MergedWork::MergedWork(uint64_t                          stratumWorkId,
                                StratumSingleWork*                first,
                                std::vector<StratumSingleWork*>&  second,
                                std::vector<int>&                 mmChainId,
                                uint32_t                          mmNonce,
                                unsigned                          virtualHashesNum,
                                const CMiningConfig&             miningCfg)
    : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // Capture BTC fields from the primary work (first pointer)
    BTCHeader_         = ltcWork()->Header;
    BTCLegacy_         = ltcWork()->CBTxLegacy_;
    BTCWitness_        = ltcWork()->CBTxWitness_;
    BTCMerklePath_     = ltcWork()->MerklePath;
    BTCConsensusCtx_   = ltcWork()->ConsensusCtx_;

    // Allocate FB arrays of size = number of secondaries
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    // fbHeaderHashes_ holds one hash slot per virtual hash
    fbHeaderHashes_.assign(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // fbRoot_ will hold the computed chain merkle root (one per secondary)
    fbRoot_.resize(second.size());

    // Reserve space for each FB’s merkle path arrays
    fbMerklePaths_.clear();
    fbMerklePaths_.reserve(virtualHashesNum);

    // Extract FB consensus contexts from each secondary work
    fbConsensusCtx_.clear();
    fbConsensusCtx_.reserve(second.size());
    fbConsensusCtx_.push_back(
        static_cast<FB::Stratum::FbWork*>(second[0])->ConsensusCtx_);

    // At construction we still don’t know fbNonce_, but we store it
    fbNonce_           = mmNonce;
    fbVirtualHashesNum = virtualHashesNum;
}

bool
Stratum::MergedWork::prepareForSubmit(const CWorkerConfig& workerCfg,
                                      const CStratumMessage& msg)
{
    // 1) Let BTC primary prepare as usual
    if (!ltcWork()->prepareForSubmitImpl(
            BTCHeader_,
            uint32_t(0),             // asicBoost bits (FB does not use these)
            BTCLegacy_,
            BTCWitness_,
            BTCMerklePath_,
            workerCfg,
            MiningCfg_,
            msg))
    {
        return false;
    }

    // 2) Build each FB header, FB coinbase, and compute FB chain merkle root
    unsigned count = static_cast<unsigned>(fbHeaders_.size());
    for (unsigned i = 0; i < count; i++) {
        auto* fw       = static_cast<FB::Stratum::FbWork*>(secondWorks[i]);
        auto& header   = fbHeaders_[i];
        auto& legacyTx = fbLegacy_[i];
        auto& witTx    = fbWitness_[i];

        // Copy the FB header template from the secondary work
        header = fw->Header;

        // Build FB coinbase with no extra-nonce (we’ll do merkle root by ourselves)
        {
            CMiningConfig noNonceCfg = MiningCfg_;
            noNonceCfg.FixedExtraNonceSize   = 0;
            noNonceCfg.MutableExtraNonceSize = 0;
            fw->buildCoinbaseTx(nullptr, 0, noNonceCfg, legacyTx, witTx);
        }

        // Calculate FB chain merkle root (first compute FB coinbase’s hash)
        uint256 cbHash;
        {
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha, legacyTx.Data.data(), legacyTx.Data.sizeOf());
            sha256Final(&sha, cbHash.begin());
            sha256Init(&sha);
            sha256Update(&sha, cbHash.begin(), sizeof(cbHash));
            sha256Final(&sha, cbHash.begin());
        }
        // “chain merkle path” from this FB work
        uint256 merkleRoot =
            calculateMerkleRootWithPath(cbHash,
                                        &fw->MerklePath[0],
                                        fw->MerklePath.size(),
                                        0);

        // NB: doge inverts bytes for merged-mining; FB does exactly the same
        std::reverse(merkleRoot.begin(), merkleRoot.end());
        fbRoot_[i] = merkleRoot;

        // Write out the FB chain merkle root into the BTC coinbase payload:
        //   [pchMergedMiningHeader][chainMerkleRoot][virtualHashesNum][fbNonce]
        {
            uint8_t buffer[1024];
            xmstream coinbaseMsg(buffer, sizeof(buffer));
            coinbaseMsg.reset();
            coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
            coinbaseMsg.write(merkleRoot.begin(), sizeof(uint256));
            coinbaseMsg.write<uint32_t>(fbVirtualHashesNum);
            coinbaseMsg.write<uint32_t>(fbNonce_);

            // Now embed “coinbaseMsg” into the BTC primary coinbase:
            // (i.e., insert after BTC’s “0xfa, 0xbe, 'm', 'm' + chainRoot + size + nonce”)
            ltcWork()->buildCoinbaseTx(coinbaseMsg.data(),
                                       coinbaseMsg.sizeOf(),
                                       MiningCfg_,
                                       BTCLegacy_,
                                       BTCWitness_);
        }

        // Record this FB headerHash into fbHeaderHashes_ at the “virtual index”
        uint256 h = header.GetHash();
        fbHeaderHashes_[ fbWorkMap_[i] ] = h;
    }

    // 3) (Re)compute “chain merkle root” from fbHeaderHashes_[0..virtualHashesNum−1],
    //     then push to the BTC primary coinbase once more.  This ensures that
    //     BTC’s coinbase contains an updated merkle root (incorporating FB).
    {
        uint256 overallRoot = calculateMerkleRoot(&fbHeaderHashes_[0], fbVirtualHashesNum);
        std::reverse(overallRoot.begin(), overallRoot.end());

        uint8_t buffer[1024];
        xmstream coinbaseMsg(buffer, sizeof(buffer));
        coinbaseMsg.reset();
        coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        coinbaseMsg.write(overallRoot.begin(), sizeof(uint256));
        coinbaseMsg.write<uint32_t>(fbVirtualHashesNum);
        coinbaseMsg.write<uint32_t>(fbNonce_);

        ltcWork()->buildCoinbaseTx(coinbaseMsg.data(),
                                   coinbaseMsg.sizeOf(),
                                   MiningCfg_,
                                   BTCLegacy_,
                                   BTCWitness_);
    }

    // 4) Capture FB consensus context from the first FB work
    fbConsensusCtx_.clear();
    fbConsensusCtx_.push_back(
        static_cast<FB::Stratum::FbWork*>(secondWorks[0])->ConsensusCtx_);

    return true;
}

double
Stratum::MergedWork::expectedWork(size_t workIdx)
{
    // For workIdx=0, delegate to BTC’s expectedWork
    if (workIdx == 0 && ltcWork()) {
        return BTC::expectedWork(BTCHeader_, BTCConsensusCtx_);
    }
    // For FB index > 0, call FB’s expectedWork
    return FB::expectedWork(fbHeaders_[workIdx - 1], fbConsensusCtx_);
}

void
Stratum::MergedWork::buildBlock(size_t workIdx, xmstream& blockHexData)
{
    // If primary (BTC), build block normally
    if (workIdx == 0 && ltcWork()) {
        ltcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
        return;
    }

    // Otherwise index into FB arrays
    unsigned idx = static_cast<unsigned>(workIdx - 1);
    auto* fbW    = static_cast<FB::Stratum::FbWork*>(secondWorks[idx]);
    fbW->buildBlockImpl(fbHeaders_[idx], fbWitness_[idx], blockHexData);
}

CCheckStatus
Stratum::MergedWork::checkConsensus(size_t workIdx)
{
    // 0 => BTC
    if (workIdx == 0 && ltcWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, FBConsensusCtx_);
    }
    // >0 => FB
    unsigned idx    = static_cast<unsigned>(workIdx - 1);
    auto* fbW       = static_cast<FB::Stratum::FbWork*>(secondWorks[idx]);
    return FB::Stratum::FbWork::checkConsensusImpl(fbHeaders_[idx], BTCConsensusCtx_);
}

////////////////////////////////////////////////////////////////////////////////
// Stratum::prepareForSubmit (top-level dispatcher for each “work”)
////////////////////////////////////////////////////////////////////////////////

bool
Stratum::prepareForSubmit(const CWorkerConfig& workerCfg, const CStratumMessage& msg)
{
    // If there is a BTC primary work, let it prepare first
    if (ltcWork()) {
        if (!ltcWork()->prepareForSubmitImpl(
                BTCHeader_,
                uint32_t(0),
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

    // Now prepare each FB header: read from Works_[i+1]
    unsigned fbCount = static_cast<unsigned>(Works_.size()) - 1;
    if (fbCount == 0) {
        // No FB secondaries => nothing else to do
        return true;
    }

    // We assume buildChainMap already ran; so fbHeaders_, fbLegacy_, etc. exist.
    for (unsigned i = 0; i < fbCount; i++) {
        auto* fbW = static_cast<FB::Stratum::FbWork*>(Works_[i + 1].Work);
        auto& header = fbHeaders_[i];
        auto& legacy = fbLegacy_[i];
        auto& witness = fbWitness_[i];

        // Copy template header from secondary
        header = fbW->Header;

        // Build coinbase (no extra-nonce) to compute merkle root
        CMiningConfig noNonceCfg = MiningCfg_;
        noNonceCfg.FixedExtraNonceSize   = 0;
        noNonceCfg.MutableExtraNonceSize = 0;
        fbW->buildCoinbaseTx(nullptr, 0, noNonceCfg, legacy, witness);

        // Compute FB chain merkle root, place into header.hashMerkleRoot
        {
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha, legacy.Data.data(), legacy.Data.sizeOf());
            sha256Final(&sha, header.hashMerkleRoot.begin());
            sha256Init(&sha);
            sha256Update(&sha, header.hashMerkleRoot.begin(), sizeof(uint256));
            sha256Final(&sha, header.hashMerkleRoot.begin());
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// Stratum::buildNotifyMessage (identical to DOGE: just FB instead of DOGE)
////////////////////////////////////////////////////////////////////////////////

void
Stratum::buildNotifyMessage(xmstream&                stream,
                            const Proto::BlockHeader& header,
                            uint32_t                 extranonce1Size,
                            int&                     extranonce2Size,
                            const std::vector<base_blob<256>>& merkleBranch,
                            const CMiningConfig&     mc,
                            bool                     segwitEnabled,
                            xmstream&                out)
{
    // Reuse DOGE’s pattern: adjust names to FB
    serializeJson(stream, "algo",        mc.AlgoName);              stream.write(',');
    serializeJson(stream, "jobId",       header.GetHash());          stream.write(',');
    serializeJson(stream, "version",     header.nVersion);           stream.write(',');
    serializeJson(stream, "prevHash",    header.hashPrevBlock);      stream.write(',');
    serializeJson(stream, "merkleBranch", merkleBranch);            stream.write(',');
    serializeJson(stream, "coinbase1",   mc.Coinbase1);             stream.write(',');
    serializeJson(stream, "coinbase2",   mc.Coinbase2);             stream.write(',');
    serializeJson(stream, "nBits",       header.nBits);              stream.write(',');
    serializeJson(stream, "nTime",       header.nTime);              stream.write(',');
    serializeJson(stream, "miningAddress", mc.MiningAddress);       stream.write(',');
    serializeJson(stream, "extranonce1Size", extranonce1Size);       stream.write(',');
    serializeJson(stream, "extranonce2Size", extranonce2Size);       stream.write(',');
    serializeJson(stream, "segwit",      segwitEnabled);             stream.write(',');
    serializeJson(stream, "jobType",     mc.JobType);                stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.chainMerkleBranch); stream.write(',');
    serializeJson(stream, "chainIndex",   header.chainIndex);         stream.write(',');
    serializeJson(stream, "parentBlock",  header.ParentBlock);        stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "parentMerkleBranch",    header.ParentBlockMerkleBranch); stream.write(',');
}

////////////////////////////////////////////////////////////////////////////////
// FbWork factory functions (newPrimaryWork and newSecondaryWork)
//
//   PrimaryWork = a BTC::WorkTy<FB::Proto,...> instance
//   SecondaryWork = a FB::Stratum::FbWork (alias for BTC::WorkTy<FB::Proto,...>)
//

Work*
Stratum::newPrimaryWork(int64_t                     stratumId,
                        PoolBackend*                backend,
                        size_t                      backendIdx,
                        const CMiningConfig&        mc,
                        const std::vector<uint8_t>& miningAddress,
                        const std::string&          coinbaseMsg,
                        CBlockTemplate&             blockTemplate,
                        std::string&                error)
{
    // Create a BTC::WorkTy<FB::Proto,...> for the primary chain
    using PrimaryWorkTy = BTC::WorkTy<FB::Proto,
                                      BTC::Stratum::HeaderBuilder,
                                      BTC::Stratum::CoinbaseBuilder,
                                      BTC::Stratum::Notify,
                                      BTC::Stratum::Prepare>;

    std::unique_ptr<PrimaryWorkTy> work(new PrimaryWorkTy(
        stratumId,
        backend->getNextUniqueWorkId(),
        backend,
        backendIdx,
        mc,
        miningAddress,
        coinbaseMsg
    ));

    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

StratumSingleWork*
Stratum::newSecondaryWork(int64_t                     stratumId,
                          PoolBackend*                backend,
                          size_t                      backendIdx,
                          const CMiningConfig&        mc,
                          const std::vector<uint8_t>& miningAddress,
                          const std::string&          coinbaseMsg,
                          CBlockTemplate&             blockTemplate,
                          std::string&                error)
{
    // Create a FB::Stratum::FbWork (alias for BTC::WorkTy<FB::Proto,...>)
    using FbWorkTy = BTC::WorkTy<FB::Proto,
                                 BTC::Stratum::HeaderBuilder,
                                 BTC::Stratum::CoinbaseBuilder,
                                 BTC::Stratum::Notify,
                                 BTC::Stratum::Prepare>;

    std::unique_ptr<FbWorkTy> work(new FbWorkTy(
        stratumId,
        backend->getNextUniqueWorkId(),
        backend,
        backendIdx,
        mc,
        miningAddress,
        coinbaseMsg
    ));

    return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

////////////////////////////////////////////////////////////////////////////////
// Utility: calculate Merkle root from an array of uint256
static uint256
CalculateMerkleRoot(const uint256* leaves, unsigned int nLeaves)
{
    if (nLeaves == 0) {
        return uint256();
    }
    if (nLeaves == 1) {
        return leaves[0];
    }
    unsigned int nextLevel = ((nLeaves + 1) / 2);
    std::vector<uint256> parentHashes(nextLevel);

    for (unsigned i = 0; i < nLeaves; i += 2) {
        if (i + 1 < nLeaves) {
            parentHashes[i / 2] = Hash(leaves[i].begin(), 32,
                                      leaves[i + 1].begin(), 32);
        } else {
            // duplicate last leaf if odd count
            parentHashes[i / 2] = Hash(leaves[i].begin(), 32,
                                      leaves[i].begin(), 32);
        }
    }
    return CalculateMerkleRoot(&parentHashes[0], nextLevel);
}

////////////////////////////////////////////////////////////////////////////////
// FB‐specific serialization into JSON (for getblocktemplate “auxpow” fields)
////////////////////////////////////////////////////////////////////////////////

void
serializeJsonInside(xmstream& stream, const Proto::BlockHeader& header)
{
    serializeJson(stream, "nVersion",            header.nVersion);           stream.write(',');
    serializeJson(stream, "hashPrevBlock",       header.hashPrevBlock);      stream.write(',');
    serializeJson(stream, "hashMerkleRoot",      header.hashMerkleRoot);     stream.write(',');
    serializeJson(stream, "nTime",               header.nTime);              stream.write(',');
    serializeJson(stream, "nBits",               header.nBits);              stream.write(',');
    serializeJson(stream, "nNonce",              header.nNonce);             stream.write(',');
    serializeJson(stream, "parentBlock",         header.ParentBlock);        stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "parentMerkleBranch",  header.ParentBlockMerkleBranch); stream.write(',');
    serializeJson(stream, "chainMerkleBranch",   header.ChainMerkleBranch);  stream.write(',');
    serializeJson(stream, "chainIndex",          header.ChainIndex);         stream.write(',');
    serializeJson(stream, "parentParentBlock",   header.ParentBlock);        // last field, no comma
}

} // namespace FB