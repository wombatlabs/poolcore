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
    uint32_t x = nNonce;
    x = x * 1103515245 + 12345;
    x += nChainId;
    x = x * 1103515245 + 12345;
    return (x % (1u << h));
}

namespace FB {

std::vector<int>
Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary,
                       uint32_t &nonce,
                       unsigned &virtualHashesNum)
{
    std::vector<int> result(secondary.size(), 0);
    std::vector<int> chainMap;
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.assign(virtualHashesNum, -1);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), -1);

            for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
                auto* work = static_cast<FB::Stratum::FbWork*>(secondary[workIdx]);
                uint32_t chainId = (work->Header.nVersion >> 16) & 0xFFFF;
                uint32_t idx    = getExpectedIndex(nonce, chainId, pathSize);

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

    return (finished ? result : std::vector<int>());
}

////////////////////////////////////////////////////////////////////////////////
// MergedWork constructor + methods
////////////////////////////////////////////////////////////////////////////////

Stratum::MergedWork::MergedWork(uint64_t                          stratumWorkId,
                                StratumSingleWork*                first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int>                 &mmChainId,
                                uint32_t                          mmNonce,
                                unsigned                          virtualHashesNum,
                                const CMiningConfig              &miningCfg)
    : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // 1) Primary (BTC) fields
    BTCHeader_       = btcWork()->Header;
    BTCMerklePath_   = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

    // 2) Allocate FB arrays
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    fbHeaderHashes_.assign(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 3) For each FB secondary: build its no-extra-nonce coinbase, compute its merkle root,
    //    store that hash into fbHeaderHashes_ at the mapped position.
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        auto* work   = static_cast<FB::Stratum::FbWork*>(second[workIdx]);
        auto& header = fbHeaders_[workIdx];
        auto& legacy = fbLegacy_[workIdx];
        auto& witness= fbWitness_[workIdx];

        header = work->Header;

        // Build FB coinbase with zero extra‐nonce
        {
            CMiningConfig noNonceCfg = miningCfg;
            noNonceCfg.FixedExtraNonceSize   = 0;
            noNonceCfg.MutableExtraNonceSize = 0;
            work->buildCoinbaseTx(nullptr, 0, noNonceCfg, legacy, witness);
        }

        // Compute FB’s merkle root for this coinbase
        {
            uint256 cbHash;
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha, legacy.Data.data(), legacy.Data.sizeOf());
            sha256Final(&sha, cbHash.begin());

            sha256Init(&sha);
            sha256Update(&sha, cbHash.begin(), sizeof(cbHash));
            sha256Final(&sha, cbHash.begin());

            header.hashMerkleRoot = 
                calculateMerkleRootWithPath(cbHash,
                                            &work->MerklePath[0],
                                            work->MerklePath.size(),
                                            0);
        }

        // Invert and store this FB header’s hash into fbHeaderHashes_
        fbHeaderHashes_[ fbWorkMap_[workIdx] ] = header.GetHash();
    }

    // 4) Calculate the “chain merkle root” over all fbHeaderHashes_
    uint256 chainRoot = calculateMerkleRoot(&fbHeaderHashes_[0], fbHeaderHashes_.size());
    std::reverse(chainRoot.begin(), chainRoot.end());

    // 5) Embed <mm signature> ∥ chainRoot ∥ virtualHashesNum ∥ mmNonce into BTC coinbase
    {
        uint8_t buffer[1024];
        xmstream coinbaseMsg(buffer, sizeof(buffer));
        coinbaseMsg.reset();
        coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        coinbaseMsg.write(chainRoot.begin(), sizeof(uint256));
        coinbaseMsg.write<uint32_t>(virtualHashesNum);
        coinbaseMsg.write<uint32_t>(mmNonce);

        btcWork()->buildCoinbaseTx(
            coinbaseMsg.data(),
            coinbaseMsg.sizeOf(),
            miningCfg,
            BTCLegacy_,
            BTCWitness_
        );
    }

    // 6) Capture FB consensus context from the first secondary
    fbConsensusCtx_.clear();
    fbConsensusCtx_.push_back( fbWork(0)->ConsensusCtx_ );
}

bool
Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                      const CStratumMessage &msg)
{
    // Let BTC primary prepare first
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
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

    // Now update each FB header’s “auxpow” fields so that getblocktemplate’s JSON is correct.
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        auto& header = fbHeaders_[workIdx];

        // Re‐serialize parentBlockCoinbaseTx from BTCWitness_ so CheckConsensus can validate.
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, header.ParentBlockCoinbaseTx);

        // Reset these fields:
        header.HashBlock.SetNull();
        header.Index = 0;

        // Copy BTC’s merkle path into FB header’s MerkleBranch (for consensus check),
        // then compute FB’s chain‐side merkle path:
        header.MerkleBranch.resize(BTCMerklePath_.size());
        for (size_t j = 0; j < BTCMerklePath_.size(); j++) {
            header.MerkleBranch[j] = BTCMerklePath_[j];
        }

        std::vector<uint256> path;
        buildMerklePath(fbHeaderHashes_, fbWorkMap_[workIdx], path);
        header.ChainMerkleBranch.resize(path.size());
        for (size_t j = 0; j < path.size(); j++) {
            header.ChainMerkleBranch[j] = path[j];
        }

        header.ChainIndex = static_cast<int>(fbWorkMap_[workIdx]);
        header.ParentBlock = BTCHeader_;
    }

    return true;
}

double
Stratum::MergedWork::expectedWork(size_t workIdx)
{
    if (workIdx == 0 && btcWork()) {
        return BTC::expectedWork(BTCHeader_, BTCConsensusCtx_);
    }
    return FB::expectedWork(fbHeaders_[workIdx - 1], fbConsensusCtx_[0]);
}

void
Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
    if (workIdx == 0 && btcWork()) {
        btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
        return;
    }

    unsigned idx = static_cast<unsigned>(workIdx - 1);
    auto* fbW = static_cast<FB::Stratum::FbWork*>(secondWorks[idx]);
    fbW->buildBlockImpl(fbHeaders_[idx], fbWitness_[idx], blockHexData);
}

CCheckStatus
Stratum::MergedWork::checkConsensus(size_t workIdx)
{
    if (workIdx == 0 && btcWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, fbConsensusCtx_[0]);
    }
    unsigned idx = static_cast<unsigned>(workIdx - 1);
    auto* fbW = static_cast<FB::Stratum::FbWork*>(secondWorks[idx]);
    return FB::Stratum::FbWork::checkConsensusImpl(fbHeaders_[idx], BTCConsensusCtx_);
}

////////////////////////////////////////////////////////////////////////////////
// Stratum::prepareForSubmit (top‐level dispatcher)
////////////////////////////////////////////////////////////////////////////////

bool
Stratum::prepareForSubmit(const CWorkerConfig &workerCfg,
                          const CStratumMessage &msg)
{
    if (btcWork()) {
        if (!btcWork()->prepareForSubmitImpl(
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

    // If there are no FB secondaries, nothing more to do
    if (Works_.size() <= 1) {
        return true;
    }

    // For each FB secondary, rebuild its coinbase and merkle fields
    for (unsigned i = 1; i < Works_.size(); i++) {
        auto* fbW = static_cast<FB::Stratum::FbWork*>(Works_[i].Work);
        auto& header = fbHeaders_[i - 1];
        auto& legacy = fbLegacy_[i - 1];
        auto& witness= fbWitness_[i - 1];

        header = fbW->Header;

        // Build FB coinbase with zero‐extra‐nonce
        CMiningConfig noNonceCfg = MiningCfg_;
        noNonceCfg.FixedExtraNonceSize   = 0;
        noNonceCfg.MutableExtraNonceSize = 0;
        fbW->buildCoinbaseTx(nullptr, 0, noNonceCfg, legacy, witness);

        // Recompute FB’s merkle root into header.hashMerkleRoot
        {
            uint256 cbHash;
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha, legacy.Data.data(), legacy.Data.sizeOf());
            sha256Final(&sha, cbHash.begin());

            sha256Init(&sha);
            sha256Update(&sha, cbHash.begin(), sizeof(cbHash));
            sha256Final(&sha, cbHash.begin());

            header.hashMerkleRoot =
                calculateMerkleRootWithPath(cbHash,
                                            &fbW->MerklePath[0],
                                            fbW->MerklePath.size(),
                                            0);
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// Stratum::buildNotifyMessage (nearly identical to doge.cpp, tweaked for FB)
////////////////////////////////////////////////////////////////////////////////

void
Stratum::buildNotifyMessage(xmstream &stream,
                            const Proto::BlockHeader &header,
                            uint32_t extranonce1Size,
                            int &extranonce2Size,
                            const std::vector<base_blob<256>> &merkleBranch,
                            const CMiningConfig &mc,
                            bool segwitEnabled,
                            xmstream &out)
{
    serializeJson(stream, "algo",            mc.AlgoName);              stream.write(',');
    serializeJson(stream, "jobId",           header.GetHash());          stream.write(',');
    serializeJson(stream, "version",         header.nVersion);           stream.write(',');
    serializeJson(stream, "prevHash",        header.hashPrevBlock);      stream.write(',');
    serializeJson(stream, "merkleBranch",    merkleBranch);              stream.write(',');
    serializeJson(stream, "coinbase1",       mc.Coinbase1);             stream.write(',');
    serializeJson(stream, "coinbase2",       mc.Coinbase2);             stream.write(',');
    serializeJson(stream, "nBits",           header.nBits);              stream.write(',');
    serializeJson(stream, "nTime",           header.nTime);              stream.write(',');
    serializeJson(stream, "miningAddress",   mc.MiningAddress);         stream.write(',');
    serializeJson(stream, "extranonce1Size", extranonce1Size);          stream.write(',');
    serializeJson(stream, "extranonce2Size", extranonce2Size);          stream.write(',');
    serializeJson(stream, "segwit",          segwitEnabled);             stream.write(',');
    serializeJson(stream, "jobType",         mc.JobType);                stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch); stream.write(',');
    serializeJson(stream, "chainIndex",        header.ChainIndex);       stream.write(',');
    serializeJson(stream, "parentBlock",       header.ParentBlock);      stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "parentMerkleBranch",    header.ParentBlockMerkleBranch);
}

////////////////////////////////////////////////////////////////////////////////
// newPrimaryWork + newSecondaryWork
////////////////////////////////////////////////////////////////////////////////

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
////////////////////////////////////////////////////////////////////////////////

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
// Serialization for FB::Proto::BlockHeader
////////////////////////////////////////////////////////////////////////////////

void
BTC::Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data)
{
    BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);
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

void
serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header)
{
    serializeJson(stream, "version",           header.nVersion);           stream.write(',');
    serializeJson(stream, "hashPrevBlock",     header.hashPrevBlock);      stream.write(',');
    serializeJson(stream, "hashMerkleRoot",    header.hashMerkleRoot);     stream.write(',');
    serializeJson(stream, "time",              header.nTime);              stream.write(',');
    serializeJson(stream, "bits",              header.nBits);              stream.write(',');
    serializeJson(stream, "nonce",             header.nNonce);             stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "hashBlock",         header.HashBlock);          stream.write(',');
    serializeJson(stream, "merkleBranch",      header.MerkleBranch);       stream.write(',');
    serializeJson(stream, "index",             header.Index);              stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch);  stream.write(',');
    serializeJson(stream, "chainIndex",        header.ChainIndex);         stream.write(',');
    stream.write("\"parentBlock\":{");
    serializeJsonInside(stream, header.ParentBlock);
    stream.write('}');
}

} // namespace FB