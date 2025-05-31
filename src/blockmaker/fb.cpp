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

std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*>& secondary, uint32_t& nonce, unsigned& virtualHashesNum)
{
    std::vector<int> result(secondary.size());
    std::vector<int> chainMap;
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.assign(virtualHashesNum, 0);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
                FbWork* work = static_cast<FbWork*>(secondary[workIdx]);
                uint32_t chainId = work->Header.nVersion >> 16;
                uint32_t indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);

                if (chainMap[indexInMerkle] == 0) {
                    chainMap[indexInMerkle] = 1;
                    result[workIdx] = indexInMerkle;
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

    return finished ? result : std::vector<int>();
}

Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork* first,
                                std::vector<StratumSingleWork*>& second,
                                std::vector<int>& mmChainId,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig& miningCfg)
    : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // Copy BTC (primary) context
    BTCHeader_ = btcWork()->Header;
    BTCMerklePath_ = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

    // Resize secondary (FB) arrays
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    fbHeaderHashes_.assign(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // For each FB work, build a coinbase with empty extra nonce to compute header hash
    for (size_t workIdx = 0; workIdx < second.size(); workIdx++) {
        FbWork* work = static_cast<FbWork*>(second[workIdx]);
        FB::Proto::BlockHeader& header = fbHeaders_[workIdx];
        BTC::CoinbaseTx& legacy = fbLegacy_[workIdx];
        BTC::CoinbaseTx& witness = fbWitness_[workIdx];

        // Copy the FB header template
        header = work->Header;

        // Build coinbase with zero extra-nonce to compute partial merkle root
        CMiningConfig emptyCfg = miningCfg;
        emptyCfg.FixedExtraNonceSize = 0;
        emptyCfg.MutableExtraNonceSize = 0;
        work->buildCoinbaseTx(nullptr, 0, emptyCfg, legacy, witness);

        // Calculate the FB partial merkle root (double-SHA256 of legacy coinbase)
        uint256 coinbaseTxHash;
        CCtxSha256 sha256;
        sha256Init(&sha256);
        sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
        sha256Final(&sha256, coinbaseTxHash.begin());
        sha256Init(&sha256);
        sha256Update(&sha256, coinbaseTxHash.begin(), coinbaseTxHash.size());
        sha256Final(&sha256, coinbaseTxHash.begin());

        // Insert the computed FB partial merkle root into header
        header.hashMerkleRoot = calculateMerkleRootWithPath(
            coinbaseTxHash,
            &work->MerklePath[0],
            work->MerklePath.size(),
            0
        );
        header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;

        // Store the FB header hash in the appropriate position for chain merkle
        fbHeaderHashes_[fbWorkMap_[workIdx]] = header.GetHash();
    }

    // Build the merged chain merkle root (reverse the leaf order)
    uint256 chainMerkleRoot = calculateMerkleRoot(&fbHeaderHashes_[0], fbHeaderHashes_.size());
    std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

    // Prepare the merged BTC coinbase message prefix
    uint8_t buffer[1024];
    xmstream coinbaseMsg(buffer, sizeof(buffer));
    coinbaseMsg.reset();
    coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
    coinbaseMsg.write<uint32_t>(virtualHashesNum);
    coinbaseMsg.write<uint32_t>(mmNonce);

    // Build the final BTC coinbase including merged-mining payload
    btcWork()->buildCoinbaseTx(
        coinbaseMsg.data(),
        coinbaseMsg.sizeOf(),
        miningCfg,
        BTCLegacy_,
        BTCWitness_
    );

    // Copy FB consensus context from the first FB work
    fbConsensusCtx_ = fbWork(0)->ConsensusCtx_;
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig& workerCfg, const CStratumMessage& msg)
{
    // First prepare the BTC submission
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
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

    // Now prepare each FB header before sending
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        FB::Proto::BlockHeader& header = fbHeaders_[workIdx];

        // Unserialize the ParentBlockCoinbaseTx from BTCWitness_
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, header.ParentBlockCoinbaseTx);

        header.HashBlock.SetNull();
        header.Index = 0;

        // Copy BTC merkle branch into FB header
        header.MerkleBranch.resize(BTCMerklePath_.size());
        for (size_t j = 0; j < BTCMerklePath_.size(); j++) {
            header.MerkleBranch[j] = BTCMerklePath_[j];
        }

        // Build FB chain merkle branch for this workIdx
        std::vector<uint256> path;
        buildMerklePath(fbHeaderHashes_, fbWorkMap_[workIdx], path);
        header.ChainMerkleBranch.resize(path.size());
        for (size_t j = 0; j < path.size(); j++) {
            header.ChainMerkleBranch[j] = path[j];
        }
        header.ChainIndex = fbWorkMap_[workIdx];

        // Copy the parent block header from BTC
        header.ParentBlock = BTCHeader_;
    }

    return true;
}

} // namespace FB

// Specialize BTC::Io for FB::Proto::BlockHeader
namespace BTC {
template<>
void Io<FB::Proto::BlockHeader>::serialize(xmstream& dst, const FB::Proto::BlockHeader& data)
{
    // Serialize the common block header fields
    BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);

    // If we have aux-pow, serialize the extra FB fields
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

template<>
void Io<FB::Proto::BlockHeader>::unserialize(xmstream& src, FB::Proto::BlockHeader& data)
{
    // Unserialize the common block header fields
    BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&data);

    // If aux-pow flag is set, unserialize the extra FB fields
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
} // namespace BTC

// JSON serialization helper for FB block header
void serializeJsonInside(xmstream& stream, const FB::Proto::BlockHeader& header)
{
    serializeJson(stream, "version",          header.nVersion);            stream.write(',');
    serializeJson(stream, "hashPrevBlock",    header.hashPrevBlock);       stream.write(',');
    serializeJson(stream, "hashMerkleRoot",   header.hashMerkleRoot);      stream.write(',');
    serializeJson(stream, "time",             header.nTime);               stream.write(',');
    serializeJson(stream, "bits",             header.nBits);               stream.write(',');
    serializeJson(stream, "nonce",            header.nNonce);              stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "hashBlock",        header.HashBlock);           stream.write(',');
    serializeJson(stream, "merkleBranch",     header.MerkleBranch);        stream.write(',');
    serializeJson(stream, "index",            header.Index);               stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch);  stream.write(',');
    serializeJson(stream, "chainIndex",       header.ChainIndex);          stream.write(',');
    stream.write("\"parentBlock\":{");
    serializeJsonInside(stream, header.ParentBlock);
    stream.write('}');
}
