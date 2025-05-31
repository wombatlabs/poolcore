#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

static unsigned merklePathSize(unsigned count) {
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1u << h);
}

namespace FB {

std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*>& secondary,
    uint32_t& nonce,
    unsigned& virtualHashesNum)
{
    std::vector<int> result(secondary.size());
    std::vector<int> chainMap;
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; ++pathSize) {
        virtualHashesNum = 1u << pathSize;
        chainMap.assign(virtualHashesNum, 0);

        for (nonce = 0; nonce < virtualHashesNum; ++nonce) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondary.size(); ++workIdx) {
                FbWork* work = static_cast<FbWork*>(secondary[workIdx]->Work);
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

    return (finished ? result : std::vector<int>());
}

Stratum::MergedWork::MergedWork(
    uint64_t stratumWorkId,
    StratumSingleWork* first,
    std::vector<StratumSingleWork*>& second,
    std::vector<int>& mmChainId,
    uint32_t mmNonce,
    unsigned virtualHashesNum,
    const CMiningConfig& miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // Copy primary BTC work fields
    BTCHeader_      = btcWork()->Header;
    BTCMerklePath_  = btcWork()->MerklePath;
    BTCConsensusCtx_= btcWork()->ConsensusCtx;

    // Resize FB-specific containers
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    fbHeaderHashes_.assign(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // Build each FB header (auxpow payload)
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); ++workIdx) {
        FbWork* work = fbWork(workIdx);
        FB::Proto::BlockHeader& header = fbHeaders_[workIdx];
        BTC::CoinbaseTx& legacy = fbLegacy_[workIdx];
        BTC::CoinbaseTx& witness = fbWitness_[workIdx];

        // Copy the raw FB header from the secondary work
        header = work->Header;

        // Build an “empty-extra-nonce” FB coinbase (both legacy & witness)
        CMiningConfig tmpCfg = miningCfg;
        tmpCfg.FixedExtraNonceSize   = 0;
        tmpCfg.MutableExtraNonceSize = 0;
        work->buildCoinbaseTx(nullptr, 0, tmpCfg, legacy, witness);

        // Mark this as AUXPOW and compute the FB merkle root using FB coinbase
        header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
        {
            uint256 coinbaseHash;
            CCtxSha256 sha256;
            sha256Init(&sha256);
            sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
            sha256Final(&sha256, coinbaseHash.begin());
            sha256Init(&sha256);
            sha256Update(&sha256, coinbaseHash.begin(), coinbaseHash.size());
            sha256Final(&sha256, coinbaseHash.begin());

            header.hashMerkleRoot = 
                calculateMerkleRootWithPath(
                    coinbaseHash,
                    work->MerklePath.data(),
                    work->MerklePath.size(),
                    0
                );
        }

        // Store the FB header’s hash into a flat array
        fbHeaderHashes_[fbWorkMap_[workIdx]] = header.GetHash();
    }

    // Build the cross-chain merkle root over all FB header‐hashes
    uint256 chainRoot = calculateMerkleRoot(fbHeaderHashes_.data(), fbHeaderHashes_.size());
    std::reverse(chainRoot.begin(), chainRoot.end());

    // Prepare actual BTC coinbase payload including merged-mining tag
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

    // Finally, keep FB consensus context from the first FB work
    fbConsensusCtx_ = fbWork(0)->ConsensusCtx;
}

bool Stratum::MergedWork::prepareForSubmit(
    const CWorkerConfig& workerCfg,
    const CStratumMessage& msg
) {
    // First, let BTC::Work do its own validation & POP submission
    if (!btcWork()->prepareForSubmitImpl(
            BTCHeader_,
            BTCHeader_.nVersion,
            BTCLegacy_,
            BTCWitness_,
            BTCMerklePath_,
            workerCfg,
            MiningCfg_,
            msg
        ))
    {
        return false;
    }

    // For each FB header, fill in its auxpow fields with the BTC context
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); ++workIdx) {
        FB::Proto::BlockHeader& header = fbHeaders_[workIdx];

        // Unserialize parent coinbase TX from BTCWitness_ into FB header
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, header.ParentBlockCoinbaseTx);

        header.HashBlock.SetNull();
        header.Index = 0;

        // Copy BTC merkle‐path to FB header
        header.MerkleBranch.resize(BTCMerklePath_.size());
        for (size_t j = 0; j < BTCMerklePath_.size(); ++j) {
            header.MerkleBranch[j] = BTCMerklePath_[j];
        }

        // Build FB’s own merkle path & index
        std::vector<uint256> auxPath;
        buildMerklePath(fbHeaderHashes_, fbWorkMap_[workIdx], auxPath);

        header.ChainMerkleBranch.resize(auxPath.size());
        for (size_t j = 0; j < auxPath.size(); ++j) {
            header.ChainMerkleBranch[j] = auxPath[j];
        }

        header.ChainIndex    = fbWorkMap_[workIdx];
        header.ParentBlock   = BTCHeader_;
    }

    return true;
}

} // namespace FB

//
// Specialization of BTC::Io for FB auxiliary‐proof‐of‐work headers
//
void BTC::Io<FB::Proto::BlockHeader>::serialize(
    xmstream& dst,
    const FB::Proto::BlockHeader& data
) {
    // Serialize the “pure” block‐header fields first
    BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);

    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        // Then append AUXPOW-specific fields:
        // 1) parent‐coinbase TX
        // 2) hashBlock, MerkleBranch, Index
        // 3) ChainMerkleBranch, ChainIndex, ParentBlock
        BTC::serialize(dst, data.ParentBlockCoinbaseTx);

        BTC::serialize(dst, data.HashBlock);
        BTC::serialize(dst, data.MerkleBranch);
        BTC::serialize(dst, data.Index);

        BTC::serialize(dst, data.ChainMerkleBranch);
        BTC::serialize(dst, data.ChainIndex);
        BTC::serialize(dst, data.ParentBlock);
    }
}

void BTC::Io<FB::Proto::BlockHeader>::unserialize(
    xmstream& src,
    FB::Proto::BlockHeader& data
) {
    // Read back the common header fields
    BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&data);

    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        // Unserialize AUXPOW‐specific data
        BTC::unserialize(src, data.ParentBlockCoinbaseTx);

        BTC::unserialize(src, data.HashBlock);
        BTC::unserialize(src, data.MerkleBranch);
        BTC::unserialize(src, data.Index);

        BTC::unserialize(src, data.ChainMerkleBranch);
        BTC::unserialize(src, data.ChainIndex);
        BTC::unserialize(src, data.ParentBlock);
    }
}

void serializeJsonInside(xmstream& stream, const FB::Proto::BlockHeader& header) {
    serializeJson(stream, "version",          header.nVersion);               stream.write(',');
    serializeJson(stream, "hashPrevBlock",    header.hashPrevBlock);           stream.write(',');
    serializeJson(stream, "hashMerkleRoot",   header.hashMerkleRoot);          stream.write(',');
    serializeJson(stream, "time",             header.nTime);                   stream.write(',');
    serializeJson(stream, "bits",             header.nBits);                   stream.write(',');
    serializeJson(stream, "nonce",            header.nNonce);                  stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "hashBlock",        header.HashBlock);               stream.write(',');
    serializeJson(stream, "merkleBranch",     header.MerkleBranch);            stream.write(',');
    serializeJson(stream, "index",            header.Index);                   stream.write(',');
    serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch);       stream.write(',');
    serializeJson(stream, "chainIndex",       header.ChainIndex);              stream.write(',');
    stream.write("\"parentBlock\":{");
    serializeJsonInside(stream, header.ParentBlock);
    stream.write('}');
}
