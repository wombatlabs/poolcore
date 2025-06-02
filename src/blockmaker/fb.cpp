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
    uint32_t r = nNonce;
    r = r * 1103515245 + 12345;
    r += nChainId;
    r = r * 1103515245 + 12345;
    return r % (1u << h);
}

namespace FB {

std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned &virtualHashesNum)
{
    std::vector<int> result;
    std::vector<int> chainMap;
    result.resize(secondary.size());

    // Try increasing merkle‐tree depths until we find a nonce that places each FB work in a unique leaf
    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);

        bool finished = false;
        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t w = 0; w < secondary.size(); w++) {
                // cast each StratumSingleWork* to FB::Stratum::FbWork*
                FB::Stratum::FbWork *work = static_cast<FB::Stratum::FbWork*>(secondary[w]->Work);
                uint32_t chainId = work->Header.nVersion >> 16;
                uint32_t idxInMerkle = getExpectedIndex(nonce, chainId, pathSize);

                if (chainMap[idxInMerkle] == 0) {
                    chainMap[idxInMerkle] = 1;
                    result[w] = idxInMerkle;
                } else {
                    finished = false;
                    break;
                }
            }
            if (finished) break;
        }

        if (!finished) {
            // try next depth
            continue;
        }
        return result;
    }

    // if we failed to find a good nonce/depth, return an empty vector
    return {};
}

Stratum::MergedWork::MergedWork(uint64_t               stratumWorkId,
                                StratumSingleWork     *first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int>      &mmChainId,
                                uint32_t               mmNonce,
                                unsigned               virtualHashesNum,
                                const CMiningConfig   &miningCfg)
    : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    //
    // Primary (BTC) fields:
    //
    BTCHeader_        = btcWork()->Header;
    BTCMerklePath_    = btcWork()->MerklePath;
    BTCConsensusCtx_  = btcWork()->ConsensusCtx_;

    //
    // Secondary (FB) fields:
    //
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    fbHeaderHashes_.resize(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 1) Build “static” FB coinbases (no mutable nonce yet), compute each FB header’s Merkle‐root, then record each FB header hash into fbHeaderHashes_ at position fbWorkMap_[w].
    for (size_t w = 0; w < fbHeaders_.size(); w++) {
        FB::Stratum::FbWork *f = fbWork(w);
        FB::Proto::BlockHeader &hdr   = fbHeaders_[w];
        BTC::CoinbaseTx       &legacy = fbLegacy_[w];
        BTC::CoinbaseTx       &wit    = fbWitness_[w];

        // copy the FB work’s header template into our array
        hdr = f->Header;

        // Build a “static” FB coinbase (no extra‐nonce), so we can compute a Merkle root
        CMiningConfig emptyCfg;
        emptyCfg.FixedExtraNonceSize   = 0;
        emptyCfg.MutableExtraNonceSize = 0;
        f->buildCoinbaseTx(nullptr, 0, emptyCfg, legacy, wit);

        // Compute FB header’s new nVersion (AUXPOW bit set)
        hdr.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;

        // Now compute the FB header’s Merkle root: double‐SHA256( legacy → witness ) + the work’s MerklePath[] 
        {
            uint256 cbHash;
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha, legacy.Data.data(), legacy.Data.sizeOf());
            sha256Final(&sha, cbHash.begin());

            sha256Init(&sha);
            sha256Update(&sha, cbHash.begin(), cbHash.size());
            sha256Final(&sha, cbHash.begin());

            hdr.hashMerkleRoot = calculateMerkleRootWithPath(cbHash, &f->MerklePath[0], f->MerklePath.size(), 0);
        }

        // Place this FB header’s ID into fbHeaderHashes_ at the index chosen by fbWorkMap_
        fbHeaderHashes_[fbWorkMap_[w]] = hdr.GetHash();
    }

    //
    // 2) Compute reversed Merkle root over all fbHeaderHashes_[…], then append that into the BTC coinbase “merged header”
    //
    uint256 chainMerkleRoot = calculateMerkleRoot(&fbHeaderHashes_[0], fbHeaderHashes_.size());
    std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

    // Build a BTC‐style merged coinbase (“pchMergedMiningHeader + chainMerkleRoot + size + nonce”)
    {
        uint8_t buffer[1024];
        xmstream coinbaseMsg(buffer, sizeof(buffer));
        coinbaseMsg.reset();
        coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
        coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
        coinbaseMsg.write<uint32_t>(virtualHashesNum);
        coinbaseMsg.write<uint32_t>(mmNonce);

        btcWork()->buildCoinbaseTx(coinbaseMsg.data(), coinbaseMsg.sizeOf(), miningCfg, BTCLegacy_, BTCWitness_);
    }

    // 3) Grab the FB ConsensusCtx from the first FB work
    fbConsensusCtx_ = fbWork(0)->ConsensusCtx_;
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg)
{
    // First call into BTC’s prepareForSubmitImpl (version + coinbase + merkle + nTime + nBits + nNonce, etc.)
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
            BTCHeader_, BTCHeader_.nVersion,
            BTCLegacy_, BTCWitness_, BTCMerklePath_,
            workerCfg, MiningCfg_, msg))
    {
        return false;
    }

    // Next, for each FB header, we need to reconstruct the auxiliary‐chain fields:
    for (size_t i = 0; i < fbHeaders_.size(); i++) {
        FB::Proto::BlockHeader &hdr = fbHeaders_[i];

        // rewind the BTCWitness_ xmstream so we can pull out the FB’s parent coinbase
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, hdr.ParentBlockCoinbaseTx);

        // zero out fields not yet set
        hdr.HashBlock.SetNull();
        hdr.Index = 0;

        // copy BTC’s MerklePath into hdr.MerkleBranch
        hdr.MerkleBranch.resize(BTCMerklePath_.size());
        for (size_t j = 0; j < BTCMerklePath_.size(); j++) {
            hdr.MerkleBranch[j] = BTCMerklePath_[j];
        }

        // build FB’s ChainMerkleBranch from the position we recorded in fbWorkMap_[i]
        {
            std::vector<uint256> path;
            buildMerklePath(fbHeaderHashes_, fbWorkMap_[i], path);
            hdr.ChainMerkleBranch.resize(path.size());
            for (size_t j = 0; j < path.size(); j++) {
                hdr.ChainMerkleBranch[j] = path[j];
            }
        }

        // set chain index
        hdr.ChainIndex = fbWorkMap_[i];

        // copy BTCHeader_ as hdr.ParentBlock
        hdr.ParentBlock = BTCHeader_;
    }

    return true;
}

} // namespace FB

void BTC::Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data)
{
    // serialize the “pure” (common) 6‐field header first
    BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);

    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        // now serialize the aux‐fields:
        BTC::serialize(dst, data.ParentBlockCoinbaseTx);
        BTC::serialize(dst, data.HashBlock);
        BTC::serialize(dst, data.MerkleBranch);
        BTC::serialize(dst, data.Index);
        BTC::serialize(dst, data.ChainMerkleBranch);
        BTC::serialize(dst, data.ChainIndex);
        BTC::serialize(dst, data.ParentBlock);
    }
}

void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &hdr)
{
    serializeJson(stream, "version", hdr.nVersion);           stream.write(',');
    serializeJson(stream, "hashPrevBlock", hdr.hashPrevBlock);stream.write(',');
    serializeJson(stream, "hashMerkleRoot", hdr.hashMerkleRoot); stream.write(',');
    serializeJson(stream, "time", hdr.nTime);                  stream.write(',');
    serializeJson(stream, "bits", hdr.nBits);                  stream.write(',');
    serializeJson(stream, "nonce", hdr.nNonce);                stream.write(',');
    serializeJson(stream, "parentBlockCoinbaseTx", hdr.ParentBlockCoinbaseTx); stream.write(',');
    serializeJson(stream, "hashBlock", hdr.HashBlock);         stream.write(',');
    serializeJson(stream, "merkleBranch", hdr.MerkleBranch);   stream.write(',');
    serializeJson(stream, "index", hdr.Index);                 stream.write(',');
    serializeJson(stream, "chainMerkleBranch", hdr.ChainMerkleBranch); stream.write(',');
    serializeJson(stream, "chainIndex", hdr.ChainIndex);       stream.write(',');
    stream.write("\"parentBlock\":{");
    serializeJsonInside(stream, hdr.ParentBlock);
    stream.write('}');
}