// fb.cpp

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
    return rand % (1 << h);
}

namespace FB {

//
// Build a collision‐free “chain map” for up to 128 secondaries.
// If there are more than 128 secondaries (minPathSize ≥ 8), bail out.
//
std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondaries,
    uint32_t                       &nonce,
    unsigned                       &virtualHashesNum
) {
    std::vector<int> result(secondaries.size());
    std::vector<int> chainMap;
    bool finished = false;

    unsigned count = static_cast<unsigned>(secondaries.size());
    unsigned minPathSize = merklePathSize(count);

    if (minPathSize >= 8) {
        // Too many secondaries to fit in a 2^h merkle tree for h < 8
        virtualHashesNum = 0;
        return {};
    }

    for (unsigned pathSize = minPathSize; pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondaries.size(); workIdx++) {
                FbWork *work = static_cast<FbWork*>(secondaries[workIdx]);
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
                // Found a nonce that yields no collisions for this pathSize
                break;
            }
        }

        if (finished) {
            // We found a valid assignment for this pathSize
            break;
        }
    }

    if (!finished) {
        virtualHashesNum = 0;
        return {};
    }

    return result;
}

//
// MergedWork constructor: one BTC primary + N FB secondaries.
//
Stratum::MergedWork::MergedWork(
    uint64_t                         stratumWorkId,
    StratumSingleWork              *first,
    std::vector<StratumSingleWork*> &second,
    std::vector<int>                &mmChainId,
    uint32_t                         mmNonce,
    unsigned                         virtualHashesNum,
    const CMiningConfig             &miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // 1) Copy the BTC “primary” header + merkle path + consensus‐ctx
    BTCHeader_       = btcWork()->Header;
    BTCMerklePath_   = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

    // 2) Prepare FB secondaries:
    if (second.size() > 128) {
        throw std::runtime_error("FB: too many secondaries (max 128)");
    }
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());

    if (virtualHashesNum > 128) {
        throw std::runtime_error("FB: virtualHashesNum too large (max 128)");
    }
    fbHeaderHashes_.resize(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 3) Build a “static” FB coinbase for each secondary, compute each FB header’s merkle root:
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        FbWork *work = fbWork(workIdx);
        FB::Proto::BlockHeader &header = fbHeaders_[workIdx];
        BTC::CoinbaseTx &legacy = fbLegacy_[workIdx];
        BTC::CoinbaseTx &witness = fbWitness_[workIdx];

        // Copy the secondary’s header as a starting point
        header = work->Header;

        // Build a “static” FB coinbase (no extra‐nonce) so we can calculate merkle root:
        CMiningConfig emptyCfg;
        emptyCfg.FixedExtraNonceSize   = 0;
        emptyCfg.MutableExtraNonceSize = 0;
        work->buildCoinbaseTx(nullptr, 0, emptyCfg, legacy, witness);

        // Mark the AuxPoW bit:
        header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;

        // Compute coinbaseTxHash = double‐SHA256(legacy.Data):
        uint256 coinbaseTxHash;
        {
            CCtxSha256 shaCtx;
            sha256Init(&shaCtx);
            sha256Update(&shaCtx, legacy.Data.data(), legacy.Data.sizeOf());
            sha256Final(&shaCtx, coinbaseTxHash.begin());
            sha256Init(&shaCtx);
            sha256Update(&shaCtx, coinbaseTxHash.begin(), coinbaseTxHash.size());
            sha256Final(&shaCtx, coinbaseTxHash.begin());
        }

        // Build header.hashMerkleRoot from that coinbaseTxHash + work->MerklePath:
        header.hashMerkleRoot = calculateMerkleRootWithPath(
            coinbaseTxHash,
            &work->MerklePath[0],
            work->MerklePath.size(),
            /* index = */ 0
        );

        // Store the hashed FB header at position mmChainId[workIdx]:
        fbHeaderHashes_[mmChainId[workIdx]] = header.GetHash();
    }

    // 4) Compute the “chain merkle root” over all fbHeaderHashes_[] and reverse bytes:
    uint256 chainMerkleRoot = calculateMerkleRoot(&fbHeaderHashes_[0], fbHeaderHashes_.size());
    std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

    // 5) Pack exactly 44 bytes of merged‐mining header:
    //
    //     [ pchMergedMiningHeader (4 bytes)
    //     | chainMerkleRoot         (32 bytes)
    //     | virtualHashesNum (4 bytes, LE)
    //     | mmNonce           (4 bytes, LE) ]
    //
    {
        std::vector<uint8_t> extraData;
        extraData.reserve(4 + sizeof(uint256) + 4 + 4);

        // 5.1) pchMergedMiningHeader (4 bytes)
        extraData.insert(extraData.end(),
                         pchMergedMiningHeader,
                         pchMergedMiningHeader + sizeof(pchMergedMiningHeader));

        // 5.2) chainMerkleRoot (32 bytes)
        const uint8_t *rootBytes = chainMerkleRoot.begin();
        extraData.insert(extraData.end(),
                         rootBytes,
                         rootBytes + sizeof(uint256));

        // 5.3) virtualHashesNum (4 bytes, LE)
        {
            uint32_t vh_le = virtualHashesNum;
            uint8_t *bytes = reinterpret_cast<uint8_t*>(&vh_le);
            extraData.insert(extraData.end(), bytes, bytes + sizeof(uint32_t));
        }

        // 5.4) mmNonce (4 bytes, LE)
        {
            uint32_t mm_le = mmNonce;
            uint8_t *bytes = reinterpret_cast<uint8_t*>(&mm_le);
            extraData.insert(extraData.end(), bytes, bytes + sizeof(uint32_t));
        }

        // 5.5) Now call buildCoinbaseTx with all nine required arguments:
        btcWork()->buildCoinbaseTx(
            extraData.data(),                      // merged‐mining header pointer
            extraData.size(),                      // length == 44
            btcWork()->CoinbaseMessage,            // primary BTC’s coinbaseMessage (std::string&)
            btcWork()->MiningAddress,              // primary BTC’s miningAddress (const vector<uint8_t>&)
            miningCfg,                             // CMiningConfig
            false,                                 // segwitEnabled = false for merged SHA256
            std::vector<uint8_t>(),                // empty witnessCommitment
            BTCLegacy_,                            // CoinbaseTx& for legacy
            BTCWitness_                            // CoinbaseTx& for witness
        );
    }

    // 6) Capture consensus context for each FB header so we can validate on submit:
    fbConsensusCtx_.resize(second.size());

    // TODO: Initialize fbChainParams_ from your FB chain parameters (powLimit, etc.)
    //   fbChainParams_ = loadFbChainParams();
    MiningCfg_ = miningCfg;
}

Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    return BTCHeader_.GetHash();
}

std::string Stratum::MergedWork::blockHash(size_t workIdx) {
    if (workIdx == 0) {
        return BTCHeader_.GetHash().ToString();
    } else if (workIdx - 1 < fbHeaders_.size()) {
        return fbHeaders_[workIdx - 1].GetHash().ToString();
    }
    return std::string();
}

void Stratum::MergedWork::mutate() {
    BTCHeader_.nTime = static_cast<uint32_t>(time(nullptr));
    BTC::Stratum::Work::buildNotifyMessageImpl(
        this,
        BTCHeader_,
        BTCHeader_.nVersion,
        BTCLegacy_,
        BTCMerklePath_,
        MiningCfg_,
        /* reset = */ true,
        NotifyMessage_
    );
}

void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork) {
    BTC::Stratum::Work::buildNotifyMessageImpl(
        this,
        BTCHeader_,
        BTCHeader_.nVersion,
        BTCLegacy_,
        BTCMerklePath_,
        MiningCfg_,
        resetPreviousWork,
        NotifyMessage_
    );
}

bool Stratum::MergedWork::prepareForSubmit(
    const CWorkerConfig   &workerCfg,
    const CStratumMessage &msg
) {
    // 1) Validate the BTC primary share:
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
            BTCHeader_,        // header
            uint32_t(0),       // asicBoostData = 0 for SHA256
            BTCLegacy_,        // coinbase legacy
            BTCWitness_,       // coinbase witness
            BTCMerklePath_,    // merkle path
            workerCfg,         // worker config
            MiningCfg_,        // mining config
            msg                // stratum message
        ))
    {
        return false;
    }

    // 2) For each FB header, unpack AuxPoW fields and verify its POW:
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        FB::Proto::BlockHeader &header = fbHeaders_[workIdx];

        // Rewind BTCWitness_.Data to the start, then unserialize the FB ParentBlockCoinbaseTx:
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, header.ParentBlockCoinbaseTx);

        // Clear HashBlock & Index for POW‐check
        header.HashBlock.SetNull();
        header.Index = 0;

        // Attach the same merkle path (from the BTC primary) for the “aux” leafs:
        header.MerkleBranch.resize(BTCMerklePath_.size());
        for (size_t j = 0; j < BTCMerklePath_.size(); j++) {
            header.MerkleBranch[j] = BTCMerklePath_[j];
        }

        // Build the chain‐merkle‐branch for this FB header:
        std::vector<uint256> path;
        buildMerklePath(
            fbHeaderHashes_,
            fbWorkMap_[workIdx],
            path
        );
        header.ChainMerkleBranch.resize(path.size());
        for (size_t j = 0; j < path.size(); j++) {
            header.ChainMerkleBranch[j] = path[j];
        }
        header.ChainIndex  = fbWorkMap_[workIdx];
        header.ParentBlock = BTCHeader_;

        // Finally, verify this FB header’s POW against our stored fbChainParams_:
        CCheckStatus status = FB::Proto::checkConsensus(
            header,
            fbConsensusCtx_[workIdx],
            fbChainParams_    // ensure you've initialized this properly elsewhere
        );
        if (!status.IsBlock) {
            return false;
        }
    }

    return true;
}

void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
    if (workIdx == 0 && btcWork()) {
        // Submit the BTC primary:
        btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
    } else if (fbWork(workIdx - 1)) {
        // Submit the FB secondary:
        fbWork(workIdx - 1)->buildBlockImpl(
            fbHeaders_[workIdx - 1],
            fbWitness_[workIdx - 1],
            blockHexData
        );
    }
}

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
    if (workIdx == 0 && btcWork()) {
        // Validate the BTC primary:
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, BTCConsensusCtx_);
    } else if (fbWork(workIdx - 1)) {
        // Validate this FB header’s POW:
        return FB::Proto::checkConsensus(
            fbHeaders_[workIdx - 1],
            fbConsensusCtx_[workIdx - 1],
            fbChainParams_
        );
    }
    return CCheckStatus();
}

//
// When FB stands alone (no merged mining), build an FB work:
//
Stratum::Work* Stratum::newPrimaryWork(
    int64_t                    stratumId,
    PoolBackend               *backend,
    size_t                     backendIdx,
    const CMiningConfig       &miningCfg,
    const std::vector<uint8_t> &miningAddress,
    const std::string         &coinbaseMessage,
    CBlockTemplate            &blockTemplate,
    std::string               &error
) {
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }
    auto work = std::make_unique<Stratum::FbWork>(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    );
    if (!work->loadFromTemplate(blockTemplate, error)) {
        return nullptr;
    }
    return work.release();
}

//
// When FB is a “secondary” under a BTC primary:
//
Stratum::Work* Stratum::newSecondaryWork(
    int64_t                    stratumId,
    PoolBackend               *backend,
    size_t                     backendIdx,
    const CMiningConfig       &miningCfg,
    const std::vector<uint8_t> &miningAddress,
    const std::string         &coinbaseMessage,
    CBlockTemplate            &blockTemplate,
    std::string               &error
) {
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type";
        return nullptr;
    }
    auto work = std::make_unique<Stratum::FbWork>(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    );
    if (!work->loadFromTemplate(blockTemplate, error)) {
        return nullptr;
    }
    return work.release();
}

//
// When BTC primary + one-or-more FB secondaries come together:
//
StratumMergedWork* Stratum::newMergedWork(
    int64_t                       stratumId,
    StratumSingleWork           *first,
    std::vector<StratumSingleWork*> &second,
    const CMiningConfig          &miningCfg,
    std::string                  &error
) {
    if (second.empty()) {
        error = "no secondary works";
        return nullptr;
    }
    uint32_t mmNonce = 0;
    unsigned virtualHashesNum = 0;
    std::vector<int> chainMap = buildChainMap(second, mmNonce, virtualHashesNum);
    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }
    return new MergedWork(
        stratumId,
        first,
        second,
        chainMap,
        mmNonce,
        virtualHashesNum,
        miningCfg
    );
}

} // namespace FB

//
// Provide serialize/unserialize specialization for FB::Proto::BlockHeader inside namespace BTC:
//
namespace BTC {

void Io<FB::Proto::BlockHeader>::serialize(
    xmstream &dst,
    const FB::Proto::BlockHeader &data
) {
    // First write the “pure” BTC header (80 bytes):
    BTC::serialize(dst, static_cast<const FB::Proto::PureBlockHeader&>(data));

    // If AuxPoW bit is set, write all AuxPoW fields:
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

void Io<FB::Proto::BlockHeader>::unserialize(
    xmstream &src,
    FB::Proto::BlockHeader &data
) {
    // First read the “pure” BTC header (80 bytes):
    BTC::unserialize(src, static_cast<FB::Proto::PureBlockHeader&>(data));

    // If AuxPoW bit is set, read all AuxPoW fields:
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
