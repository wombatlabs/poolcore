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
// buildChainMap: identical to DOGE::buildChainMap, except we cast to FbWork*.
//
std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondaries,
    uint32_t                       &nonce,
    unsigned                       &virtualHashesNum
) {
    std::vector<int> result(secondaries.size());
    std::vector<int> chainMap;
    bool finished = false;

    // 1) Compute how many leaves we need at minimum:
    unsigned count = static_cast<unsigned>(secondaries.size());
    unsigned minPathSize = merklePathSize(count);

    // If minPathSize >= 8, (1<<minPathSize) >= 256, which we do NOT support
    // (we only allow up to height 7, i.e. 128 leaves). Just bail out:
    if (minPathSize >= 8) {
        virtualHashesNum = 0;
        return { };
    }

    // 2) Try all pathSizes from that minimum up to 7 (inclusive):
    for (unsigned pathSize = minPathSize; pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);

        // 3) Try every nonce until we find a collision-free assignment or exhaust all nonces:
        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondaries.size(); workIdx++) {
                // each StratumSingleWork* is itself the FbWork instance:
                FbWork *work = static_cast<FbWork*>( secondaries[workIdx] );

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
                // Found a valid nonce for this pathSize
                break;
            }
        }

        if (finished) {
            // We found a collision-free assignment at this pathSize
            break;
        }
    }

    // 4) If we never found a collision-free arrangement, return empty:
    if (!finished) {
        virtualHashesNum = 0;
        return { };
    }

    return result;
}

//
// MergedWork constructor: copy+adapt from DOGE::Stratum::MergedWork,
// replacing DOGE/LTC with FB/BTC.
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

    if (second.size() > 128) {
        // We only support up to 128 secondaries per FB‐chain.
        MiningCfg_ = miningCfg;
        throw std::runtime_error("FB: too many secondaries");
    }
    if (virtualHashesNum > (1u << 7)) {
        // That would mean a 128‐element or bigger chain,
        // which FB does not support. Bail out:
        MiningCfg_ = miningCfg;
        throw std::runtime_error("FB: invalid virtualHashesNum");
    }
    // 1) Copy “primary” (BTC) header + merkle + consensus‐ctx:
    BTCHeader_       = btcWork()->Header;
    BTCMerklePath_   = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;  // <-- correct field name

    // 2) Prepare FB secondaries:
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());
    fbHeaderHashes_.resize(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 3) Build “static” FB coinbase + compute each secondary’s merkle root hash:
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        Stratum::FbWork *work = fbWork(workIdx);
        FB::Proto::BlockHeader &header = fbHeaders_[workIdx];
        BTC::CoinbaseTx &legacy = fbLegacy_[workIdx];
        BTC::CoinbaseTx &witness = fbWitness_[workIdx];

        header = work->Header;

        // Build a “static” FB coinbase (no extra‐nonce) so we can calculate merkle root:
        CMiningConfig emptyCfg;
        emptyCfg.FixedExtraNonceSize   = 0;
        emptyCfg.MutableExtraNonceSize = 0;
        work->buildCoinbaseTx(nullptr, 0, emptyCfg, legacy, witness);

        // Mark AuxPoW bit:
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

    // 5) Pack <pchMergedMiningHeader> | <chainMerkleRoot> | <virtualHashesNum> | <mmNonce> into BTC coinbase extra‐data:
    uint8_t buffer[1024];
    xmstream coinbaseMsg(buffer, sizeof(buffer));
    coinbaseMsg.reset();
    coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
    coinbaseMsg.write<uint32_t>(virtualHashesNum);
    coinbaseMsg.write<uint32_t>(mmNonce);

    btcWork()->buildCoinbaseTx(coinbaseMsg.data(), coinbaseMsg.sizeOf(), miningCfg, BTCLegacy_, BTCWitness_);

    // 6) Capture consensus context for each FB header so we can validate on submit:
    fbConsensusCtx_.resize(second.size());

    // **You must initialize fbChainParams_ here** (e.g. from your config). Example:
    //    fbChainParams_ = loadFbChainParams();
    //
    MiningCfg_ = miningCfg;
}

Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    // shareHash = hash of the “primary” (BTC) header:
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
    // Just bump primary’s nTime and re‐emit notify:
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
    // 1) Validate primary (BTC) share:
    //    Must pass a uint32_t asicBoostData = 0 for SHA256:
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
            BTCHeader_,        // header
            uint32_t(0),       // asicBoostData
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

    // 2) For each FB header, unpack the AuxPoW fields and verify its POW:
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        FB::Proto::BlockHeader &header = fbHeaders_[workIdx];

        // Rewind BTCWitness_.Data to the start, then unserialize the embedded FB ParentBlockCoinbaseTx:
        BTCWitness_.Data.seekSet(0);
        BTC::unserialize(BTCWitness_.Data, header.ParentBlockCoinbaseTx);

        // Clear HashBlock & Index for POW‐check:
        header.HashBlock.SetNull();
        header.Index = 0;

        // Attach the same merkle path for the “aux” leafs (built from primary’s merkle tree):
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

        // Finally, verify this FB header’s POW:
        CCheckStatus status = FB::Proto::checkConsensus(
            header,
            fbConsensusCtx_[workIdx],
            fbChainParams_    // must be initialized correctly
        );
        if (!status.IsBlock) {
            return false;
        }
    }

    return true;
}

void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
    if (workIdx == 0 && btcWork()) {
        // Submit primary (BTC):
        btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
    } else if (fbWork(workIdx - 1)) {
        // Submit secondary (FB):
        fbWork(workIdx - 1)->buildBlockImpl(
            fbHeaders_[workIdx - 1],
            fbWitness_[workIdx - 1],
            blockHexData
        );
    }
}

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
    if (workIdx == 0 && btcWork()) {
        // Validate the primary (BTC) header:
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
// Standalone FB primary work:
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
    // Ownership passes to caller; return FbWork* (alias Work*):
    return work.release();
}

//
// FB as a “secondary” under a BTC primary:
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
    // Return as Work* (alias to FbWork*):
    return work.release();
}

//
// When BTC primary + FB secondaries come together:
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
    // Find a valid chainMap for the FB secondaries:
    uint32_t mmNonce = 0;
    unsigned virtualHashesNum = 0;
    std::vector<int> chainMap = buildChainMap(second, mmNonce, virtualHashesNum);
    if (chainMap.empty()) {
        error = "chainId conflict";
        return nullptr;
    }
    // Construct the MergedWork:
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
// Provide Io<FB::Proto::BlockHeader> serialize/unserialize inside namespace BTC
//
namespace BTC {

void Io<FB::Proto::BlockHeader>::serialize(
    xmstream &dst,
    const FB::Proto::BlockHeader &data
) {
    // Base BTC header (the first 80 bytes):
    BTC::serialize(dst, static_cast<const FB::Proto::PureBlockHeader&>(data));

    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        // Now serialize each AuxPoW field:
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
    // Base BTC header:
    BTC::unserialize(src, static_cast<FB::Proto::PureBlockHeader&>(data));

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
