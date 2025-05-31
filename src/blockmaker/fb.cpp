// fract.cpp

#include "blockmaker/fract.h"
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

namespace FRACT {

//
// buildChainMap: identical to DOGE::buildChainMap except
// we cast to FractWork* instead of DogeWork*.
//

std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondaries,
    uint32_t                       &nonce,
    unsigned                       &virtualHashesNum
) {
    std::vector<int> result(secondaries.size());
    std::vector<int> chainMap;
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondaries.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondaries.size(); workIdx++) {
                FractWork *work = static_cast<FractWork*>(secondaries[workIdx]);
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

            if (finished) break;
        }

        if (finished) break;
    }

    return finished ? result : std::vector<int>();
}

//
// MergedWork constructor: copy+adapt from DOGE::Stratum::MergedWork, replacing DOGE/LTC with FRACT/BTC.
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
    // 1) Copy “primary” (BTC) header + merkle + consensus‐ctx:
    BTCHeader_      = btcWork()->Header;
    BTCMerklePath_  = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx;

    // 2) Prepare FB secondaries:
    fractHeaders_.resize(second.size());
    fractLegacy_.resize(second.size());
    fractWitness_.resize(second.size());
    fractHeaderHashes_.resize(virtualHashesNum, uint256());
    fractWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 3) Build “static” FB coinbase + compute each secondary’s merkle root hash:
    for (size_t workIdx = 0; workIdx < fractHeaders_.size(); workIdx++) {
        FractWork *work = fractWork(workIdx);
        FRACT::Proto::BlockHeader &header = fractHeaders_[workIdx];
        BTC::CoinbaseTx &legacy = fractLegacy_[workIdx];
        BTC::CoinbaseTx &witness = fractWitness_[workIdx];

        header = work->Header;

        // Build a “static” FB coinbase (no extra‐nonce) so we can calculate merkle root:
        CMiningConfig emptyCfg;
        emptyCfg.FixedExtraNonceSize   = 0;
        emptyCfg.MutableExtraNonceSize = 0;
        work->buildCoinbaseTx(nullptr, 0, emptyCfg, legacy, witness);

        // Mark AuxPoW bit:
        header.nVersion |= FRACT::Proto::BlockHeader::VERSION_AUXPOW;

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
        fractHeaderHashes_[mmChainId[workIdx]] = header.GetHash();
    }

    // 4) Compute the “chain merkle root” over all fractHeaderHashes_[] and reverse bytes:
    uint256 chainMerkleRoot = calculateMerkleRoot(&fractHeaderHashes_[0], fractHeaderHashes_.size());
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
    fractConsensusCtx_.resize(second.size());
    fractChainParams_ = /* load FB chain params (powLimit, etc.) from your config */;
    MiningCfg_       = miningCfg;
}

Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    // shareHash = hash of the “primary” (BTC) header:
    return BTCHeader_.GetHash();
}

std::string Stratum::MergedWork::blockHash(size_t workIdx) {
    if (workIdx == 0) {
        return BTCHeader_.GetHash().ToString();
    } else if (workIdx - 1 < fractHeaders_.size()) {
        return fractHeaders_[workIdx - 1].GetHash().ToString();
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

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) {
    // 1) Validate primary (BTC) share:
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
            BTCHeader_,
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

    // 2) For each FB header, unpack the AuxPoW fields and verify its POW:
    for (size_t workIdx = 0; workIdx < fractHeaders_.size(); workIdx++) {
        FRACT::Proto::BlockHeader &header = fractHeaders_[workIdx];

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
            fractHeaderHashes_,
            fractWorkMap_[workIdx],
            path
        );
        header.ChainMerkleBranch.resize(path.size());
        for (size_t j = 0; j < path.size(); j++) {
            header.ChainMerkleBranch[j] = path[j];
        }
        header.ChainIndex   = fractWorkMap_[workIdx];
        header.ParentBlock  = BTCHeader_;

        // Finally, verify this FB header’s POW:
        CCheckStatus status = FRACT::Proto::checkConsensus(
            header,
            fractConsensusCtx_[workIdx],
            fractChainParams_
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
    } else if (fractWork(workIdx - 1)) {
        // Submit secondary (FB):
        fractWork(workIdx - 1)->buildBlockImpl(
            fractHeaders_[workIdx - 1],
            fractWitness_[workIdx - 1],
            blockHexData
        );
    }
}

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
    if (workIdx == 0 && btcWork()) {
        // Validate the primary (BTC) header:
        return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, BTCConsensusCtx_);
    } else if (fractWork(workIdx - 1)) {
        // Validate this FB header’s POW:
        return FRACT::Proto::checkConsensus(
            fractHeaders_[workIdx - 1],
            fractConsensusCtx_[workIdx - 1],
            fractChainParams_
        );
    }
    return CCheckStatus();
}

//
// Io<Proto::BlockHeader> serialize already declared above; implement it here:
//
void BTC::Io<FRACT::Proto::BlockHeader>::serialize(xmstream &dst, const FRACT::Proto::BlockHeader &data) {
    // Base BTC header:
    BTC::serialize(dst, *(FRACT::Proto::PureBlockHeader*)&data);
    if (data.nVersion & FRACT::Proto::BlockHeader::VERSION_AUXPOW) {
        BTC::serialize(dst, data.ParentBlockCoinbaseTx);
        BTC::serialize(dst, data.HashBlock);
        BTC::serialize(dst, data.MerkleBranch);
        BTC::serialize(dst, data.Index);
        BTC::serialize(dst, data.ChainMerkleBranch);
        BTC::serialize(dst, data.ChainIndex);
        BTC::serialize(dst, data.ParentBlock);
    }
}

void BTC::Io<FRACT::Proto::BlockHeader>::unserialize(xmstream &src, FRACT::Proto::BlockHeader &data) {
    // Base BTC header:
    BTC::unserialize(src, *(FRACT::Proto::PureBlockHeader*)&data);
    if (data.nVersion & FRACT::Proto::BlockHeader::VERSION_AUXPOW) {
        BTC::unserialize(src, data.ParentBlockCoinbaseTx);
        BTC::unserialize(src, data.HashBlock);
        BTC::unserialize(src, data.MerkleBranch);
        BTC::unserialize(src, data.Index);
        BTC::unserialize(src, data.ChainMerkleBranch);
        BTC::unserialize(src, data.ChainIndex);
        BTC::unserialize(src, data.ParentBlock);
    }
}

//
// JSON serialization helper for FB headers:
//
void serializeJsonInside(xmstream &stream, const FRACT::Proto::BlockHeader &header) {
    serializeJson(stream, "version",       header.nVersion);       stream.write(',');
    serializeJson(stream, "hashPrevBlock", header.hashPrevBlock);  stream.write(',');
    serializeJson(stream, "hashMerkleRoot",header.hashMerkleRoot); stream.write(',');
    serializeJson(stream, "time",          header.nTime);          stream.write(',');
    serializeJson(stream, "bits",          header.nBits);
}

//
// Standalone FB primary work:
//
BTC::Stratum::Work* Stratum::newPrimaryWork(
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
    std::unique_ptr<FractWork> work(new FractWork(
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

//
// FB as a “secondary” under a BTC primary:
//
FractWork* Stratum::newSecondaryWork(
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
    std::unique_ptr<FractWork> work(new FractWork(
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

} // namespace FRACT
