#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "poolcommon/debug.h"  // <— adjust to whatever header actually defines LOG_INFO / LOG_DEBUG

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

std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                        uint32_t &nonce,
                                        unsigned &virtualHashesNum)
{
    LOG_INFO("FB::Stratum::buildChainMap called with {} secondaries", secondary.size());
    std::vector<int> result(secondary.size());
    std::vector<int> chainMap;
    bool finished = true;

    unsigned startPathSize = merklePathSize(secondary.size());
    LOG_DEBUG("  initial merklePathSize = {}", startPathSize);

    for (unsigned pathSize = startPathSize; pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);
        LOG_DEBUG("  trying pathSize={}, virtualHashesNum={}", pathSize, virtualHashesNum);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
                FB::Stratum::FbWork *work = static_cast<FB::Stratum::FbWork*>(secondary[workIdx]);
                uint32_t chainId       = work->Header.nVersion >> 16;
                uint32_t indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);

                if (chainMap[indexInMerkle] == 0) {
                    chainMap[indexInMerkle] = 1;
                    result[workIdx] = indexInMerkle;
                    LOG_DEBUG("    workIdx={} → chainId=0x{:x}, indexInMerkle={}", workIdx, chainId, indexInMerkle);
                } else {
                    finished = false;
                    break;
                }
            }
            if (finished) {
                LOG_INFO("  buildChainMap succeeded at pathSize={}, nonce={}", pathSize, nonce);
                break;
            }
        }
        if (finished) break;
        else LOG_DEBUG("  pathSize={} failed, moving to next", pathSize);
    }

    if (!finished) {
        LOG_ERROR("FB::Stratum::buildChainMap failed to find a non‐conflicting map");
        return {};
    }

    return result;
}

Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int> &mmChainId,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig &miningCfg)
    : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    LOG_INFO("FB::Stratum::MergedWork constructor: stratumWorkId={}, {} secondaries", 
             stratumWorkId, second.size());

    // (1) Copy BTC (primary) header + context
    BTCHeader_       = btcWork()->Header;
    BTCMerklePath_   = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx_;
    LOG_DEBUG("  Copied BTC header: version=0x{:x}, nTime={}, nBits=0x{:x}",
              BTCHeader_.nVersion, BTCHeader_.nTime, BTCHeader_.nBits);

    // (2) Resize FB data structures
    FBHeader_.resize(second.size());
    FBLegacy_.resize(second.size());
    FBWitness_.resize(second.size());
    FBHeaderHashes_.resize(virtualHashesNum, uint256());
    FBWorkMap_.assign(mmChainId.begin(), mmChainId.end());
    LOG_DEBUG("  FBHeader_ resized to {}, virtualHashesNum={}", FBHeader_.size(), virtualHashesNum);

    // (3) For each FB work: set AuxPoW bit, build static coinbase, compute Merkle root
    for (size_t workIdx = 0; workIdx < FBHeader_.size(); workIdx++) {
        FB::Stratum::FbWork *work = fbWork(workIdx);
        FB::Proto::BlockHeader &header = FBHeader_[workIdx];
        BTC::CoinbaseTx &legacy = FBLegacy_[workIdx];
        BTC::CoinbaseTx &witness= FBWitness_[workIdx];

        header = work->Header;
        header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
        LOG_DEBUG("  [FB workIdx={}]: original version=0x{:x}, set VERSION_AUXPOW → version=0x{:x}", 
                  workIdx, work->Header.nVersion, header.nVersion);

        // Build coinbase WITHOUT extra-nonce
        CMiningConfig emptyExtraNonceCfg;
        emptyExtraNonceCfg.FixedExtraNonceSize   = 0;
        emptyExtraNonceCfg.MutableExtraNonceSize = 0;
        work->buildCoinbaseTx(nullptr, 0, emptyExtraNonceCfg, legacy, witness);

        // Double-SHA256 of legacy data
        uint256 coinbaseTxHash;
        CCtxSha256 sha256;
        sha256Init(&sha256);
        sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
        sha256Final(&sha256, coinbaseTxHash.begin());
        sha256Init(&sha256);
        sha256Update(&sha256, coinbaseTxHash.begin(), coinbaseTxHash.size());
        sha256Final(&sha256, coinbaseTxHash.begin());

        header.hashMerkleRoot = calculateMerkleRootWithPath(
                                    coinbaseTxHash,
                                    &work->MerklePath[0],
                                    work->MerklePath.size(),
                                    0);
        FBHeaderHashes_[FBWorkMap_[workIdx]] = header.GetHash();
        LOG_DEBUG("    FBHeader[{}].hashMerkleRoot={}, gethash={}", workIdx,
                  header.hashMerkleRoot.ToString().substr(0,16),
                  header.GetHash().ToString().substr(0,16));
    }

    // (4) Build reversed Merkle root from all FB header hashes
    uint256 chainMerkleRoot = calculateMerkleRoot(&FBHeaderHashes_[0], FBHeaderHashes_.size());
    std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());
    LOG_INFO("  Computed FB‐chain merkle root (reversed): {}", chainMerkleRoot.ToString());

    // (5) Prepend “mm” header to BTC coinbase
    uint8_t buffer[1024];
    xmstream coinbaseMsg(buffer, sizeof(buffer));
    coinbaseMsg.reset();

    coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
    coinbaseMsg.write<uint32_t>(virtualHashesNum);
    coinbaseMsg.write<uint32_t>(mmNonce);

    // Log the raw “mm‐header” prefix for debugging
    LOG_DEBUG("  Writing mm‐header: 0x%02x%02x%02x%02x + [FB merkle root] + virtualHashesNum={}, mmNonce={}",
              pchMergedMiningHeader[0], pchMergedMiningHeader[1],
              pchMergedMiningHeader[2], pchMergedMiningHeader[3],
              virtualHashesNum, mmNonce);

    btcWork()->buildCoinbaseTx(coinbaseMsg.data(),
                               coinbaseMsg.sizeOf(),
                               miningCfg,
                               BTCLegacy_,
                               BTCWitness_);

    // For extra clarity, log the final BTC coinbase script (hex)
    LOG_DEBUG("  Final BTC coinbase (hex): {}", BTCLegacy_.Data.toHex().substr(0, 64) + "…");

    FBConsensusCtx_ = fbWork(0)->ConsensusCtx_;
    LOG_INFO("FB::MergedWork construction complete");
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                           const CStratumMessage &msg)
{
    // The template code in stratumWorkStorage calls this for each workIdx.
    // We add a log to see which branch is taken:
    size_t workIdx = msg.WorkIndex;  // (assume StratumInstance sets WorkIndex)
    if (workIdx == 0 && btcWork()) {
        LOG_DEBUG("prepareForSubmit: using BTC work (primary) for workIdx=0");
        return btcWork()->prepareForSubmitImpl(
            BTCHeader_,
            BTCHeader_.nVersion,
            BTCLegacy_,
            BTCWitness_,
            BTCMerklePath_,
            workerCfg,
            MiningCfg_,
            msg
        );
    } else if (fbWork(workIdx - 1)) {
        LOG_DEBUG("prepareForSubmit: using FB work (secondary) for workIdx={}", workIdx);
        return fbWork(workIdx - 1)->prepareForSubmitImpl(
            FBHeader_[workIdx - 1],
            FBHeader_[workIdx - 1].nVersion,
            FBLegacy_[workIdx - 1],
            FBWitness_[workIdx - 1],
            /* FBMerklePath_ – if you track it inside FbWork */,
            workerCfg,
            MiningCfg_,
            msg
        );
    }
    LOG_ERROR("prepareForSubmit: invalid workIdx={} or missing work pointer", workIdx);
    return false;
}

} // namespace FB


void BTC::Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data)
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

//------------------------------------------------------------------------------------------------
// FB::serializeJsonInside: write JSON for FB::Proto::BlockHeader
//------------------------------------------------------------------------------------------------
void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header)
{
  serializeJson(stream, "version", header.nVersion); stream.write(',');
  serializeJson(stream, "hashPrevBlock", header.hashPrevBlock); stream.write(',');
  serializeJson(stream, "hashMerkleRoot", header.hashMerkleRoot); stream.write(',');
  serializeJson(stream, "time", header.nTime); stream.write(',');
  serializeJson(stream, "bits", header.nBits); stream.write(',');
  serializeJson(stream, "nonce", header.nNonce); stream.write(',');
  serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
  serializeJson(stream, "hashBlock", header.HashBlock); stream.write(',');
  serializeJson(stream, "merkleBranch", header.MerkleBranch); stream.write(',');
  serializeJson(stream, "index", header.Index); stream.write(',');
  serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch); stream.write(',');
  serializeJson(stream, "chainIndex", header.ChainIndex); stream.write(',');
  stream.write("\"parentBlock\":{");
  serializeJsonInside(stream, header.ParentBlock);
  stream.write('}');
}
