// fb.cpp
#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

// --------------------------------------------------------------------------------
// 1. SerializeJson helper: either correct every serializeJson(...) call to pass a
//    field name, or stub it out if you don't need GBT JSON for mining.
// --------------------------------------------------------------------------------
#if 1
static void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &h) {
    // Example of correct usage; you can remove or #if 0 out any parts you don't use:
    serializeJson(stream, "version", h.nVersion);
    serializeJson(stream, "prevblockhash", h.hashPrevBlock);
    serializeJson(stream, "time", h.nTime);
    serializeJson(stream, "bits", h.nBits);
    serializeJson(stream, "nonce", h.nNonce);
    if (h.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        // Only emit AuxPoW JSON if merged mining is enabled:
        serializeJson(stream, "parentcoinbase", h.ParentBlockCoinbaseTx);
        serializeJson(stream, "parentblockhash", h.HashBlock);
        // Build merkle branch array in JSON:
        serializeJson(stream, "merklebranch", h.MerkleBranch);
        writeNumber(stream, static_cast<uint32_t>(h.Index));
        serializeJson(stream, "chainmerklebranch", h.ChainMerkleBranch);
        writeNumber(stream, static_cast<uint32_t>(h.ChainIndex));
        serializeJson(stream, "parentblock", h.ParentBlock);
    }
}
#else
// If you do not need JSON at all, simply do nothing:
static void serializeJsonInside(xmstream &, const FB::Proto::BlockHeader &) { }
#endif

// --------------------------------------------------------------------------------
// 2. Provide Io<FB::Proto::BlockHeader> so FB header serializes exactly like AuxPoW
// --------------------------------------------------------------------------------
namespace BTC {
void Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data) {
    // First serialize the “pure” 80‐byte header:
    BTC::Io<FB::Proto::PureBlockHeader>::serialize(dst, (const FB::Proto::PureBlockHeader&)data);

    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
        // Serialize AuxPoW fields exactly as BTC does:
        BTC::serialize(dst, data.ParentBlockCoinbaseTx);
        BTC::serialize(dst, data.HashBlock);
        BTC::serialize(dst, data.MerkleBranch);
        BTC::serialize(dst, data.Index);
        BTC::serialize(dst, data.ChainMerkleBranch);
        BTC::serialize(dst, data.ChainIndex);
        BTC::serialize(dst, data.ParentBlock);
    }
}

void Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &data) {
    // Stub out if you never need to parse an AuxPoW header from incoming data:
    // Otherwise implement the inverse of serialize(...) above.
}
} // namespace BTC

// --------------------------------------------------------------------------------
// 3. Helper to render JSON fields (called by the “getblocktemplate” path, if ever used):
// --------------------------------------------------------------------------------
void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header) {
    // NOTE: This is already defined above under #if 1.
}

// --------------------------------------------------------------------------------
// 4. “stratum work” implementation for FB
// --------------------------------------------------------------------------------
namespace FB {

// BuildChainMap: identical to DOGE, but cast to FbWork instead of DgWork.
std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondaries,
    uint32_t                       &nonce,
    unsigned                       &virtualHashesNum
) {
    std::vector<int> result(secondaries.size());
    bool finished = false;
    std::vector<int> chainMap;

    for (unsigned pathSize = merklePathSize(secondaries.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = (1u << pathSize);
        chainMap.assign(virtualHashesNum, 0);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            std::fill(chainMap.begin(), chainMap.end(), 0);
            finished = true;

            for (size_t i = 0; i < secondaries.size(); i++) {
                auto *fw = static_cast<FbWork*>(secondaries[i]);  // FB work is the “child”
                int    chainId      = (fw->Header.nVersion >> 16);
                unsigned indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);
                if (chainMap[indexInMerkle] == 0) {
                    chainMap[indexInMerkle] = 1;
                    result[i] = indexInMerkle;
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

// --------------------------------------------------------------------------------
// 5. MergedWork constructor: copy primary (BTC) + all secondaries (FB)
// --------------------------------------------------------------------------------
Stratum::MergedWork::MergedWork(
    uint64_t                          stratumWorkId,
    StratumSingleWork               *first,
    std::vector<StratumSingleWork*>  &second,
    std::vector<int>                 &mmChainId,
    uint32_t                          mmNonce,
    unsigned                          virtualHashesNum,
    const CMiningConfig              &miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg)
  , MiningCfg_(miningCfg)
{
    // 5.1. Extract primary (BTC) info:
    auto *bw = static_cast<BTC::Stratum::Work*>(first);
    btcWork()->HeaderBuilder.writeHeader(bw->Header);  // ensure header is populated
    BTCHeader_       = bw->Header;
    {
        // Instead of direct assignment, swap or serialize+deserialize:
        xmstream tmp;
        bw->CBTxLegacy_.serialize(tmp);
        BTCLegacy_.reset();
        BTCLegacy_.deserialize(tmp);
    }
    {
        xmstream tmp;
        bw->CBTxWitness_.serialize(tmp);
        BTCWitness_.reset();
        BTCWitness_.deserialize(tmp);
    }
    BTCMerklePath_     = bw->MerklePath;
    BTCConsensusCtx_   = bw->ConsensusCtx_;

    // 5.2. Reserve space for each FB secondary:
    size_t nSec = second.size();
    fbHeaders_       .resize(nSec);
    fbLegacy_        .resize(nSec);
    fbWitness_       .resize(nSec);
    fbHeaderHashes_  .resize(nSec);
    fbWorkMap_       .resize(nSec);
    fbConsensusCtx_  .resize(nSec);

    // 5.3. Copy each secondary’s header + coinbase  
    for (size_t i = 0; i < nSec; i++) {
        auto *fw = static_cast<FbWork*>(second[i]);
        fbWorkMap_[i] = mmChainId[i];

        // Copy the FB header fields (pure‐BTC part + AuxPoW fields)
        fbHeaders_[i].nVersion        = fw->Header.nVersion;
        fbHeaders_[i].hashPrevBlock   = fw->Header.hashPrevBlock;
        fbHeaders_[i].hashMerkleRoot  = fw->Header.hashMerkleRoot;
        fbHeaders_[i].nTime           = fw->Header.nTime;
        fbHeaders_[i].nBits           = fw->Header.nBits;
        fbHeaders_[i].nNonce          = fw->Header.nNonce;

        // Copy child’s AuxPoW template header (Prime’s “parent” block inside FB work):
        fbHeaders_[i].ParentBlockCoinbaseTx = fw->Header.ParentBlockCoinbaseTx;
        fbHeaders_[i].HashBlock               = fw->Header.HashBlock;

        // Merge the MerkleBranch into an xvector:
        {
            xvector<uint256> xv;
            xv.reserve(fw->Header.MerkleBranch.size());
            for (auto &h : fw->Header.MerkleBranch) xv.push_back(h);
            fbHeaders_[i].MerkleBranch = std::move(xv);
        }
        fbHeaders_[i].Index = fw->Header.Index;

        // Chain‐Merkle:
        {
            xvector<uint256> xv2;
            xv2.reserve(fw->Header.ChainMerkleBranch.size());
            for (auto &h : fw->Header.ChainMerkleBranch) xv2.push_back(h);
            fbHeaders_[i].ChainMerkleBranch = std::move(xv2);
        }
        fbHeaders_[i].ChainIndex = fw->Header.ChainIndex;
        fbHeaders_[i].ParentBlock = fw->Header.ParentBlock;

        // Copy the child coinbase:
        {
            xmstream tmp;
            fw->CBTxLegacy_.serialize(tmp);
            fbLegacy_[i].reset();
            fbLegacy_[i].deserialize(tmp);
        }
        {
            xmstream tmp;
            fw->CBTxWitness_.serialize(tmp);
            fbWitness_[i].reset();
            fbWitness_[i].deserialize(tmp);
        }

        // Save the child’s header hash for checkConsensus later:
        fbHeaderHashes_[i] = fw->getBlockHash();
        fbConsensusCtx_[i] = fw->ConsensusCtx_;  // copy the CheckConsensus context
    }

    // 5.4. Load FB chainParams (for consensus‐checking of secondaries):
    fbChainParams_ = miningCfg.FBChainParams; // assume your CMiningConfig holds a ChainParams for FB

    // 5.5. (Now perform exactly the same loop DOGE does:
    //        • insert pchMergedMiningHeader into primary’s coinbase,
    //        • recompute primary merkle root,
    //        • build all AuxPoW branches inside Primary coinbase script)
    //
    //    Copy the code from doge.cpp, replacing DOGE:: → FB:: everywhere.
}

// --------------------------------------------------------------------------------
// 6. shareHash(): delegate to primary’s shareHash()
// --------------------------------------------------------------------------------
FB::Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    return btcWork()->shareHash();
}

// --------------------------------------------------------------------------------
// 7. blockHash(): delegate to primary’s blockHash(index=0)
// --------------------------------------------------------------------------------
std::string Stratum::MergedWork::blockHash(size_t workIdx) {
    if (workIdx == 0) {
        return btcWork()->blockHash(0);
    } else {
        // If client wants the FB‐secondary’s blockhash, return its precomputed header hash:
        return fbHeaderHashes_[workIdx - 1].ToString();
    }
}

// --------------------------------------------------------------------------------
// 8. mutate(): same as DOGE (mutate primary only; secondaries stay constant)
// --------------------------------------------------------------------------------
void Stratum::MergedWork::mutate() {
    btcWork()->mutate();
    // no changes to fbHeaders_ here
}

// --------------------------------------------------------------------------------
// 9. buildNotifyMessage(reset?): same as BTC→DOGE: call primary’s notify
// --------------------------------------------------------------------------------
void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork) {
    btcWork()->buildNotifyMessage(resetPreviousWork);
}

// --------------------------------------------------------------------------------
// 10. prepareForSubmit: serialize the primary + each AuxPoW child
// --------------------------------------------------------------------------------
bool Stratum::MergedWork::prepareForSubmit(
    const CWorkerConfig &workerCfg,
    const CStratumMessage &msg
) {
    // 10.1. Let BTC’s prepareForSubmitImpl handle the primary:
    bool okPrimary = BTC::Stratum::Work::prepareForSubmitImpl(
                         BTCHeader_,
                         BTCHeader_.nVersion,
                         BTCLegacy_,
                         BTCWitness_,
                         BTCMerklePath_,
                         workerCfg,
                         MiningCfg_,
                         msg
                     );
    if (!okPrimary) return false;

    // 10.2. Now append our AuxPoW JSON fields: get the real “submit” stream object:
    //       (Replace getSubmitStream() with however your version exposes it:)
    xmstream &stream = msg.SubmitStream; // or msg.submitPayload, etc.

    // 10.3. Write “auxpow”‐fields exactly as DOGE does:
    // For each secondary i:
    for (size_t i = 0; i < fbHeaders_.size(); i++) {
        stream.write(",\"parentblock\":");
        serializeJson(stream, "parentblock", fbHeaders_[i].ParentBlock);
        stream.write(",\"parentcoinbase\":");
        serializeJson(stream, "parentcoinbase", fbHeaders_[i].ParentBlockCoinbaseTx);
        stream.write(",\"hashblock\":");
        serializeJson(stream, "hashblock", fbHeaders_[i].HashBlock);
        stream.write(",\"merklebranch\":");
        serializeJson(stream, "merklebranch", fbHeaders_[i].MerkleBranch);
        stream.write(",\"index\":"); writeNumber(stream, static_cast<uint32_t>(fbHeaders_[i].Index));
        stream.write(",\"chainmerklebranch\":");
        serializeJson(stream, "chainmerklebranch", fbHeaders_[i].ChainMerkleBranch);
        stream.write(",\"chainindex\":"); writeNumber(stream, static_cast<uint32_t>(fbHeaders_[i].ChainIndex));
        stream.write(",\"parentheader\":");
        serializeJson(stream, "parentheader", fbHeaders_[i].ParentBlock);
    }

    return true;
}

// --------------------------------------------------------------------------------
// 11. buildBlock(): build the full block hex for a given workIdx (0=primary, >0=secondary?)
// --------------------------------------------------------------------------------
void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
    if (workIdx == 0) {
        btcWork()->buildBlock(0, blockHexData);
    } else {
        // FB‐secondary alone (standalone mining); delegate to fbWork():
        fbWork(workIdx - 1)->buildBlock(0, blockHexData);
    }
}

// --------------------------------------------------------------------------------
// 12. checkConsensus(): first check primary, then check secondaries if merged
// --------------------------------------------------------------------------------
CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
    if (workIdx == 0) {
        // Check primary (BTC) consensus using BTCConsensusCtx_ and BTCHeader_:
        auto status = BTC::Proto::checkConsensus(BTCHeader_, BTCConsensusCtx_, MiningCfg_.BTCChainParams);
        return status;
    } else {
        // Check the i‐th FB child’s consensus on its own header:
        auto &ctx = fbConsensusCtx_[workIdx - 1];
        auto &hdr = fbHeaders_[workIdx - 1];
        auto cst = FB::Proto::checkConsensus(hdr, ctx, fbChainParams_);
        return cst;
    }
}

// --------------------------------------------------------------------------------
// 13. newPrimaryWork: same as BTC’s newPrimaryWork, but allocates an FbWork
// --------------------------------------------------------------------------------
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
    return BTC::Stratum::newPrimaryWork<FbWork>(
        stratumId, backend, backendIdx, miningCfg, miningAddress, coinbaseMessage, blockTemplate, error
    );
}

// --------------------------------------------------------------------------------
// 14. newSecondaryWork: identical to DOGE’s but for FbWork
// --------------------------------------------------------------------------------
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
    return BTC::Stratum::newPrimaryWork<FbWork>(
        stratumId, backend, backendIdx, miningCfg, miningAddress, coinbaseMessage, blockTemplate, error
    );
}

// --------------------------------------------------------------------------------
// 15. newMergedWork: exactly follow DOGE’s pattern, but use FB’s buildChainMap()
// --------------------------------------------------------------------------------
StratumMergedWork* Stratum::newMergedWork(
    int64_t                       stratumId,
    StratumSingleWork           *first,
    std::vector<StratumSingleWork*> &second,
    const CMiningConfig          &miningCfg,
    std::string                  &error
) {
    // 15.1. Let BTC buildChainMap() pick nonce + chain slots for FB secondaries
    uint32_t mmNonce = 0;
    unsigned virtHashes = 0;
    auto slotMap = Stratum::buildChainMap(second, mmNonce, virtHashes);
    if (slotMap.empty()) {
        error = "failed to allocate unique slots for FB secondaries under AuxPoW";
        return nullptr;
    }

    return new MergedWork(stratumId, first, second, slotMap, mmNonce, virtHashes, miningCfg);
}

} // namespace FB
