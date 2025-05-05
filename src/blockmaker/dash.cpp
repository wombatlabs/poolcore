#include "blockmaker/dash.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "blockmaker/x11.h"
#include "blockmaker/btc.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t r = nNonce;
    r = r * 1103515245 + 12345;
    r += nChainId;
    r = r * 1103515245 + 12345;
    return r % (1u << h);
}

// X11 proof-of-work
CCheckStatus DASH::Proto::checkPow(const DASH::Proto::BlockHeader& header, uint32_t nBits) {
    arith_uint256 x11Hash;
    x11_hash(reinterpret_cast<const uint8_t*>(&header), sizeof(header), x11Hash.begin());
    CCheckStatus status;
    status.ShareDiff = BTC::difficultyFromBits(x11Hash.GetCompact(), 29);
    bool fNegative = false, fOverflow = false;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || bnTarget == 0 || fOverflow || x11Hash > bnTarget)
        return status;
    status.IsBlock = true;
    return status;
}

// Construct merged work: Bitcoin primary + Dash aux
DASH::Stratum::MergedWork::MergedWork(uint64_t workId,
                                     CSingleWork* btcW,
                                     CSingleWork* dashW,
                                     MiningConfig& cfg)
  : CMergedWork(workId, btcW, dashW, cfg)
{
    // Bitcoin context
    btcHeader_       = btcW->Header;
    btcLegacy_       = btcW->Legacy;
    btcWitness_      = btcW->Witness;
    btcMerklePath_   = btcW->MerklePath;
    btcConsensusCtx_ = btcW->ConsensusCtx;

    // Prepare Dash
    dashW->Header.nVersion |= DASH::Proto::VERSION_AUXPOW;
    dashHeader_       = dashW->Header;
    dashW->buildCoinbaseTx(nullptr, 0, cfg, dashLegacy_, dashWitness_);
    dashConsensusCtx_ = dashW->ConsensusCtx;

    // Compute hashBlock (big-endian reversed)
    auto h = dashHeader_.GetHash();
    std::reverse(h.begin(), h.end());
    dashHeader_.hashBlock = h;

    // Aux merkle
    dashMerklePath_ = btcMerklePath_;
    dashHeader_.Index = 0;
    dashHeader_.chainMerkleBranch.clear();
    dashHeader_.chainIndex = 0;
    dashHeader_.parentBlock = btcHeader_;
}

bool DASH::Stratum::MergedWork::prepareForSubmit(const WorkerConfig& worker,
                                                const StratumMessage& msg)
{
    // Submit Bitcoin share
    if (!BTC::Stratum::Work::prepareForSubmitImpl(
           btcHeader_, btcLegacy_, btcWitness_, btcMerklePath_,
           worker, miningCfg_, msg))
        return false;

    // Extract aux coinbase from BTC
    xmstream& cb = btcWitness_.Data;
    cb.seekSet(0);
    BTC::Io<DASH::Proto::BlockHeader>::unserialize(cb, dashHeader_);

    // Append aux header for Dash
    xmstream& out = dashWitness_.Data;
    BTC::Io<DASH::Proto::BlockHeader>::serialize(out, dashHeader_);
    return true;
}

// JSON serialization for Dash headers
namespace BTC {
template<> struct Io<DASH::Proto::BlockHeader> {
    static void serialize(xmstream& dst, const DASH::Proto::BlockHeader& h) {
        serializeJson(dst, "hashPrevBlock", h.hashPrevBlock); dst.write(',');
        serializeJson(dst, "hashMerkleRoot", h.hashMerkleRoot); dst.write(',');
        serializeJson(dst, "time", h.nTime); dst.write(',');
        serializeJson(dst, "bits", h.nBits); dst.write(',');
        serializeJson(dst, "nonce", h.nNonce); dst.write(',');
        serializeJson(dst, "parentCoinbaseTx", h.parentCoinbaseTx); dst.write(',');
        serializeJson(dst, "hashBlock", h.hashBlock); dst.write(',');
        serializeJson(dst, "merkleBranch", h.merkleBranch); dst.write(',');
        serializeJson(dst, "Index", h.Index); dst.write(',');
        serializeJson(dst, "chainMerkleBranch", h.chainMerkleBranch); dst.write(',');
        serializeJson(dst, "chainIndex", h.chainIndex); dst.write(',');
        dst.write("\"parentBlock\":{"); serializeJsonInside(dst, h.parentBlock); dst.write('}');
    }
    static void unserialize(xmstream& src, DASH::Proto::BlockHeader& h) {
        DASH::Proto::unserialize(src, h);
    }
};
} // namespace BTC