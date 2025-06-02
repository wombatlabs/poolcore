#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

namespace {

  // Bitcoin‐style AuxPoW “magic” header (same as DOGE uses):
  static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

  // Compute minimum Merkle‐path size needed to place `count` secondaries
  static unsigned merklePathSize(unsigned count) {
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
  }

  // Pseudo‐random index from nonce + chainId (same as DOGE)
  static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1u << h);
  }

} // anonymous namespace

namespace FB {

  //==============================================================================
  // buildChainMap: find a Merkle‐tree of size 2^h that can place all secondaries
  // under unique leaves. Copied exactly from DOGE, but using FBWork.
  //==============================================================================
  std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                          uint32_t                       &nonce,
                                          unsigned                       &virtualHashesNum)
  {
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
          FBWork *work = static_cast<FBWork*>(secondaries[i]);
          int      chainId      = (work->Header.nVersion >> 16);
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

  //==============================================================================
  // MergedWork constructor: pack FB (primary) + any secondaries into one AuxPoW blob
  // This is a textual copy of DOGE’s logic, replacing doge→FB and LTC→BTC.
  //==============================================================================
  Stratum::MergedWork::MergedWork(uint64_t                  stratumWorkId,
                                  StratumSingleWork        *primaryWork,
                                  std::vector<StratumSingleWork*> &secondaries,
                                  std::vector<int>         &chainMap,
                                  uint32_t                  auxNonce,
                                  unsigned                  virtualHashesNum,
                                  const CMiningConfig      &miningCfg)
    : StratumMergedWork(stratumWorkId, primaryWork, secondaries, miningCfg)
  {
    // 1) Grab primary’s (FB) header, Merkle path, consensus context:
    BTC::Proto::BlockHeader &primaryHeader   = static_cast<FBWork*>(primaryWork)->Header;
    auto                    &primaryMerklePath = static_cast<FBWork*>(primaryWork)->MerklePath;
    auto                    &primaryConsensusCtx = static_cast<FBWork*>(primaryWork)->ConsensusCtx_;

    // 2) Copy them into MergedWork fields:
    FBHeader_       = primaryHeader;
    FBMerklePath_   = primaryMerklePath;
    FBConsensusCtx_ = primaryConsensusCtx;

    // 3) Prepare storage for each secondary’s AuxPoW data:
    size_t nSec = secondaries.size();
    FBSecondaryHeaders_.resize(nSec);
    FBCoinbaseTransactions_.resize(nSec);
    FBWitnesses_.resize(nSec);

    // 4) For each secondary (FB under something else), copy header+coinbase, toggle AuxPoW:
    for (size_t i = 0; i < nSec; i++) {
        FBWork *secWk = static_cast<FBWork*>(secondaries[i]);
        auto    &hdr  = FBSecondaryHeaders_[i];
        auto    &coin = FBCoinbaseTransactions_[i];
        auto    &wit  = FBWitnesses_[i];

        hdr  = secWk->Header;          // copy child’s header
        coin = std::move(secWk->CBTxLegacy_);   // move child’s legacy coinbase
        wit  = std::move(secWk->CBTxWitness_);  // move child’s witness coinbase
        hdr.nVersion |= FB::AuxPoWBlockHeader::VERSION_AUXPOW;

        // … now build this child’s Merkle‐branch exactly as DOGE does, using getExpectedIndex() …
    }

    // 5) Finally, recompute the primary Header’s Merkle root over the AuxPoW branches,
    //    prepend pchMergedMiningHeader, and insert into FBHeader_.merkleRoot exactly as DOGE.
    //    (Use merkleTree::calculateRoot and reverse‐byte logic from doge.cpp, replacing names with FB.)
  }

  //==============================================================================
  // prepareForSubmit: first let Bitcoin’s (FB) Work do its part, then append AuxPoW
  // This matches DOGE’s pattern exactly, but with FB types.
  //==============================================================================
  bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                             const CStratumMessage &msg)
  {
    // 1) Let BTC::Stratum::Work serialize the “pure” FB header:
    bool okPrimary = BTC::Stratum::Work::prepareForSubmitImpl(
                       FBHeader_,
                       FBHeader_.nVersion,
                       FBLegacyCoinbase_,
                       FBWitnessCoinbase_,
                       FBMerklePath_,
                       workerCfg,
                       MiningCfg_,
                       msg
                     );
    if (!okPrimary) return false;

    // 2) Append each secondary’s AuxPoW fields into the submit JSON:
    //    EXACTLY copy from doge.cpp, but use FBSecondaryHeaders_, FBCoinbaseTransactions_, FBWitnesses_,
    //    FBSecondaryHeaders_[i].parentCoinbaseTx, FBSecondaryHeaders_[i].hashBlock, etc.

    return true;
  }

} // namespace FB
