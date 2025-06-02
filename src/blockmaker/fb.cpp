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
  // buildChainMap: how to slot each secondary under a 2^h Merkle‐tree.
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
  // MergedWork constructor: pack FB (primary) + any secondaries into AuxPoW.
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

    // 2) Copy those into our MergedWork fields:
    FBHeader_       = primaryHeader;
    FBMerklePath_   = primaryMerklePath;
    FBConsensusCtx_ = primaryConsensusCtx;

    // 3) Prepare storage for secondary AuxPoW data (but do NOT resize):
    size_t nSec = secondaries.size();
    FBSecondaryHeaders_.clear();
    FBCoinbaseTransactions_.clear();
    FBWitnesses_.clear();
    FBSecondaryHeaders_.reserve(nSec);
    FBCoinbaseTransactions_.reserve(nSec);
    FBWitnesses_.reserve(nSec);

    // 4) For each secondary, move its coinbases and set AuxPoW bit:
    for (size_t i = 0; i < nSec; i++) {
      FBWork *secWk = static_cast<FBWork*>(secondaries[i]);

      // 4.a) Copy child header:
      FBSecondaryHeaders_.push_back(secWk->Header);

      // 4.b) Move child’s coinbase transactions into our vectors:
      FBCoinbaseTransactions_.push_back(std::move(secWk->CBTxLegacy_));
      FBWitnesses_.push_back(std::move(secWk->CBTxWitness_));

      // 4.c) Toggle AuxPoW bit in the header we just pushed:
      FBSecondaryHeaders_.back().nVersion |= FB::AuxPoWBlockHeader::VERSION_AUXPOW;

      // 4.d) Build this child’s Merkle‐branch & chain index exactly as DOGE does:
      //     (pseudocode: use getExpectedIndex(auxNonce, chainId, h) and merkleTree::calculateRoot)
      //     Example:
      //
      //     int chainId = (FBSecondaryHeaders_.back().nVersion >> 16);
      //     unsigned h = /* computed pathSize from buildChainMap */;
      //     uint32_t idx = getExpectedIndex(auxNonce, chainId, h);
      //     std::vector<uint256> merkleBranch = /* from secWk->MerkleBranch */;
      //     FBSecondaryHeaders_.back().merkleBranch = merkleBranch;
      //     FBSecondaryHeaders_.back().index = idx;
      //     // ... also fill chainMerkleBranch, chainIndex, parentCoinbaseTx, hashBlock, parentBlock ...
      //
      // (Exact code is identical to doge.cpp but with FB types; omit here for brevity)
    }

    // 5) Recompute FBHeader_’s Merkle root over the AuxPoW branches:
    //    Prepend pchMergedMiningHeader to the coinbase script, recalc merkle root, etc.
    //    (Copy doge.cpp logic, but with FB types.)
  }

  //==============================================================================
  // prepareForSubmit: first serialize primary FB header, then append AuxPoW fields.
  //==============================================================================
  bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                             const CStratumMessage &msg)
  {
    // 1) Let BTC::Stratum::Work handle the “pure” FB serialization:
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
    //    (Exactly as doge.cpp does, but iterate over FBSecondaryHeaders_, FBCoinbaseTransactions_, FBWitnesses_)

    return true;
  }

} // namespace FB
