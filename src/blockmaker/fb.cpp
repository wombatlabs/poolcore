#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

namespace {

  // Bitcoin‐style AuxPoW “magic” header (same as DOGE’s 0xfabe' m' 'm'):
  static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

  // Compute the minimum Merkle‐path size needed to place `count` secondaries under a single root.
  // If count ≤ 1, path size = 0; otherwise it’s ceil(log2(count)).
  static unsigned merklePathSize(unsigned count) {
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
  }

  // Pseudo‐random index within [0, 2^h) for AuxPoW placement:
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
  // 1) buildChainMap: find a Merkle‐tree of size 2^h such that no two secondaries collide.
  //    Exactly the same algorithm as DOGE’s, just with FBWork instead of DogeWork.
  //==============================================================================
  std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                          uint32_t                       &nonce,
                                          unsigned                       &virtualHashesNum)
  {
    std::vector<int> result(secondaries.size());
    bool finished = false;
    std::vector<int> chainMap;

    // Try increasing tree‐height until all secondaries fit:
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
  // 2) MergedWork constructor: pack FB primary + any secondaries into one AuxPoW blob.
  //    Follows DOGE’s 4‐step recipe but with FB/BTC types.
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
    // 2.a) Grab the primary FB work (which itself is a BTC::WorkTy<FB::Proto,…>).
    BTC::Proto::BlockHeader &primaryHeader   = static_cast<FBWork*>(primaryWork)->Header;
    auto                    &primaryMerklePath = static_cast<FBWork*>(primaryWork)->MerklePath;
    auto                    &primaryConsensusCtx = static_cast<FBWork*>(primaryWork)->ConsensusCtx_;

    // 2.b) Copy those into our MergedWork fields:
    FBHeader_       = primaryHeader;
    FBMerklePath_   = primaryMerklePath;
    FBConsensusCtx_ = primaryConsensusCtx;

    // 2.c) Prepare storage for the secondaries (but do NOT resize, since CoinbaseTx is move-only):
    size_t nSec = secondaries.size();
    FBSecondaryHeaders_.clear();
    FBCoinbaseTransactions_.clear();
    FBWitnesses_.clear();
    FBSecondaryHeaders_.reserve(nSec);
    FBCoinbaseTransactions_.reserve(nSec);
    FBWitnesses_.reserve(nSec);

    // 2.d) For each FB secondary under something else (if FB were merged under another chain):
    for (size_t i = 0; i < nSec; i++) {
      FBWork *secWk = static_cast<FBWork*>(secondaries[i]);

      // 2.d.i) Copy the child’s header into FBSecondaryHeaders_:
      FBSecondaryHeaders_.push_back(secWk->Header);

      // 2.d.ii) Move the child’s coinbase transactions into our vectors:
      FBCoinbaseTransactions_.push_back(std::move(secWk->CBTxLegacy_));
      FBWitnesses_.push_back(std::move(secWk->CBTxWitness_));

      // 2.d.iii) Set the AuxPoW bit on that copied header:
      FBSecondaryHeaders_.back().nVersion |= FB::AuxPoWBlockHeader::VERSION_AUXPOW;

      // 2.d.iv) Build this child’s Merkle‐branch & chain index exactly as DOGE does:
      //
      //      int chainId = (FBSecondaryHeaders_.back().nVersion >> 16);
      //      unsigned h = /* pathSize from buildChainMap for this i */;
      //      uint32_t idx = getExpectedIndex(auxNonce, chainId, h);
      //      FBSecondaryHeaders_.back().index = idx;
      //      FBSecondaryHeaders_.back().merkleBranch = secWk->MerklePath;
      //      // chainMerkleBranch, chainIndex, parentCoinbaseTx, hashBlock, parentBlock:
      //      FBSecondaryHeaders_.back().chainMerkleBranch.clear(); // if no parent chain
      //      FBSecondaryHeaders_.back().chainIndex = 0;            // ditto
      //      FBSecondaryHeaders_.back().parentCoinbaseTx = secWk->Header.parentCoinbaseTx; // from AuxPoW payload
      //      FBSecondaryHeaders_.back().hashBlock         = secWk->Header.hashBlock;
      //      FBSecondaryHeaders_.back().parentBlock       = secWk->Header.parentBlock;
      //
      //    (The above five lines should be copied exactly from doge.cpp’s loop, substituting
      //     FBSecondaryHeaders_ instead of DOGESecondaryHeaders_, etc.)
      //
      //    In PoolCore’s doge.cpp, you’ll find something like:
      //      for (i=0..nSec):
      //        hdr = DOGESecondaryHeaders_[i];
      //        hdr.ParentBlockCoinbaseTx = secWk->ParentBlockCoinbaseTx;
      //        hdr.HashBlock = secWk->HashBlock;
      //        hdr.MerkleBranch = secWk->MerkleBranch;
      //        hdr.Index = getExpectedIndex(...);
      //        hdr.ChainMerkleBranch.clear();
      //        hdr.ChainIndex = 0;
      //        hdr.ParentBlock = secWk->ParentBlock;
      //
      //    So copy exactly that logic here, replacing DOGE types with FB types, LTC types with BTC types.
    }

    // 2.e) Once all secondaries are in FBSecondaryHeaders_, recalc the primary FBHeader_.merkleRoot:
    //      - Prepend pchMergedMiningHeader to the primary’s coinbase script (in FBLegacyCoinbase_)
    //      - Recompute the Merkle root over FBMerklePath_ plus all secondary roots
    //      - Set FBHeader_.merkleRoot accordingly
    //
    //    In doge.cpp, this looks like:
    //      merkleRoot = merkleTree::calculateRoot(secRootHash, secMerkleBranch);
    //      reverseBytes(merkleRoot);
    //      insert pchMergedMiningHeader + reversed merkleRoot into primary coinbase script
    //      primaryMerkleRoot = merkleTree::calculateRoot(primaryRootHash, primaryMerkleBranch)
    //      FBHeader_.merkleRoot = primaryMerkleRoot;
    //
    //    Copy that entire block from doge.cpp, replacing “LTC*” → “BTC*” and “DOGE*” → “FB*”.
  }

  //==============================================================================
  // 3) prepareForSubmit: first let BTC::Stratum::Work serialize “pure” FB header,
  //    then append each AuxPoW child exactly as DOGE does.
  //==============================================================================
  bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                             const CStratumMessage &msg)
  {
    // 3.a) Serialize the pure FB header (80‐byte BTC header) using Bitcoin’s Stratum::Work:
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

    // 3.b) Now append the AuxPoW JSON. DOGE’s code does something like:
    //      xmstream &stream = msg.getSubmitStream();
    //      stream.write(",\"auxpow\":{");
    //      // for each child i:
    //      stream.write("\"parentBlock\":");
    //      serializeJSON(stream, DOGESecondaryHeaders_[i].ParentBlock);
    //      stream.write(",\"merkleBranch\":[");
    //      for each hash in DOGESecondaryHeaders_[i].MerkleBranch: serializeJSON(stream, hash);
    //      stream.write("],");
    //      stream.write("\"index\":");
    //      stream.writeInt(DOGESecondaryHeaders_[i].Index);
    //      // and so on for chainMerkleBranch, chainIndex, parentCoinbaseTx, hashBlock, etc.
    //      stream.write("}");
    //
    //    In FB’s case, do the same, but use FBSecondaryHeaders_, FBCoinbaseTransactions_, FBWitnesses_.
    //
    //    Example (pseudocode):
    //      xmstream &stream = msg.getSubmitStream();
    //      stream.write(",\"auxpow\":{");
    //      // parentBlock:
    //      stream.write("\"parentBlock\":");
    //      serializeJSON(stream, FBSecondaryHeaders_[i].parentBlock);
    //      // merkleBranch array:
    //      stream.write(",\"merkleBranch\":[");
    //      for (auto &h : FBSecondaryHeaders_[i].merkleBranch) {
    //        serializeJSON(stream, h);
    //        if (not last) stream.write(",");
    //      }
    //      stream.write("]");
    //      // "index":
    //      stream.write(",\"index\":");
    //      stream.writeInt(FBSecondaryHeaders_[i].index);
    //      // "chainMerkleBranch":
    //      stream.write(",\"chainMerkleBranch\":[");
    //      for (auto &c : FBSecondaryHeaders_[i].chainMerkleBranch) {
    //        serializeJSON(stream, c);
    //        if (not last) stream.write(",");
    //      }
    //      stream.write("]");
    //      // "chainIndex":
    //      stream.write(",\"chainIndex\":");
    //      stream.writeInt(FBSecondaryHeaders_[i].chainIndex);
    //      // "parentCoinbaseTx":
    //      stream.write(",\"parentCoinbaseTx\":");
    //      serializeJSON(stream, FBSecondaryHeaders_[i].parentCoinbaseTx);
    //      // "hashBlock":
    //      stream.write(",\"hashBlock\":");
    //      serializeJSON(stream, FBSecondaryHeaders_[i].hashBlock);
    //      // finishing:
    //      stream.write("}");
    //
    //    Copy exactly from doge.cpp but swap DOGESecondaryHeaders_→FBSecondaryHeaders_, etc.

    return true;
  }

} // namespace FB
