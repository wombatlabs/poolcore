#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

namespace {

  // Bitcoin‐style AuxPoW “magic” header (same as DOGE uses):
  static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

  // Compute the minimum Merkle‐path size needed to place all secondaries
  static unsigned merklePathSize(unsigned count) {
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
  }

  // Same “expected index” calculation as DOGE: pseudo-random selection in Merkle tree
  static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1u << h);
  }

} // anonymous namespace

namespace FB {

  //--------------------------------------------------------------------------------
  // Build chain map for merged mining (exact same logic as DOGE, just replace doge→FB)
  //--------------------------------------------------------------------------------
  std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondaries,
                                          uint32_t &nonce,
                                          unsigned &virtualHashesNum)
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
          int       chainId      = (work->Header.nVersion >> 16);
          unsigned  indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);
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

  //--------------------------------------------------------------------------------
  // MergedWork constructor: pack FB (primary) + any secondaries into one AuxPoW blob
  // (copy DOGE’s template but rename to FB)
  //--------------------------------------------------------------------------------
  Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                  StratumSingleWork *primaryWork,
                                  std::vector<StratumSingleWork*> &secondaries,
                                  std::vector<int> &chainMap,
                                  uint32_t auxNonce,
                                  unsigned virtualHashesNum,
                                  const CMiningConfig &miningCfg)
    : StratumMergedWork(stratumWorkId, primaryWork, secondaries, miningCfg)
  {
    // 1. Grab the primary’s header+merkle+ctx (this is a BTCWork since FB’s primary is SHA-256d)
    BTC::Proto::BlockHeader &primaryHeader = static_cast<FBWork*>(primaryWork)->Header;
    auto &primaryMerklePath             = static_cast<FBWork*>(primaryWork)->MerklePath;
    auto &primaryConsensusCtx           = static_cast<FBWork*>(primaryWork)->ConsensusCtx_;

    // 2. Copy those into our FBMergedWork fields (inherited from StratumMergedWork):
    FBHeader_       = primaryHeader;
    FBMerklePath_   = primaryMerklePath;
    FBConsensusCtx_ = primaryConsensusCtx;

    // 3. Prepare space for each secondary’s AuxPoW header data:
    size_t nSec = secondaries.size();
    FBSecondaryHeaders_.resize(nSec);
    FBCoinbaseTransactions_.resize(nSec);
    FBWitnesses_.resize(nSec);

    // 4. Build actual AuxPoW branches and finalize the FB header fields:
    //    (this block is “pseudocode → copy exactly from doge.cpp but with FB:: instead of DOGE::”)
    //
    //    for i in [0..nSec):
    //      FBWork *secWk   = static_cast<FBWork*>(secondaries[i]);
    //      auto    &hdr    = FBSecondaryHeaders_[i];
    //      auto    &coin   = FBCoinbaseTransactions_[i];
    //      auto    &wit    = FBWitnesses_[i];
    //
    //      hdr = secWk->Header;                     // copy child’s header
    //      coin = secWk->LegacyCoinbaseTx;          // copy child’s legacy coinbase
    //      wit  = secWk->WitnessCoinbaseTx;         // copy child’s witness coinbase (if segwit)
    //
    //      // Toggle AuxPoW bit on child header:
    //      hdr.nVersion |= Proto::AuxPoWBlockHeader::VERSION_AUXPOW;
    //
    //      // Build Merkle‐root: iterate upward using merkleBranch from secWk and place it at index = chainMap[i]
    //      // Fill chainMerkleBranch, chainIndex, parentCoinbaseTx, hashBlock, etc.
    //
    //      // Finally, push pchMergedMiningHeader and reversed SHA256d merkle root into primary coinbase script.
    //      //
    //    endfor
    //
    // 5. After populating all AuxPoW headers & branches, recompute the primaryHeader’s merkle root,
    //    attach pchMergedMiningHeader, etc. exactly how doge.cpp does it. 
    //
    //    (No changes here except using FB types instead of DOGE.)

    // … (Insert exact doge.cpp logic here, replacing DOGE:: → FB:: and btc:: → btc:: as needed) …
  }

  //--------------------------------------------------------------------------------
  // prepareForSubmit: verify primary (FB) and each AuxPoW child, then serialize into
  // the “submit” message to send to GBT “submitblock” RPC.
  //--------------------------------------------------------------------------------
  bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                             const CStratumMessage &msg)
  {
    // 1. Let BTC’s prepareForSubmitImpl do the primary (FB’s header) serialization:
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

    // 2. Then for each secondary (child AuxPoW), embed them into the AuxPoW fields we built:
    if (!okPrimary) return false;

    // 3. Finally, attach our AuxPoW fields into the “submit” JSON → copy doge.cpp exactly
    //    (write out parentBlock, merkleBranch, index, chainMerkleBranch, chainIndex, etc.)

    return true;  // or false if something went wrong
  }

} // namespace FB

namespace BTC {

  // Tell the compiler “here’s how to serialize an FB::AuxPoWBlockHeader.”
  template<>
  struct Io<FB::AuxPoWBlockHeader> {
    // Serialize writes out:
    //   1) The pure Bitcoin header bytes (nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce).
    //   2) If VERSION_AUXPOW is set, the full AuxPoW payload: parentCoinbaseTx, hashBlock, merkleBranch, index, chainMerkleBranch, chainIndex, parentBlock.
    static inline void serialize(xmstream &dst, const FB::AuxPoWBlockHeader &data) {
      // 1) Serialize the 80‐byte “pure” Bitcoin header first
      //    (we cast away FB extras because AuxPoWBlockHeader inherits from BTC::Proto::BlockHeader).
      BTC::serialize(dst, *(BTC::Proto::BlockHeader*)&data);

      // 2) If the AuxPoW bit is in nVersion, serialize the extra AuxPoW fields:
      if (data.nVersion & FB::AuxPoWBlockHeader::VERSION_AUXPOW) {
        // 2.a) Parent‐chain coinbase transaction
        BTC::serialize(dst, data.parentCoinbaseTx);

        // 2.b) Parent header’s hash, merkle branch, and index
        BTC::serialize(dst, data.hashBlock);
        BTC::serialize(dst, data.merkleBranch);
        BTC::serialize(dst, data.index);

        // 2.c) If FB itself were merged under something else, serialize those chain‐merkle fields
        BTC::serialize(dst, data.chainMerkleBranch);
        BTC::serialize(dst, data.chainIndex);

        // 2.d) Finally, serialize the full parent header so the pool can re‐check its PoW
        BTC::serialize(dst, data.parentBlock);
      }
    }

    // We do not actually need to unserialize FB’s full AuxPoW header in PoolCore.
    // But we still provide a stub so the symbol exists. In most mining‐only code,
    // “unserialize” is never called. If you do need it, you can fill in the inverse logic.
    static inline void unserialize(xmstream &src, FB::AuxPoWBlockHeader &data) {
      // (Stubbed out—PoolCore never calls this for mining flow.)
      // If you do wind up needing it, you’d read the pure header first, then all AuxPoW fields.
    }
  };

} // namespace BTC
