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
  std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                           uint32_t &nonce,
                                           unsigned &virtualHashesNum) {
    std::vector<int> result;
    std::vector<int> chainMap;
    result.resize(secondary.size());
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
      virtualHashesNum = 1u << pathSize;
      chainMap.resize(virtualHashesNum);
      for (nonce = 0; nonce < virtualHashesNum; nonce++) {
        finished = true;
        std::fill(chainMap.begin(), chainMap.end(), 0);
        for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
          FB::Stratum::FbWork *work = (FB::Stratum::FbWork*)secondary[workIdx];
          uint32_t chainId        = work->Header.nVersion >> 16;
          uint32_t indexInMerkle  = getExpectedIndex(nonce, chainId, pathSize);
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

  Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                  StratumSingleWork *first,
                                  std::vector<StratumSingleWork*> &second,
                                  std::vector<int> &mmChainId,
                                  uint32_t mmNonce,
                                  unsigned virtualHashesNum,
                                  const CMiningConfig &miningCfg)
    : StratumMergedWork(stratumWorkId, first, second, miningCfg)
  {
    // (1) Copy BTC header + context
    BTCHeader_      = btcWork()->Header;
    BTCMerklePath_  = btcWork()->MerklePath;
    BTCConsensusCtx_= btcWork()->ConsensusCtx_;

    // (2) Resize FB data structures
    FBHeader_.resize(second.size());
    FBLegacy_.resize(second.size());
    FBWitness_.resize(second.size());
    FBHeaderHashes_.resize(virtualHashesNum, uint256());
    FBWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // (3) For each FB work, mark AuxPoW bit, build “static” FB coinbase, compute Merkle root
    for (size_t workIdx = 0; workIdx < FBHeader_.size(); workIdx++) {
      FB::Stratum::FbWork *work = fbWork(workIdx);
      FB::Proto::BlockHeader &header = FBHeader_[workIdx];
      BTC::CoinbaseTx &legacy = FBLegacy_[workIdx];
      BTC::CoinbaseTx &witness= FBWitness_[workIdx];

      header = work->Header;
      header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;

      // Build coinbase WITHOUT extra-nonce
      CMiningConfig emptyExtraNonceConfig;
      emptyExtraNonceConfig.FixedExtraNonceSize   = 0;
      emptyExtraNonceConfig.MutableExtraNonceSize = 0;
      work->buildCoinbaseTx(nullptr, 0, emptyExtraNonceConfig, legacy, witness);

      // Double-SHA256 of legacy data
      uint256 coinbaseTxHash;
      CCtxSha256 sha256;
      sha256Init(&sha256);
      sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
      sha256Final(&sha256, coinbaseTxHash.begin());
      sha256Init(&sha256);
      sha256Update(&sha256, coinbaseTxHash.begin(), coinbaseTxHash.size());
      sha256Final(&sha256, coinbaseTxHash.begin());

      // FB Merkle root (coinbase + MerklePath)
      header.hashMerkleRoot = calculateMerkleRootWithPath(coinbaseTxHash,
                                                         &work->MerklePath[0],
                                                         work->MerklePath.size(),
                                                         0);
      FBHeaderHashes_[FBWorkMap_[workIdx]] = header.GetHash();
    }

    // (4) Build reversed Merkle root from all FB header hashes
    uint256 chainMerkleRoot = calculateMerkleRoot(&FBHeaderHashes_[0], FBHeaderHashes_.size());
    std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

    // (5) Prepend “mm” header to BTC coinbase
    uint8_t buffer[1024];
    xmstream coinbaseMsg(buffer, sizeof(buffer));
    coinbaseMsg.reset();
    coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
    coinbaseMsg.write<uint32_t>(virtualHashesNum);
    coinbaseMsg.write<uint32_t>(mmNonce);
    btcWork()->buildCoinbaseTx(coinbaseMsg.data(),
                               coinbaseMsg.sizeOf(),
                               miningCfg,
                               BTCLegacy_,
                               BTCWitness_);

    FBConsensusCtx_ = fbWork(0)->ConsensusCtx_;
  }

  bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                             const CStratumMessage &msg)
  {
    // Mirror DOGE’s logic: if primary (workIdx 0) → call BTC; else → call FB
    // (Implementation details omitted for brevity; copy DOGE’s pattern verbatim)
  }

  // … buildBlock(...) and checkConsensus(...) copied from DOGE, substituting FB vs. DOGE …
}
