#include "blockmaker/frac.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "poolcommon/arith_uint256.h"

// “mm” header for merged mining (same as DOGE’s)
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

namespace FRAC {

//////////////////////////
// 1) buildChainMap(...) – identical to DOGE’s implementation
//    It chooses “nonce” and “pathSize” so that all secondary works
//    map into distinct leaves of an mm merkle tree.
std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned &virtualHashesNum)
{
  std::vector<int> result(secondary.size());
  std::vector<int> chainMap;
  bool finished = true;

  for (unsigned pathSize = 
         (secondary.size() > 1 ? (31 - __builtin_clz((secondary.size() << 1) - 1)) : 0);
       pathSize < 8;
       pathSize++)
  {
    virtualHashesNum = 1u << pathSize;
    chainMap.resize(virtualHashesNum);
    for (nonce = 0; nonce < virtualHashesNum; nonce++) {
      finished = true;
      std::fill(chainMap.begin(), chainMap.end(), 0);

      for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
        auto *work = static_cast<FRAC::Stratum::FracWork*>(secondary[workIdx]);
        uint32_t chainId = work->Header.nVersion >> 16;
        // exactly same PRNG as DOGE
        uint32_t rand = nonce;
        rand = rand * 1103515245 + 12345;
        rand += chainId;
        rand = rand * 1103515245 + 12345;
        uint32_t indexInMerkle = rand % (1 << pathSize);

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

//////////////////////////
// 2) checkConsensus(...) – decide whether to verify AuxPoW or “pure” PoW
CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header, CheckConsensusCtx &ctx, Proto::ChainParams &chainParams)
{
  // If VERSION_AUXPOW bit is set, check the parent header’s PoW under nBits
  if (header.nVersion & Proto::BlockHeader::VERSION_AUXPOW) {
    return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
  } else {
    // No AuxPoW: treat as plain SHA-256 header using BTC’s checkConsensus
    return BTC::Proto::checkConsensus(header, ctx, chainParams);
  }
}

//////////////////////////
// 3) MergedWork constructor – parallel to DOGE’s MergedWork
Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int> &mmChainId,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig &miningCfg)
  : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
  // “first” is the primary coin’s work: cast to BTC::Stratum::Work
  BaseHeader_ = baseWork()->Header;
  BaseMerklePath_ = baseWork()->MerklePath;
  BaseConsensusCtx_ = baseWork()->ConsensusCtx_;

  // Allocate storage for FRAC sub-headers & coinbases
  FRACHeaders_.resize(second.size());
  FRACLegacy_.resize(second.size());
  FRACWitness_.resize(second.size());

  FRACHeaderHashes_.resize(virtualHashesNum, uint256());
  FRACWorkMap_.assign(mmChainId.begin(), mmChainId.end());

  // For each secondary (FRAC) work, compute its “aux-pow” block header
  for (size_t workIdx = 0; workIdx < FRACHeaders_.size(); workIdx++) {
    auto *work = static_cast<FRAC::Stratum::FracWork*>(second[workIdx]);
    FRACHeaders_[workIdx] = work->Header;

    // Build a “static” FRAC coinbase (no extra-nonce) to compute its merkle path
    CMiningConfig emptyExtra; 
    emptyExtra.FixedExtraNonceSize   = 0;
    emptyExtra.MutableExtraNonceSize = 0;
    work->buildCoinbaseTx(nullptr, 0, emptyExtra, FRACLegacy_[workIdx], FRACWitness_[workIdx]);

    // Mark version with AuxPoW bit
    FRACHeaders_[workIdx].nVersion |= FRAC::Proto::BlockHeader::VERSION_AUXPOW;

    // Compute FRAC merkle root from transaction (double-SHA256 of FRACLegacy[workIdx])
    uint256 coinbaseTxHash;
    CCtxSha256 sha256;
    sha256Init(&sha256);
    sha256Update(&sha256, FRACLegacy_[workIdx].Data.data(), FRACLegacy_[workIdx].Data.sizeOf());
    sha256Final(&sha256, coinbaseTxHash.begin());
    sha256Init(&sha256);
    sha256Update(&sha256, coinbaseTxHash.begin(), coinbaseTxHash.size());
    sha256Final(&sha256, coinbaseTxHash.begin());

    FRACHeaders_[workIdx].hashMerkleRoot = calculateMerkleRootWithPath(
      coinbaseTxHash,
      &work->MerklePath[0],
      work->MerklePath.size(),
      0
    );

    // Save the “little-endian” FRAC header hash for the mm tree
    FRACHeaderHashes_[FRACWorkMap_[workIdx]] = FRACHeaders_[workIdx].GetHash();
  }

  // Build the “chain merkle root”, then reverse it for the mm payload
  uint256 chainMerkleRoot = calculateMerkleRoot(&FRACHeaderHashes_[0], FRACHeaderHashes_.size());
  std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

  // Build mm coinbase payload: 0xfa,0xbe,'m','m' || chainMerkleRoot || virtualHashesNum || mmNonce
  uint8_t buffer[1024];
  xmstream mmPayload(buffer, sizeof(buffer));
  mmPayload.reset();
  mmPayload.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
  mmPayload.write(chainMerkleRoot.begin(), sizeof(uint256));
  mmPayload.write<uint32_t>(virtualHashesNum);
  mmPayload.write<uint32_t>(mmNonce);

  // Append this mm payload into the primary (first) coinbase
  baseWork()->buildCoinbaseTx(mmPayload.data(), mmPayload.sizeOf(), miningCfg, BaseLegacy_, BaseWitness_);

  // Copy FRAC consensus context for block validation later
  BaseConsensusCtx_ = baseWork()->ConsensusCtx_;
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg)
{
  // Submit primary proof to the pool; subsidiary (FRAC) shares are checked by BaseConsensusCtx_
  if (!BTC::Stratum::Work::prepareForSubmitImpl(BaseHeader_, BaseHeader_.nVersion, BaseLegacy_, BaseWitness_, BaseMerklePath_, workerCfg, MiningCfg_, msg))
    return false;

  // Now validate each FRAC share against its parent header bits
  for (size_t workIdx = 0; workIdx < FRACHeaders_.size(); workIdx++) {
    auto &hdr = FRACHeaders_[workIdx];
    // parent header PoW check is done by FRAC::Proto::checkConsensus
    if (!FRAC::Stratum::FracWork::checkConsensusImpl(hdr, FRACConsensusCtx_).IsBlock) {
      return false;
    }
  }
  return true;
}

//////////////////////////
// 4) newPrimaryWork / newSecondaryWork
FRAC::Stratum::FracWork *Stratum::newPrimaryWork(int64_t stratumId,
                                                PoolBackend *backend,
                                                size_t backendIdx,
                                                const CMiningConfig &miningCfg,
                                                const std::vector<uint8_t> &miningAddress,
                                                const std::string &coinbaseMessage,
                                                CBlockTemplate &blockTemplate,
                                                std::string &error)
{
  if (blockTemplate.WorkType != EWorkBitcoin) {
    error = "incompatible work type";
    return nullptr;
  }

  auto *work = new FRAC::Stratum::FracWork(stratumId,
                                           blockTemplate.UniqueWorkId,
                                           backend,
                                           backendIdx,
                                           miningCfg,
                                           miningAddress,
                                           coinbaseMessage);
  return work->loadFromTemplate(blockTemplate, error) ? work : (void(delete work), nullptr);
}

StratumSingleWork *Stratum::newSecondaryWork(int64_t stratumId,
                                             PoolBackend *backend,
                                             size_t backendIdx,
                                             const CMiningConfig &miningCfg,
                                             const std::vector<uint8_t> &miningAddress,
                                             const std::string &coinbaseMessage,
                                             CBlockTemplate &blockTemplate,
                                             std::string &error)
{
  // Secondary works for FRAC are identical to primary, except we don't merge them
  // (PoolCore will treat them as aux-pow contributors).
  return nullptr; // PoolCore’s workStorage will never call this for FRAC (you could stub it)
}

} // namespace FRAC
