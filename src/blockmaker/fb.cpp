#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

// same magic as DOGE/Litecoin merged-mining header
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };


// Build chain map for FB merged mining (simplified for single secondary)
static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned &virtualHashesNum)
{
  std::vector<int> result;
  result.resize(secondary.size());
  
  // For FB, we use a simple approach since typically there's only one secondary chain
  // Calculate minimum tree size to accommodate all secondaries
  unsigned minTreeSize = 1;
  while (minTreeSize < secondary.size()) {
    minTreeSize <<= 1;
  }
  
  virtualHashesNum = minTreeSize;
  nonce = 0; // Start with nonce 0
  
  // Simple mapping: each secondary gets an index in order
  for (size_t i = 0; i < secondary.size(); i++) {
    result[i] = static_cast<int>(i);
  }
  
  return result;
}

namespace FB {

void FB::Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
  if (workIdx == 0 && btcWork()) {
    // Primary (BTC) produces a raw block via submitblock
    btcWork()->buildBlock(workIdx, blockHexData);
  } else if (workIdx > 0 && fbWork(workIdx - 1)) {
    // Secondary (FB) builds AuxPoW block like DOGE does for secondary chains
    // The pool framework should handle submitauxblock based on CanBeSecondaryCoin flag
    fbWork(workIdx - 1)->buildBlockImpl(FBHeader_[workIdx - 1], FBWitness_[workIdx - 1], blockHexData);
  }
}

FB::Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                    StratumSingleWork *first,
                                    std::vector<StratumSingleWork*> &second,
                                    std::vector<int> &mmChainId,
                                    uint32_t mmNonce,
                                    unsigned virtualHashesNum,
                                    const CMiningConfig &miningCfg)
  : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
  // === Primary (BTC) context copied, no heavy objects copied ===
  BTCHeader_       = btcWork()->Header;
  BTCMerklePath_   = btcWork()->MerklePath;
  BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

  // === Secondaries (FB) ===
  FBHeader_.resize(second.size());
  FBLegacy_.resize(second.size());
  FBWitness_.resize(second.size());

  FBHeaderHashes_.resize(virtualHashesNum, uint256());
  FBWorkMap_.assign(mmChainId.begin(), mmChainId.end());

  for (size_t workIdx = 0; workIdx < FBHeader_.size(); workIdx++) {
    FB::Stratum::FBWork *work = fbWork(workIdx);
    FB::Proto::BlockHeader &header = FBHeader_[workIdx];
    BTC::CoinbaseTx &legacy = FBLegacy_[workIdx];
    BTC::CoinbaseTx &witness = FBWitness_[workIdx];

    // Copy only POD fields from template header (avoid copying CoinbaseTx/xmstream members)
    header.nVersion       = work->Header.nVersion;
    header.hashPrevBlock  = work->Header.hashPrevBlock;
    header.hashMerkleRoot = work->Header.hashMerkleRoot;
    header.nTime          = work->Header.nTime;
    header.nBits          = work->Header.nBits;
    header.nNonce         = work->Header.nNonce;

    // --- Build a static FB coinbase (no extranonce) like DOGE does ---
    CMiningConfig emptyExtraNonceConfig;
    emptyExtraNonceConfig.FixedExtraNonceSize   = 0;
    emptyExtraNonceConfig.MutableExtraNonceSize = 0;
    work->buildCoinbaseTx(nullptr, 0, emptyExtraNonceConfig, legacy, witness);

    // --- Compute FB merkle root from that static coinbase and FB merkle path ---
    header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW; // AuxPoW bit
    {
      // double-SHA256(coinbase) -> coinbaseTxHash
      uint256 coinbaseTxHash;
      CCtxSha256 sha256;
      sha256Init(&sha256);
      sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
      sha256Final(&sha256, coinbaseTxHash.begin());
      sha256Init(&sha256);
      sha256Update(&sha256, coinbaseTxHash.begin(), coinbaseTxHash.size());
      sha256Final(&sha256, coinbaseTxHash.begin());

      // FB work already exposes MerklePath like DOGE work
      header.hashMerkleRoot = calculateMerkleRootWithPath(
          coinbaseTxHash, &work->MerklePath[0], work->MerklePath.size(), 0);
    }

    // Save FB header hash in the virtual chain slot
    FBHeaderHashes_[FBWorkMap_[workIdx]] = header.GetHash();
  }

  // --- Build the "chain merkle root" over all FB header hashes (reverse to LE bytes) ---
  uint256 chainMerkleRoot = calculateMerkleRoot(&FBHeaderHashes_[0], FBHeaderHashes_.size());
  std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

  // --- Prepare BTC coinbase with merged-mining commitment, exactly like LTC side for DOGE ---
  uint8_t buffer[1024];
  xmstream coinbaseMsg(buffer, sizeof(buffer));
  coinbaseMsg.reset();
  coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader)); // 0xfa 0xbe 'm' 'm'
  coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));             // chain merkle root (reversed)
  coinbaseMsg.write<uint32_t>(virtualHashesNum);                           // tree size
  coinbaseMsg.write<uint32_t>(mmNonce);                                    // fixed part of nonce

  // This splices the commitment into the BTC coinbase and builds legacy+witness templates
  btcWork()->buildCoinbaseTx(coinbaseMsg.data(), coinbaseMsg.sizeOf(), miningCfg, BTCLegacy_, BTCWitness_);

  FBConsensusCtx_ = fbWork(0)->ConsensusCtx_;
}


std::string FB::Stratum::MergedWork::blockHash(size_t workIdx)
{
  if (workIdx == 0 && btcWork())
    return BTCHeader_.GetHash().GetHex();
  else if (fbWork(workIdx - 1))
    return FBHeader_[workIdx - 1].GetHash().GetHex();
  return std::string();
}

bool FB::Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                               const CStratumMessage &msg)
{
  // Fill primary BTC header from the miner's share fields  
  if (!BTC::Stratum::Work::prepareForSubmitImpl(
          BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCWitness_, BTCMerklePath_,
          workerCfg, MiningCfg_, msg))
    return false;

  // Build AuxPoW metadata for each FB secondary
  for (size_t i = 0; i < FBHeader_.size(); ++i) {
    FB::Proto::BlockHeader &hdr = FBHeader_[i];
    
    // Deserialize parent BTC coinbase transaction (critical for AuxPoW)
    BTCWitness_.Data.seekSet(0);
    BTC::unserialize(BTCWitness_.Data, hdr.ParentBlockCoinbaseTx);

    hdr.HashBlock.SetNull();
    hdr.Index = 0;

    // Parent (BTC) tx merkle branch path -> coinbase
    hdr.MerkleBranch.resize(BTCMerklePath_.size());
    for (size_t j = 0; j < BTCMerklePath_.size(); ++j)
      hdr.MerkleBranch[j] = BTCMerklePath_[j];

    // Chain (virtual) merkle branch for the FB header among secondaries
    std::vector<uint256> path;
    buildMerklePath(FBHeaderHashes_, FBWorkMap_[i], path);
    hdr.ChainMerkleBranch.resize(path.size());
    for (size_t j = 0; j < path.size(); ++j)
      hdr.ChainMerkleBranch[j] = path[j];

    hdr.ChainIndex = FBWorkMap_[i];
    hdr.ParentBlock = BTCHeader_;
  }

  return true;
}

CCheckStatus FB::Stratum::MergedWork::checkConsensus(size_t workIdx)
{
  if (workIdx == 0 && btcWork()) {
    // Primary BTC work consensus check
    return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, BTCConsensusCtx_);
  } else if (workIdx > 0 && workIdx - 1 < FBHeader_.size()) {
    // For FB secondary in merged mining, return default success status
    // The actual validation happens in the FB node via submitauxblock
    return CCheckStatus();
  }
  return CCheckStatus();
}

// Required pure-virtuals from StratumWork
void FB::Stratum::MergedWork::mutate()
{
  // Update timestamp like DOGE does
  BTCHeader_.nTime = static_cast<uint32_t>(time(nullptr));
  // Build notify message with updated header
  BTC::Stratum::Work::buildNotifyMessageImpl(this, BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCMerklePath_, MiningCfg_, true, NotifyMessage_);
}

void FB::Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork)
{
  // Build stratum notify message for merged mining work
  BTC::Stratum::Work::buildNotifyMessageImpl(this, BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCMerklePath_, MiningCfg_, resetPreviousWork, NotifyMessage_);
}

// Secondary work creation: FB needs the aux hash from createauxblock.
// We piggy-back on the generic WorkTy loader then patch in the AuxPoW bit and aux hash.
FB::Stratum::FBWork *FB::Stratum::newSecondaryWork(int64_t stratumId,
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

  std::unique_ptr<FBWork> work(new FBWork(stratumId,
                                          blockTemplate.UniqueWorkId,
                                          backend,
                                          backendIdx,
                                          miningCfg,
                                          miningAddress,
                                          coinbaseMessage));

  if (!work->loadFromTemplate(blockTemplate, error))
    return nullptr;

  // Mark AuxPoW (version bit); the aux hash will be committed from createauxblock in MergedWork ctor
  work->Header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
  return work.release();
}

// Glue everything into a StratumMergedWork
StratumMergedWork *FB::Stratum::newMergedWork(int64_t stratumId,
                                          StratumSingleWork *first,
                                          std::vector<StratumSingleWork*> &second,
                                          const CMiningConfig &miningCfg,
                                          std::string &error)
{
  uint32_t mmNonce = 0;
  unsigned virtualHashesNum = 0;
  std::vector<int> chainMap = buildChainMap(second, mmNonce, virtualHashesNum);
  if (chainMap.empty()) {
    error = "cannot build chain map for merged mining";
    return nullptr;
  }
  return new FB::Stratum::MergedWork(stratumId, first, second, chainMap, mmNonce, virtualHashesNum, miningCfg);
}

} // namespace FB

// JSON helpers — optional, just mirrors DOGE for consistency
namespace BTC {
void Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &h)
{
  BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&h);
  if (h.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
    BTC::serialize(dst, h.ParentBlockCoinbaseTx);
    BTC::serialize(dst, h.HashBlock);
    BTC::serialize(dst, h.MerkleBranch);
    BTC::serialize(dst, h.Index);
    BTC::serialize(dst, h.ChainMerkleBranch);
    BTC::serialize(dst, h.ChainIndex);
    BTC::serialize(dst, h.ParentBlock);
  }
}
void Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &h)
{
  BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&h);
  if (h.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
    BTC::unserialize(src, h.ParentBlockCoinbaseTx);
    BTC::unserialize(src, h.HashBlock);
    BTC::unserialize(src, h.MerkleBranch);
    BTC::unserialize(src, h.Index);
    BTC::unserialize(src, h.ChainMerkleBranch);
    BTC::unserialize(src, h.ChainIndex);
    BTC::unserialize(src, h.ParentBlock);
  }
}
}

void serializeJsonInside(xmstream &s, const FB::Proto::BlockHeader &h)
{
  serializeJson(s, "version", h.nVersion); s.write(',');
  serializeJson(s, "hashPrevBlock", h.hashPrevBlock); s.write(',');
  serializeJson(s, "hashMerkleRoot", h.hashMerkleRoot); s.write(',');
  serializeJson(s, "time", h.nTime); s.write(',');
  serializeJson(s, "bits", h.nBits); s.write(',');
  serializeJson(s, "nonce", h.nNonce); s.write(',');
  serializeJson(s, "hashBlock", h.HashBlock); s.write(',');
  serializeJson(s, "merkleBranch", h.MerkleBranch); s.write(',');
  serializeJson(s, "index", h.Index); s.write(',');
  serializeJson(s, "chainMerkleBranch", h.ChainMerkleBranch); s.write(',');
  serializeJson(s, "chainIndex", h.ChainIndex); s.write(',');
}
