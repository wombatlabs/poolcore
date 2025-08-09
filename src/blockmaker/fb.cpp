#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

// same magic as DOGE/Litecoin merged-mining header
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

static unsigned merklePathSize(unsigned count)
{
  return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

// Reuse the same “virtual tree” mapping pattern as DOGE
static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned &virtualHashesNum)
{
  std::vector<int> result;
  std::vector<int> chainMap;
  result.resize(secondary.size());
  bool finished = true;
  for (unsigned h = 0; ; h++) {
    unsigned treeSize = (1U << h);
    if (treeSize >= secondary.size()) {
      virtualHashesNum = treeSize;
      chainMap.resize(virtualHashesNum, -1);
      for (size_t i = 0; i < secondary.size(); i++) {
        uint32_t expectedIndex = (nonce + i) % virtualHashesNum;
        chainMap[expectedIndex] = static_cast<int>(i);
      }
      for (size_t i = 0; i < chainMap.size(); i++) {
        if (chainMap[i] < 0)
          finished = false;
        else
          result[chainMap[i]] = static_cast<int>(i);
      }
    }
    if (finished)
      break;
  }
  return finished ? result : std::vector<int>();
}

namespace FB {

Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
  // Only the primary (BTC) produces a raw block here; FB is submitted via submitauxblock.
  if (workIdx == 0 && btcWork()) {
    btcWork()->buildBlock(workIdx, blockHexData);
  }
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
    header.nVersion |= 0x100; // AuxPoW bit (same convention as Namecoin/DOGE)
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


std::string Stratum::MergedWork::blockHash(size_t workIdx)
{
  if (workIdx == 0 && btcWork())
    return BTCHeader_.GetHash().GetHex();
  else if (fbWork(workIdx - 1))
    return FBHeader_[workIdx - 1].GetHash().GetHex();
  return std::string();
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg)
{
  // Fill primary BTC header from the miner’s share fields
  if (!BTC::Stratum::Work::prepareForSubmitImpl(BTCHeader_, /*asicBoostData*/0, BTCLegacy_, BTCWitness_, BTCMerklePath_, workerCfg, MiningCfg_, msg))
    return false;

  // Build AuxPoW metadata (except coinbase) for each FB secondary
  for (size_t i = 0; i < FBHeader_.size(); i++) {
    FB::Proto::BlockHeader &h = FBHeader_[i];
    h.HashBlock.SetNull();
    h.Index = 0;
    h.MerkleBranch.assign(BTCMerklePath_.begin(), BTCMerklePath_.end());
    std::vector<uint256> path;
    buildMerklePath(FBHeaderHashes_, FBWorkMap_[i], path);
    h.ChainMerkleBranch.assign(path.begin(), path.end());
    h.ChainIndex = FBWorkMap_[i];
    h.ParentBlock = BTCHeader_;
  }
  return true;
}

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx)
{
  if (workIdx == 0 && btcWork())
    return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, BTCConsensusCtx_);
  else if (fbWork(workIdx - 1))
    return FB::Stratum::FBWork::checkConsensusImpl(FBHeader_[workIdx - 1], FBConsensusCtx_);
  return CCheckStatus();
}

// Required pure-virtuals from StratumWork
void Stratum::MergedWork::mutate()
{
  // Delegate mutation (extranonce/version rolling) to primary BTC work
  if (btcWork()) btcWork()->mutate();
}

void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork)
{
  // For now just delegate primary notify; we’ll extend to include FB fields later
  if (btcWork()) btcWork()->buildNotifyMessage(resetPreviousWork);
}

// Secondary work creation: FB needs the aux hash from createauxblock.
// We piggy-back on the generic WorkTy loader then patch in the AuxPoW bit and aux hash.
FB::Stratum::FBWork *Stratum::newSecondaryWork(int64_t stratumId,
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
  work->Header.nVersion |= 0x100;
  return work.release();
}

// Glue everything into a StratumMergedWork
StratumMergedWork *Stratum::newMergedWork(int64_t stratumId,
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
  return new Stratum::MergedWork(stratumId, first, second, chainMap, mmNonce, virtualHashesNum, miningCfg);
}

} // namespace FB

// JSON helpers — optional, just mirrors DOGE for consistency
namespace BTC {
void Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &h)
{
  BTC::serialize(dst, h.nVersion);
  BTC::serialize(dst, h.hashPrevBlock);
  BTC::serialize(dst, h.hashMerkleRoot);
  BTC::serialize(dst, h.nTime);
  BTC::serialize(dst, h.nBits);
  BTC::serialize(dst, h.nNonce);
  BTC::serialize(dst, h.HashBlock);
  BTC::serialize(dst, h.MerkleBranch);
  BTC::serialize(dst, h.Index);
  BTC::serialize(dst, h.ChainMerkleBranch);
  BTC::serialize(dst, h.ChainIndex);
  BTC::serialize(dst, h.ParentBlock);
}
void Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &h)
{
  BTC::unserialize(src, h.nVersion);
  BTC::unserialize(src, h.hashPrevBlock);
  BTC::unserialize(src, h.hashMerkleRoot);
  BTC::unserialize(src, h.nTime);
  BTC::unserialize(src, h.nBits);
  BTC::unserialize(src, h.nNonce);
  BTC::unserialize(src, h.HashBlock);
  BTC::unserialize(src, h.MerkleBranch);
  BTC::unserialize(src, h.Index);
  BTC::unserialize(src, h.ChainMerkleBranch);
  BTC::unserialize(src, h.ChainIndex);
  BTC::unserialize(src, h.ParentBlock);
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
