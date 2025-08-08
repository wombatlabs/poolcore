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

Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int> &mmChainId,
                                uint32_t mmNonce,
                                unsigned int virtualHashesNum,
                                const CMiningConfig &miningCfg)
  : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
  // Primary (BTC)
  BTCHeader_ = btcWork()->Header;
  BTCLegacy_ = BTC::CoinbaseTx();
  BTCWitness_ = BTC::CoinbaseTx();

  // Secondaries
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

    header = work->Header;

    // Prepare merged-mining commitment for BTC coinbase
    CMiningConfig emptyExtraNonceConfig;
    emptyExtraNonceConfig.FixedExtraNonceSize = 0;
    emptyExtraNonceConfig.MutableExtraNonceSize = 0;
    btcWork()->buildCoinbaseTx(nullptr, 0, emptyExtraNonceConfig, BTCLegacy_, BTCWitness_);

    // Set AuxPoW bit and compute the FB header merkle root from a static FB coinbase (no extranonce) + path
    header.nVersion |= 0x100; // AuxPoW bit
    {
      xmstream nonMutable;
      BTC::Io<decltype(legacy)>::serialize(nonMutable, legacy);
      uint256 coinbaseHash = BTC::SerializeHash(nonMutable);
      std::vector<uint256> &path = BTCMerklePath_;
      if (path.empty()) {
        // compute BTC merkle path from BTCLegacy_ + BTC txs (the primary work already exposes it for notify)
        // We re-use BTCWork's path builder — already baked into WorkTy
        btcWork()->buildMerklePath(BTCHeader_, BTCLegacy_, path);
      }
      header.hashMerkleRoot = calculateMerkleRoot(coinbaseHash, path);
      header.HashBlock = header.GetHash();
      FBHeaderHashes_[workIdx] = header.HashBlock;
    }

    // Assemble BTC coinbase commitment: 0xfabemm | fb_hash | tree_size | 0x00000000
    xmstream mmCommit;
    mmCommit.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    mmCommit.write(FBHeaderHashes_[workIdx].begin(), 32);
    uint32_t treeSize = 1U << merklePathSize(virtualHashesNum);
    mmCommit.writebe(treeSize);
    mmCommit.writebe(0U); // fixed nonce part

    // Splice commitment into BTC coinbase
    btcWork()->appendMergedMiningCommitment(mmCommit);

    // Keep per-secondary copies of coinbase templates (not extranonce-mutated) for AuxPoW assembly on submit
    legacy = BTCLegacy_;
    witness = BTCWitness_;
  }
}

std::string Stratum::MergedWork::blockHash(size_t workIdx)
{
  if (workIdx == 0 && btcWork())
    return BTC::Io<BTC::Proto::BlockHashTy>::toString(BTCHeader_.GetHash());
  else if (fbWork(workIdx - 1))
    return BTC::Io<FB::Proto::BlockHashTy>::toString(FBHeader_[workIdx - 1].GetHash());
  return std::string();
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg)
{
  // Fill primary BTC header from the miner’s share fields
  if (!BTC::Stratum::Work::prepareForSubmitImpl(BTCHeader_, BTCLegacy_, BTCWitness_, BTCMerklePath_, workerCfg, MiningCfg_, msg))
    return false;

  // Build AuxPoW for each FB secondary
  for (size_t i = 0; i < FBHeader_.size(); i++) {
    FB::Proto::BlockHeader &h = FBHeader_[i];

    BTCWitness_.Data.seekSet(0);
    BTC::unserialize(BTCWitness_.Data, h.ParentBlockCoinbaseTx);

    h.HashBlock.SetNull();
    h.Index = 0;

    h.MerkleBranch.resize(BTCMerklePath_.size());
    for (size_t j = 0; j < BTCMerklePath_.size(); j++)
      h.MerkleBranch[j] = BTCMerklePath_[j];

    std::vector<uint256> path;
    buildMerklePath(FBHeaderHashes_, FBWorkMap_[i], path);
    h.ChainMerkleBranch.resize(path.size());
    for (size_t j = 0; j < path.size(); j++)
      h.ChainMerkleBranch[j] = path[j];
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
  BTC::serialize(dst, h.ParentBlockCoinbaseTx);
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
  BTC::unserialize(src, h.ParentBlockCoinbaseTx);
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
  serializeJson(s, "parentBlockCoinbaseTx", h.ParentBlockCoinbaseTx); s.write(',');
  serializeJson(s, "hashBlock", h.HashBlock); s.write(',');
  serializeJson(s, "merkleBranch", h.MerkleBranch); s.write(',');
  serializeJson(s, "index", h.Index); s.write(',');
  serializeJson(s, "chainMerkleBranch", h.ChainMerkleBranch); s.write(',');
  serializeJson(s, "chainIndex", h.ChainIndex); s.write(',');
  serializeJson(s, "parentBlock", h.ParentBlock);
}
