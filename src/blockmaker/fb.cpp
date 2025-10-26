#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

// Same magic as DOGE/Litecoin merged-mining header
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

// ---- helpers (mirrored from DOGE) -------------------------------------------------

static unsigned merklePathSize(unsigned count)
{
  return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h)
{
  uint32_t rand = nNonce;
  rand = rand * 1103515245 + 12345;
  rand += nChainId;
  rand = rand * 1103515245 + 12345;

  return rand % (1u << h);
}

namespace FB {

// Build a collision-free randomized chain map like DOGE
std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                        uint32_t &nonce,
                                        unsigned &virtualHashesNum)
{
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
        FB::Stratum::FBWork *work = (FB::Stratum::FBWork*) secondary[workIdx];
        uint32_t chainId = work->Header.nVersion >> 16; // same scheme as DOGE
        uint32_t indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);

        if (chainMap[indexInMerkle] == 0) {
          chainMap[indexInMerkle] = 1;
          result[workIdx] = (int) indexInMerkle;
        } else {
          finished = false;
          break;
        }
      }

      if (finished)
        break;
    }

    if (finished)
      break;
  }

  return finished ? result : std::vector<int>();
}

// -----------------------------------------------------------------------------------
// MergedWork
// -----------------------------------------------------------------------------------

void FB::Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData)
{
  if (workIdx == 0 && btcWork()) {
    // Primary (BTC) must use the mutated header/coinbase that matches the submitted share
    btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
  }
  else if (workIdx > 0 && fbWork(workIdx - 1)) {
    // Secondary (FB) produces AuxPoW container like DOGE
    fbWork(workIdx - 1)->buildBlockImpl(FBHeader_[workIdx - 1], FBWitness_[workIdx - 1], blockHexData);
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
  // ---- BTC (primary) context (mirror DOGE's LTC primary handling) ----
  BTCHeader_       = btcWork()->Header;
  BTCMerklePath_   = btcWork()->MerklePath;
  BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

  // ---- FB (secondaries) ----
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

    // Copy POD fields (avoid copying streams)
    header = work->Header;

    // Build a static coinbase (no extranonce) to compute the hashMerkleRoot like DOGE
    CMiningConfig emptyExtraNonceConfig;
    emptyExtraNonceConfig.FixedExtraNonceSize   = 0;
    emptyExtraNonceConfig.MutableExtraNonceSize = 0;
    work->buildCoinbaseTx(nullptr, 0, emptyExtraNonceConfig, legacy, witness);

    // Mark AuxPoW and compute merkle root from static coinbase + FB merkle path
    header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
    {
      uint256 coinbaseTxHash;
      CCtxSha256 sha256;
      sha256Init(&sha256);
      sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
      sha256Final(&sha256, coinbaseTxHash.begin());
      sha256Init(&sha256);
      sha256Update(&sha256, coinbaseTxHash.begin(), coinbaseTxHash.size());
      sha256Final(&sha256, coinbaseTxHash.begin());

      header.hashMerkleRoot = calculateMerkleRootWithPath(
        coinbaseTxHash, &work->MerklePath[0], work->MerklePath.size(), 0);
    }

    // Save header hash at its virtual chain position
    FBHeaderHashes_[FBWorkMap_[workIdx]] = header.GetHash();
  }

  // ---- Build the reversed chain merkle root over FB header hashes (exactly like DOGE) ----
  uint256 chainMerkleRoot = calculateMerkleRoot(&FBHeaderHashes_[0], FBHeaderHashes_.size());
  std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

  // ---- Splice the merged-mining commitment into the BTC coinbase ----
  uint8_t buffer[1024];
  xmstream coinbaseMsg(buffer, sizeof(buffer));
  coinbaseMsg.reset();
  coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
  coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
  coinbaseMsg.write<uint32_t>(virtualHashesNum);
  coinbaseMsg.write<uint32_t>(mmNonce);
  btcWork()->buildCoinbaseTx(coinbaseMsg.data(), coinbaseMsg.sizeOf(), miningCfg, BTCLegacy_, BTCWitness_);

  FBConsensusCtx_ = fbWork(0)->ConsensusCtx_;
}

std::string FB::Stratum::MergedWork::blockHash(size_t workIdx)
{
  if (workIdx == 0 && btcWork())
    return BTCHeader_.GetHash().GetHex();
  else if (workIdx > 0 && fbWork(workIdx - 1))
    return FBHeader_[workIdx - 1].GetHash().GetHex();
  return std::string();
}

bool FB::Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                               const CStratumMessage &msg)
{
  // Primary – fill header from submitted share
  if (!BTC::Stratum::Work::prepareForSubmitImpl(
        BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCWitness_, BTCMerklePath_,
        workerCfg, MiningCfg_, msg))
    return false;

  // For each FB secondary, attach AuxPoW proof data (parent coinbase, branches, etc.)
  for (size_t i = 0; i < FBHeader_.size(); ++i) {
    FB::Proto::BlockHeader &hdr = FBHeader_[i];

    // Parent block coinbase (deserialize from BTC witness template)
    BTCWitness_.Data.seekSet(0);
    BTC::unserialize(BTCWitness_.Data, hdr.ParentBlockCoinbaseTx);

    hdr.HashBlock.SetNull();
    hdr.Index = 0;

    // Tx merkle path inside BTC block (to coinbase)
    hdr.MerkleBranch.resize(BTCMerklePath_.size());
    for (size_t j = 0; j < BTCMerklePath_.size(); ++j)
      hdr.MerkleBranch[j] = BTCMerklePath_[j];

    // Virtual chain merkle branch for this FB header
    std::vector<uint256> path;
    buildMerklePath(FBHeaderHashes_, FBWorkMap_[i], path);
    hdr.ChainMerkleBranch.resize(path.size());
    for (size_t j = 0; j < path.size(); ++j)
      hdr.ChainMerkleBranch[j] = path[j];

    hdr.ChainIndex  = FBWorkMap_[i];
    hdr.ParentBlock = BTCHeader_;
  }

  return true;
}

CCheckStatus FB::Stratum::MergedWork::checkConsensus(size_t workIdx)
{
  if (workIdx == 0 && btcWork())
    return BTC::Stratum::Work::checkConsensusImpl(BTCHeader_, BTCConsensusCtx_);
  else if (workIdx > 0 && fbWork(workIdx - 1))
    return FB::Stratum::FBWork::checkConsensusImpl(FBHeader_[workIdx - 1], FBConsensusCtx_);

  return CCheckStatus();
}

// Required pure-virtuals from StratumWork
void FB::Stratum::MergedWork::mutate()
{
  // Same pattern as DOGE: bump nTime and rebuild notify
  BTCHeader_.nTime = static_cast<uint32_t>(time(nullptr));
  BTC::Stratum::Work::buildNotifyMessageImpl(
    this, BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCMerklePath_, MiningCfg_, true, NotifyMessage_);
}

void FB::Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork)
{
  BTC::Stratum::Work::buildNotifyMessageImpl(
    this, BTCHeader_, BTCHeader_.nVersion, BTCLegacy_, BTCMerklePath_, MiningCfg_, resetPreviousWork, NotifyMessage_);
}

// -----------------------------------------------------------------------------------
// Secondary work creation & merged-work glue
// -----------------------------------------------------------------------------------

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

  // Mark AuxPoW (version bit); aux hash is indirectly committed via MergedWork ctor
  work->Header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
  return work.release();
}

StratumMergedWork *FB::Stratum::newMergedWork(int64_t stratumId,
                                              StratumSingleWork *first,
                                              std::vector<StratumSingleWork*> &second,
                                              const CMiningConfig &miningCfg,
                                              std::string &error)
{
  uint32_t mmNonce = 0;
  unsigned virtualHashesNum = 0;

  std::vector<int> chainMap = Stratum::buildChainMap(second, mmNonce, virtualHashesNum);
  if (chainMap.empty()) {
    error = "cannot build chain map for merged mining";
    return nullptr;
  }

  return new FB::Stratum::MergedWork(stratumId, first, second, chainMap, mmNonce, virtualHashesNum, miningCfg);
}

} // namespace FB

// -----------------------------------------------------------------------------------
// I/O helpers (parity with DOGE, plus FB has unserialize convenience)
// -----------------------------------------------------------------------------------

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
} // namespace BTC

// -----------------------------------------------------------------------------------
// JSON parity (match DOGE including nested parentBlock)
// -----------------------------------------------------------------------------------

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
  s.write("\"parentBlock\":{");
  serializeJsonInside(s, h.ParentBlock);
  s.write('}');
}
