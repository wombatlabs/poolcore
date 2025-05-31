#include "fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

namespace FB {

//------------------------------------------------------------------------------
// buildChainMap: VERY similar to DOGE’s version, but for FB:
//------------------------------------------------------------------------------

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

std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*>& secondary, uint32_t& nonce, unsigned& virtualHashesNum) {
  std::vector<int> result(secondary.size());
  bool finished = true;

  for (unsigned pathSize = merklePathSize(secondary.size()); pathSize < 8; pathSize++) {
    virtualHashesNum = 1u << pathSize;
    std::vector<int> chainMap(virtualHashesNum);

    for (nonce = 0; nonce < virtualHashesNum; nonce++) {
      finished = true;
      std::fill(chainMap.begin(), chainMap.end(), 0);

      for (size_t workIdx = 0; workIdx < secondary.size(); workIdx++) {
        Stratum::FbWork* work = fbWork(workIdx);
        uint32_t chainId = work->Header.nVersion >> 16;
        uint32_t indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);

        if (chainMap[indexInMerkle] == 0) {
          chainMap[indexInMerkle] = 1;
          result[workIdx] = indexInMerkle;
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

  return (finished ? result : std::vector<int>());
}

//------------------------------------------------------------------------------
// MergedWork constructor
//------------------------------------------------------------------------------

Stratum::MergedWork::MergedWork(
    uint64_t stratumWorkId,
    StratumSingleWork* first,
    std::vector<StratumSingleWork*>& second,
    std::vector<int>& mmChainId,
    uint32_t mmNonce,
    unsigned virtualHashesNum,
    const CMiningConfig& miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
  // --- copy primary (BTC) header + merkle + consensus ctx ---
  BTCHeader_ = btcWork()->Header;
  BTCMerklePath_ = btcWork()->MerklePath;
  BTCConsensusCtx_ = btcWork()->ConsensusCtx_;

  // --- allocate FB-specific arrays ---
  FBHeader_.resize(second.size());
  FBLegacy_.resize(second.size());
  FBWitness_.resize(second.size());
  FBHeaderHashes_.resize(virtualHashesNum, uint256());
  FBWorkMap_.assign(mmChainId.begin(), mmChainId.end());

  // --- for each FB secondary work, build “static” coinbase (no extra nonce) to compute header hash ---
  for (size_t workIdx = 0; workIdx < FBHeader_.size(); workIdx++) {
    Stratum::FbWork* work = fbWork(workIdx);
    FB::Proto::BlockHeader& header = FBHeader_[workIdx];
    BTC::CoinbaseTx& legacy = FBLegacy_[workIdx];
    BTC::CoinbaseTx& witness = FBWitness_[workIdx];

    header = work->Header;

    // create a “static” FB coinbase TX without any extra‐nonce
    CMiningConfig emptyExtra;
    emptyExtra.FixedExtraNonceSize = 0;
    emptyExtra.MutableExtraNonceSize = 0;
    work->buildCoinbaseTx(nullptr, 0, emptyExtra, legacy, witness);

    // calculate FB-specific merkle root:
    header.nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
    {
      uint256 coinbaseHash;
      CCtxSha256 sha256;
      sha256Init(&sha256);
      sha256Update(&sha256, legacy.Data.data(), legacy.Data.sizeOf());
      sha256Final(&sha256, coinbaseHash.begin());
      sha256Init(&sha256);
      sha256Update(&sha256, coinbaseHash.begin(), coinbaseHash.size());
      sha256Final(&sha256, coinbaseHash.begin());
      header.hashMerkleRoot = calculateMerkleRootWithPath(coinbaseHash, &work->MerklePath[0], work->MerklePath.size(), 0);
    }
    FBHeaderHashes_[FBWorkMap_[workIdx]] = header.GetHash();
  }

  // compute “reversed” chain‐merkle‐root from all FB header hashes:
  uint256 chainMerkleRoot = calculateMerkleRoot(&FBHeaderHashes_[0], FBHeaderHashes_.size());
  std::reverse(chainMerkleRoot.begin(), chainMerkleRoot.end());

  // now build the BTC coinbase; insert: <preamble><chainMerkleRoot><virtualHashesNum><mmNonce>
  {
    uint8_t buffer[1024];
    xmstream coinbaseMsg(buffer, sizeof(buffer));
    coinbaseMsg.reset();
    coinbaseMsg.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    coinbaseMsg.write(chainMerkleRoot.begin(), sizeof(uint256));
    coinbaseMsg.write<uint32_t>(virtualHashesNum);
    coinbaseMsg.write<uint32_t>(mmNonce);
    btcWork()->buildCoinbaseTx(
      coinbaseMsg.data(),
      coinbaseMsg.sizeOf(),
      miningCfg,
      BTCLegacy_,
      BTCWitness_
    );
  }

  // finally, grab the FB consensus‐context from the first secondary:
  FBConsensusCtx_ = fbWork(0)->ConsensusCtx_;
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig& workerCfg, const CStratumMessage& msg) {
  // first, have BTC::Stratum::Work prepare and fill everything related to BTC
  if (!BTC::Stratum::Work::prepareForSubmitImpl(
        BTCHeader_,
        BTCHeader_.nVersion,
        BTCLegacy_,
        BTCWitness_,
        BTCMerklePath_,
        workerCfg,
        MiningCfg_,
        msg))
    return false;

  // then for each FB header, we stitch in its AuxPoW fields
  for (size_t workIdx = 0; workIdx < FBHeader_.size(); workIdx++) {
    FB::Proto::BlockHeader& header = FBHeader_[workIdx];
    BTCWitness_.Data.seekSet(0);
    BTC::unserialize(BTCWitness_.Data, header.ParentBlockCoinbaseTx);

    header.HashBlock.SetNull();
    header.Index = 0;

    // copy BTC merkle branches into FB header
    header.MerkleBranch.resize(BTCMerklePath_.size());
    for (size_t j = 0; j < BTCMerklePath_.size(); j++)
      header.MerkleBranch[j] = BTCMerklePath_[j];

    // rebuild the FB merkle path for this workIdx
    std::vector<uint256> path;
    buildMerklePath(FBHeaderHashes_, FBWorkMap_[workIdx], path);
    header.ChainMerkleBranch.resize(path.size());
    for (size_t j = 0; j < path.size(); j++)
      header.ChainMerkleBranch[j] = path[j];
    header.ChainIndex = FBWorkMap_[workIdx];
    header.ParentBlock = BTCHeader_;
  }

  return true;
}

//------------------------------------------------------------------------------
// Helper: return the primary BTC::Work pointer
//------------------------------------------------------------------------------

BTC::Stratum::Work* Stratum::btcWork() {
  return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
}

//------------------------------------------------------------------------------
// Helper: return the FB::Work pointer at index
//------------------------------------------------------------------------------

Stratum::FbWork* Stratum::fbWork(unsigned index) {
  // index 0 of "secondaries" is actually stored at Works_[index+1]
  return static_cast<Stratum::FbWork*>(Works_[index + 1].Work);
}

//------------------------------------------------------------------------------
// newPrimaryWork: exactly the same as DOGE/LTC except FB::WorkTy instead of LTC::Work
//------------------------------------------------------------------------------

LTC::Stratum::Work* Stratum::newPrimaryWork(
    int64_t stratumId,
    PoolBackend* backend,
    size_t backendIdx,
    const CMiningConfig& miningCfg,
    const std::vector<uint8_t>& miningAddress,
    const std::string& coinbaseMessage,
    CBlockTemplate& blockTemplate,
    std::string& error
) {
  if (blockTemplate.WorkType != EWorkBitcoin) {
    error = "incompatible work type";
    return nullptr;
  }
  std::unique_ptr<LTC::Stratum::Work> work(new LTC::Stratum::Work(
    stratumId,
    blockTemplate.UniqueWorkId,
    backend,
    backendIdx,
    miningCfg,
    miningAddress,
    coinbaseMessage
  ));
  return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//------------------------------------------------------------------------------
// newSecondaryWork: analogous to DOGE::newSecondaryWork but for FB::WorkTy
//------------------------------------------------------------------------------

Stratum::FbWork* Stratum::newSecondaryWork(
    int64_t stratumId,
    PoolBackend* backend,
    size_t backendIdx,
    const CMiningConfig& miningCfg,
    const std::vector<uint8_t>& miningAddress,
    const std::string& coinbaseMessage,
    CBlockTemplate& blockTemplate,
    std::string& error
) {
  if (blockTemplate.WorkType != EWorkBitcoin) {
    error = "incompatible work type";
    return nullptr;
  }
  std::unique_ptr<FbWork> work(new FbWork(
    stratumId,
    blockTemplate.UniqueWorkId,
    backend,
    backendIdx,
    miningCfg,
    miningAddress,
    coinbaseMessage
  ));
  return work->loadFromTemplate(blockTemplate, error) ? work.release() : nullptr;
}

//------------------------------------------------------------------------------
// newMergedWork: exactly the same pattern as DOGE, except calling our MergedWork
//------------------------------------------------------------------------------

StratumMergedWork* Stratum::newMergedWork(
    int64_t stratumId,
    StratumSingleWork* primaryWork,
    std::vector<StratumSingleWork*>& secondaryWorks,
    const CMiningConfig& miningCfg,
    std::string& error
) {
  if (secondaryWorks.empty()) {
    error = "no secondary works";
    return nullptr;
  }
  uint32_t nonce = 0;
  unsigned virtualHashesNum = 0;
  std::vector<int> chainMap = buildChainMap(secondaryWorks, nonce, virtualHashesNum);
  if (chainMap.empty()) {
    error = "chainId conflict";
    return nullptr;
  }
  return new MergedWork(stratumId, primaryWork, secondaryWorks, chainMap, nonce, virtualHashesNum, miningCfg);
}

} // namespace FB

//------------------------------------------------------------------------------
// Specialize BTC::Io for FB::Proto::BlockHeader (exactly as DOGE did)
//------------------------------------------------------------------------------

namespace BTC {
template<> struct Io<FB::Proto::BlockHeader> {
  static void serialize(xmstream& dst, const FB::Proto::BlockHeader& data) {
    BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);
    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
      BTC::serialize(dst, data.ParentBlockCoinbaseTx);
      BTC::serialize(dst, data.HashBlock);
      BTC::serialize(dst, data.MerkleBranch);
      BTC::serialize(dst, data.Index);
      BTC::serialize(dst, data.ChainMerkleBranch);
      BTC::serialize(dst, data.ChainIndex);
      BTC::serialize(dst, data.ParentBlock);
    }
  }

  static void unserialize(xmstream& src, FB::Proto::BlockHeader& data) {
    BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&data);
    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
      BTC::unserialize(src, data.ParentBlockCoinbaseTx);
      BTC::unserialize(src, data.HashBlock);
      BTC::unserialize(src, data.MerkleBranch);
      BTC::unserialize(src, data.Index);
      BTC::unserialize(src, data.ChainMerkleBranch);
      BTC::unserialize(src, data.ChainIndex);
      BTC::unserialize(src, data.ParentBlock);
    }
  }
};
} // namespace BTC

//------------------------------------------------------------------------------
// JSON serialization helper (same as DOGE’s, but for FB)
//------------------------------------------------------------------------------

void serializeJsonInside(xmstream& stream, const FB::Proto::BlockHeader& header) {
  serializeJson(stream, "version", header.nVersion); stream.write(',');
  serializeJson(stream, "hashPrevBlock", header.hashPrevBlock); stream.write(',');
  serializeJson(stream, "hashMerkleRoot", header.hashMerkleRoot); stream.write(',');
  serializeJson(stream, "time", header.nTime); stream.write(',');
  serializeJson(stream, "bits", header.nBits); stream.write(',');
  serializeJson(stream, "nonce", header.nNonce); stream.write(',');
  serializeJson(stream, "parentBlockCoinbaseTx", header.ParentBlockCoinbaseTx); stream.write(',');
  serializeJson(stream, "hashBlock", header.HashBlock); stream.write(',');
  serializeJson(stream, "merkleBranch", header.MerkleBranch); stream.write(',');
  serializeJson(stream, "index", header.Index); stream.write(',');
  serializeJson(stream, "chainMerkleBranch", header.ChainMerkleBranch); stream.write(',');
  serializeJson(stream, "chainIndex", header.ChainIndex); stream.write(',');
  stream.write("\"parentBlock\":{");
  serializeJsonInside(stream, header.ParentBlock);
  stream.write('}');
}
