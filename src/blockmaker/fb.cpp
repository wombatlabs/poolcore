// fb.cpp
#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "blockmaker/serialize.h"      // for BTC::serialize / unserialize
#include "poolinstances/stratum.h"     // for StratumMergedWork, CStratumMessage, etc.

static void quoteString(xmstream &stream, const std::string &s) {
    stream.write("\"", 1);
    stream.write(s.data(), s.size());
    stream.write("\"", 1);
}

namespace BTC {
  //------------------------------------------------------------------------------------------------
  // Serialize FB::Proto::BlockHeader exactly like AuxPoW. First the 80-byte BTC header, then
  // (if VERSION_AUXPOW is set) all the AuxPoW payload fields.
  //------------------------------------------------------------------------------------------------
  void Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data) {
    // 1) Write pure 80-byte BTC header (cast away AuxPoW fields)
    BTC::serialize(dst, *(const BTC::Proto::BlockHeader*)&data);

    // 2) If AuxPoW bit is set, serialize AuxPoW extras:
    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
      // a) Parent-chain coinbase transaction
      BTC::serialize(dst, data.ParentBlockCoinbaseTx);
      // b) Parent header’s hash, Merkle branch, and index
      BTC::serialize(dst, data.HashBlock);
      BTC::serialize(dst, data.MerkleBranch);
      BTC::serialize(dst, data.Index);
      // c) Chain-merkle branch (empty for FB) and chain index
      BTC::serialize(dst, data.ChainMerkleBranch);
      BTC::serialize(dst, data.ChainIndex);
      // d) Full parent header so pool can re-check its PoW
      BTC::serialize(dst, data.ParentBlock);
    }
  }

  void Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &data) {
    // PoolCore’s mining flow never calls this; stub out:
    BTC::unserialize(src, (BTC::Proto::BlockHeader&)data);
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
} // namespace BTC

//------------------------------------------------------------------------------------------------
// JSON-serializer for getblocktemplate: write only the “inside” fields of the FB header.
// (PoolCore’s mining logic does not use this directly; it’s here in case an external FB
// daemon needs to include AuxPoW fields in JSON responses to wallets, etc.)
//------------------------------------------------------------------------------------------------
void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header) {
  // We use serializeJson(...) (from "blockmaker/serializeJson.h") for numeric or object fields,
  // and manual quoting for uint256 hashes.
  stream.write("{", 1);

  // Pure BTC header
  serializeJson(stream, "version", header.nVersion);
  stream.write(",\"previousblockhash\":", 21);
  quoteString(stream, header.hashPrevBlock.ToString());
  stream.write(",\"merkleroot\":", 14);
  quoteString(stream, header.hashMerkleRoot.ToString());
  stream.write(",\"time\":", 8);
  serializeJson(stream, header.nTime);
  stream.write(",\"bits\":", 8);
  serializeJson(stream, header.nBits);
  stream.write(",\"nonce\":", 9);
  serializeJson(stream, header.nNonce);

  // AuxPoW fields if present
  if (header.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
    stream.write(",\"parentcoinbase\":", 17);
    serializeJson(stream, header.ParentBlockCoinbaseTx);

    stream.write(",\"hashblock\":", 13);
    quoteString(stream, header.HashBlock.ToString());

    // MerkleBranch array
    stream.write(",\"merklebranch\":", 16);
    stream.write("[", 1);
    for (size_t i = 0; i < header.MerkleBranch.size(); ++i) {
      quoteString(stream, header.MerkleBranch[i].ToString());
      if (i + 1 < header.MerkleBranch.size()) stream.write(",", 1);
    }
    stream.write("]", 1);

    stream.write(",\"index\":", 9);
    serializeJson(stream, header.Index);

    // ChainMerkleBranch array (FB has none)
    stream.write(",\"chainmerklebranch\":", 21);
    stream.write("[", 1);
    for (size_t i = 0; i < header.ChainMerkleBranch.size(); ++i) {
      quoteString(stream, header.ChainMerkleBranch[i].ToString());
      if (i + 1 < header.ChainMerkleBranch.size()) stream.write(",", 1);
    }
    stream.write("]", 1);

    stream.write(",\"chainindex\":", 14);
    serializeJson(stream, header.ChainIndex);

    stream.write(",\"parentblock\":", 13);
    serializeJson(stream, header.ParentBlock);
  }

  stream.write("}", 1);
}

namespace FB {
namespace {
  // AuxPoW “magic” header (same as DOGE)
  static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

  // Compute minimal Merkle-path height to accommodate count leaves
  static unsigned merklePathSize(unsigned count) {
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
  }

  // Pseudo-random index in [0, 2^h) given nonce and chainId
  static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t x = nNonce;
    x = x * 1103515245 + 12345;
    x += nChainId;
    x = x * 1103515245 + 12345;
    return x % (1u << h);
  }
} // anon namespace

//------------------------------------------------------------------------------------------------
// Build a distinct index for each FB secondary in a Merkle tree. Identical to Doge’s logic.
// secondaries.size() = N; returns a vector<int> of length N mapping each work → leaf index.
//------------------------------------------------------------------------------------------------
std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondaries,
    uint32_t                       &nonce,
    unsigned                       &virtualHashesNum
) {
  std::vector<int> result(secondaries.size());
  bool finished = false;
  std::vector<int> chainMap;

  unsigned needed = merklePathSize(secondaries.size());
  for (unsigned pathSize = needed; pathSize < 8; ++pathSize) {
    virtualHashesNum = (1u << pathSize);
    chainMap.assign(virtualHashesNum, 0);

    for (nonce = 0; nonce < virtualHashesNum; ++nonce) {
      std::fill(chainMap.begin(), chainMap.end(), 0);
      finished = true;
      for (size_t i = 0; i < secondaries.size(); ++i) {
        FbWork *wk = static_cast<FbWork*>(secondaries[i]);
        int chainId = (wk->Header.nVersion >> 16);
        unsigned idx = getExpectedIndex(nonce, chainId, pathSize);
        if (chainMap[idx] == 0) {
          chainMap[idx] = 1;
          result[i] = idx;
        } else {
          finished = false;
          break;
        }
      }
      if (finished) break;
    }
    if (finished) break;
  }

  return (finished ? result : std::vector<int>());
}

//------------------------------------------------------------------------------------------------
// When FB runs standalone (no merged mining), accept only EWorkBitcoin templates.
//------------------------------------------------------------------------------------------------
Stratum::Work* Stratum::newPrimaryWork(
    int64_t                    stratumId,
    PoolBackend               *backend,
    size_t                     backendIdx,
    const CMiningConfig       &miningCfg,
    const std::vector<uint8_t> &miningAddress,
    const std::string         &coinbaseMessage,
    CBlockTemplate            &blockTemplate,
    std::string               &error
) {
  if (blockTemplate.WorkType != EWorkBitcoin) {
    error = "incompatible work type for FB";
    return nullptr;
  }
  auto ptr = std::make_unique<FbWork>(
    stratumId,
    blockTemplate.UniqueWorkId,
    backend,
    backendIdx,
    miningCfg,
    miningAddress,
    coinbaseMessage
  );
  return ptr->loadFromTemplate(blockTemplate, error) ? ptr.release() : nullptr;
}

//------------------------------------------------------------------------------------------------
// When FB is a secondary under BTC (merged mining), accept EWorkBitcoin as well.
//------------------------------------------------------------------------------------------------
Stratum::Work* Stratum::newSecondaryWork(
    int64_t                    stratumId,
    PoolBackend               *backend,
    size_t                     backendIdx,
    const CMiningConfig       &miningCfg,
    const std::vector<uint8_t> &miningAddress,
    const std::string         &coinbaseMessage,
    CBlockTemplate            &blockTemplate,
    std::string               &error
) {
  if (blockTemplate.WorkType != EWorkBitcoin) {
    error = "incompatible work type for FB-secondary";
    return nullptr;
  }
  auto ptr = std::make_unique<FbWork>(
    stratumId,
    blockTemplate.UniqueWorkId,
    backend,
    backendIdx,
    miningCfg,
    miningAddress,
    coinbaseMessage
  );
  return ptr->loadFromTemplate(blockTemplate, error) ? ptr.release() : nullptr;
}

//------------------------------------------------------------------------------------------------
// When PoolCore builds one BTC primary + N FB secondaries, this returns a MergedWork.
//------------------------------------------------------------------------------------------------
StratumMergedWork* Stratum::newMergedWork(
    int64_t                         stratumId,
    StratumSingleWork              *first,
    std::vector<StratumSingleWork*> &second,
    const CMiningConfig             &miningCfg,
    std::string                     &error
) {
  uint32_t nonce = 0;
  unsigned virtualHashesNum = 0;
  std::vector<int> chainMap = buildChainMap(second, nonce, virtualHashesNum);
  if (chainMap.empty()) {
    error = "failed to build AuxPoW chain map for FB secondaries";
    return nullptr;
  }
  return new MergedWork(stratumId, first, second, chainMap, nonce, virtualHashesNum, miningCfg);
}

//------------------------------------------------------------------------------------------------
// MergedWork constructor: pack one BTC primary + N FB secondaries into an AuxPoW blob.
//------------------------------------------------------------------------------------------------
Stratum::MergedWork::MergedWork(
    uint64_t                         stratumWorkId,
    StratumSingleWork              *first,
    std::vector<StratumSingleWork*> &second,
    std::vector<int>                &mmChainId,
    uint32_t                         mmNonce,
    unsigned                         virtualHashesNum,
    const CMiningConfig             &miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg),
    MiningCfg_(miningCfg)
{
  // 1) Extract BTC primary fields
  auto *bw = static_cast<BTC::Stratum::Work*>(Works_[0].Work);
  BTCHeader_       = bw->Header;
  BTCMerklePath_   = bw->MerklePath;
  BTCConsensusCtx_ = bw->ConsensusCtx_;
  // Move primary's coinbase TXs (legacy + witness)
  BTCLegacy_  = std::move(bw->CBTxLegacy_);
  BTCWitness_ = std::move(bw->CBTxWitness_);

  // 2) Resize FB secondary arrays
  size_t nSec = second.size();
  fbHeaders_.resize(nSec);
  fbLegacy_.resize(nSec);
  fbWitness_.resize(nSec);
  fbWorkMap_ = mmChainId;
  fbConsensusCtx_.resize(nSec);
  fbChainParams_ = BTC::Proto::ChainParams();

  // 3) For each FB secondary: copy header, coinbases, consensus, toggle AuxPoW, etc.
  for (size_t i = 0; i < nSec; ++i) {
    auto *fw = static_cast<FbWork*>(second[i]);
    fbHeaders_[i] = fw->Header;                               // copy child’s header
    fbLegacy_[i]  = std::move(fw->CBTxLegacy_);               // move child’s legacy coinbase
    fbWitness_[i] = std::move(fw->CBTxWitness_);              // move child’s witness coinbase
    fbConsensusCtx_[i] = fw->ConsensusCtx_;                   // copy consensus context

    // Toggle AuxPoW version bit on child header:
    fbHeaders_[i].nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
    // Copy child’s Merkle path and set its index in the chain:
    fbHeaders_[i].MerkleBranch = fw->MerklePath;
    fbHeaders_[i].Index        = mmChainId[i];
    // FB has no further “chain” levels, so:
    fbHeaders_[i].ChainMerkleBranch.clear();
    fbHeaders_[i].ChainIndex = 0;
    // Copy parentCoinbase, hashBlock, parentBlock:
    fbHeaders_[i].ParentBlockCoinbaseTx = fw->Header.ParentBlockCoinbaseTx;
    fbHeaders_[i].HashBlock             = fw->Header.HashBlock;
    fbHeaders_[i].ParentBlock           = fw->Header.ParentBlock;
  }

  // 4) Compute “child root” from the first FB secondary’s HashBlock & MerkleBranch
  uint256 childRoot = merkleTree::calculateRoot(
    (uint256&)fbHeaders_[0].HashBlock,
    fbHeaders_[0].MerkleBranch
  );
  // Convert to big-endian bytes, then reverse to little-endian for coinbase:
  std::vector<uint8_t> rootBytes(32);
  childRoot.ToBytes(rootBytes.data());
  std::reverse(rootBytes.begin(), rootBytes.end());

  // 5) Prepend AuxPoW “magic” + reversed childRoot to primary’s coinbase script
  xmstream cbStream;
  cbStream.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
  cbStream.write(rootBytes.data(), 32);

  // Append original primary coinbase (serialize then write)
  xmstream origCb;
  BTCLegacy_.serialize(origCb);
  cbStream.write(origCb.data(), origCb.size());
  // Replace BTCLegacy_ with the new combined script
  BTCLegacy_.deserialize(cbStream);

  // 6) Recompute primary’s hashMerkleRoot from modified BTCLegacy_ + BTCMerklePath_
  uint256 newRoot = merkleTree::calculateRoot(
    (uint256&)BTCHeader_.hashMerkleRoot,
    BTCMerklePath_
  );
  BTCHeader_.hashMerkleRoot = newRoot;
}

//------------------------------------------------------------------------------------------------
// shareHash: always use primary’s share-hash (FB shares count only on primary).
//------------------------------------------------------------------------------------------------
Proto::BlockHashTy Stratum::MergedWork::shareHash() {
  return btcWork()->shareHash();
}

//------------------------------------------------------------------------------------------------
// blockHash: index 0 → BTC’s blockhash; index i>0 → FB’s parentBlock hash.
//------------------------------------------------------------------------------------------------
std::string Stratum::MergedWork::blockHash(size_t workIdx) {
  if (workIdx == 0) {
    return btcWork()->blockHash(workIdx);
  } else {
    return fbHeaders_[workIdx - 1].ParentBlock.GetHash().ToString();
  }
}

//------------------------------------------------------------------------------------------------
// mutate: delegate to primary
//------------------------------------------------------------------------------------------------
void Stratum::MergedWork::mutate() {
  btcWork()->mutate();
}

//------------------------------------------------------------------------------------------------
// buildNotifyMessage: delegate to primary
//------------------------------------------------------------------------------------------------
void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork) {
  btcWork()->buildNotifyMessage(resetPreviousWork);
}

//------------------------------------------------------------------------------------------------
// prepareForSubmit: first serialize primary, then append "auxpow":[…] for FB secondaries.
//------------------------------------------------------------------------------------------------
bool Stratum::MergedWork::prepareForSubmit(
    const CWorkerConfig &workerCfg,
    const CStratumMessage &msg
) {
  // 1) Serialize primary using BTC’s prepareForSubmitImpl
  bool ok = BTC::Stratum::Work::prepareForSubmitImpl(
               BTCHeader_,
               BTCHeader_.nVersion,
               BTCLegacy_,
               BTCWitness_,
               BTCMerklePath_,
               workerCfg,
               MiningCfg_,
               msg
             );
  if (!ok) return false;

  // 2) Append ,"auxpow":[…] for each FB secondary
  xmstream &stream = msg.getSubmitStream();
  stream.write(",\"auxpow\":[", 10);
  for (size_t i = 0; i < fbHeaders_.size(); ++i) {
    stream.write("{", 1);
    // "parentblock":
    stream.write("\"parentblock\":", 14);
    serializeJson(stream, fbHeaders_[i].ParentBlock);
    // ,"merklebranch":[…]
    stream.write(",\"merklebranch\":[", 17);
    for (size_t j = 0; j < fbHeaders_[i].MerkleBranch.size(); ++j) {
      quoteString(stream, fbHeaders_[i].MerkleBranch[j].ToString());
      if (j + 1 < fbHeaders_[i].MerkleBranch.size()) stream.write(",", 1);
    }
    stream.write("]", 1);
    // ,"index":
    stream.write(",\"index\":", 9);
    serializeJson(stream, fbHeaders_[i].Index);
    // ,"chainmerklebranch":[…]
    stream.write(",\"chainmerklebranch\":[", 21);
    for (size_t j = 0; j < fbHeaders_[i].ChainMerkleBranch.size(); ++j) {
      quoteString(stream, fbHeaders_[i].ChainMerkleBranch[j].ToString());
      if (j + 1 < fbHeaders_[i].ChainMerkleBranch.size()) stream.write(",", 1);
    }
    stream.write("]", 1);
    // ,"chainindex":
    stream.write(",\"chainindex\":", 14);
    serializeJson(stream, fbHeaders_[i].ChainIndex);
    // ,"parentcoinbasetx":
    stream.write(",\"parentcoinbasetx\":", 19);
    serializeJson(stream, fbHeaders_[i].ParentBlockCoinbaseTx);
    // ,"hashblock":
    stream.write(",\"hashblock\":", 13);
    quoteString(stream, fbHeaders_[i].HashBlock.ToString());
    stream.write("}", 1);
    if (i + 1 < fbHeaders_.size()) stream.write(",", 1);
  }
  stream.write("]", 1);

  return true;
}

//------------------------------------------------------------------------------------------------
// buildBlock: only primary is submitted. FB secondaries’ shares are not separately submitted.
//------------------------------------------------------------------------------------------------
void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
  if (workIdx == 0) {
    btcWork()->buildBlock(workIdx, blockHexData);
  }
}

//------------------------------------------------------------------------------------------------
// checkConsensus: verify primary’s POW or FB’s parent-block POW.
//------------------------------------------------------------------------------------------------
CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
  if (workIdx == 0) {
    return BTC::Proto::checkConsensus(BTCHeader_, BTCConsensusCtx_, fbChainParams_);
  } else {
    // FB secondary was already validated via parent block; accept.
    return CCheckStatus::OK;
  }
}

} // namespace FB
