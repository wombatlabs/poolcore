// fb.cpp
#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "blockmaker/serialize.h"         // for BTC::serialize(xmstream&, ...)
#include "poolinstances/stratum.h"        // for StratumMergedWork base class
#include "poolcommon/arith_uint256.hpp"   // for uint256

namespace BTC {
  //============================================================================== 
  // Serialize FB::Proto::BlockHeader as AuxPoW header: first pure BTC header, then AuxPoW fields
  //==============================================================================
  void Io<FB::Proto::BlockHeader>::serialize(xmstream &dst, const FB::Proto::BlockHeader &data) {
    // 1) Write pure BTC header (six 4/32/32/4/4/4 bytes)
    BTC::serialize(dst, *(const BTC::Proto::BlockHeader*)&data);

    // 2) If AuxPoW bit set, write AuxPoW fields
    if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
      // a) Parent-block coinbase transaction
      BTC::serialize(dst, data.ParentBlockCoinbaseTx);
      // b) Parent header’s hash, Merkle branch, and index
      BTC::serialize(dst, data.HashBlock);
      BTC::serialize(dst, data.MerkleBranch);
      BTC::serialize(dst, data.Index);
      // c) Chain Merkle branch and index
      BTC::serialize(dst, data.ChainMerkleBranch);
      BTC::serialize(dst, data.ChainIndex);
      // d) Finally, the full parent header
      BTC::serialize(dst, data.ParentBlock);
    }
  }

  void Io<FB::Proto::BlockHeader>::unserialize(xmstream &src, FB::Proto::BlockHeader &data) {
    // Unserialization is not used in mining flow. Stub out:
    // 1) Read pure BTC header
    BTC::unserialize(src, (BTC::Proto::BlockHeader&)data);
    // 2) If AuxPoW version, skip AuxPoW fields (not needed for pool)
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

//==============================================================================
// JSON‐serialize only the “inside” fields of an FB header (for getblocktemplate responses).
// This is used when the FB daemon needs to include AuxPoW fields in JSON.
//==============================================================================
void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header) {
  // Pure BTC header fields:
  stream.write("{");
  serializeJSON(stream, "version");            stream.write(":"); stream.writeInt(header.nVersion);
  stream.write(",\"previousblockhash\":");     serializeJSON(stream, header.hashPrevBlock);
  stream.write(",\"merkleroot\":");            serializeJSON(stream, header.hashMerkleRoot);
  stream.write(",\"time\":");                   stream.writeInt(header.nTime);
  stream.write(",\"bits\":");                   stream.writeInt(header.nBits);
  stream.write(",\"nonce\":");                  stream.writeInt(header.nNonce);

  // AuxPoW fields (if present):
  if (header.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
    // ParentBlockCoinbaseTx as hex
    stream.write(",\"parentcoinbase\":");
    serializeJSON(stream, header.ParentBlockCoinbaseTx);
    // HashBlock
    stream.write(",\"hashblock\":");      serializeJSON(stream, header.HashBlock);
    // MerkleBranch array
    stream.write(",\"merklebranch\":[");
    for (size_t i = 0; i < header.MerkleBranch.size(); ++i) {
      serializeJSON(stream, header.MerkleBranch[i]);
      if (i + 1 < header.MerkleBranch.size()) stream.write(",");
    }
    stream.write("]");
    // Index
    stream.write(",\"index\":");          stream.writeInt(header.Index);
    // ChainMerkleBranch array
    stream.write(",\"chainmerklebranch\":[");
    for (size_t i = 0; i < header.ChainMerkleBranch.size(); ++i) {
      serializeJSON(stream, header.ChainMerkleBranch[i]);
      if (i + 1 < header.ChainMerkleBranch.size()) stream.write(",");
    }
    stream.write("]");
    // ChainIndex
    stream.write(",\"chainindex\":");     stream.writeInt(header.ChainIndex);
    // ParentBlock header
    stream.write(",\"parentblock\":");     serializeJSON(stream, header.ParentBlock);
  }
  stream.write("}");
}

namespace FB {

namespace {
  // AuxPoW “magic” header bytes (same as DOGE)
  static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

  // Compute minimal Merkle path height to accommodate count leaves
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
} // anonymous namespace

//==============================================================================
// buildChainMap: identical to DOGE logic, but using FbWork instead of DogeWork.
// secondaries.size() = N, returns a vector<int> of length N mapping each work to a distinct leaf.
//==============================================================================
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

//==============================================================================
// newPrimaryWork: when FB runs standalone (primary), wrap BTC::Stratum::WorkTy logic.
//==============================================================================
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
  // FB uses pure SHA256, but our WorkTy is still BTC::WorkTy; check WorkType:
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

//==============================================================================
// newSecondaryWork: FB as a secondary under BTC—build FbWork from FB template.
//==============================================================================
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
  // As a secondary, FB still pulls pure BTC‐style templates from its own node,
  // but we must allow AuxPoW bit. However, since AuxPoW building happens in MergedWork,
  // here we treat FB as pure SHA256 as well.
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

//==============================================================================
// newMergedWork: build a MergedWork combining a BTC primary + N FB secondaries.
//==============================================================================
StratumMergedWork* Stratum::newMergedWork(
    int64_t                      stratumId,
    StratumSingleWork           *first,
    std::vector<StratumSingleWork*> &second,
    const CMiningConfig          &miningCfg,
    std::string                  &error
) {
  // ‘first’ is the primary (should be a BTC::Stratum::Work*)
  // second[i] are FB secondaries (FbWork*)
  // We need to compute chainMap + nonce + virtualHashesNum
  uint32_t nonce = 0;
  unsigned virtualHashesNum = 0;
  std::vector<int> chainMap = buildChainMap(second, nonce, virtualHashesNum);
  if (chainMap.empty()) {
    error = "failed to build AuxPoW chain map for FB secondaries";
    return nullptr;
  }
  return new MergedWork(stratumId, first, second, chainMap, nonce, virtualHashesNum, miningCfg);
}

//==============================================================================
// MergedWork constructor: pack one BTC primary + N FB secondaries into AuxPoW blob.
//==============================================================================
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
  // 1) Extract primary BTC work fields
  auto *bw = static_cast<BTC::Stratum::Work*>(Works_[0].Work);
  BTCHeader_     = bw->Header;
  BTCLegacy_     = std::move(bw->CBTxLegacy_);
  BTCWitness_    = std::move(bw->CBTxWitness_);
  BTCMerklePath_ = bw->MerklePath;
  BTCConsensusCtx_ = bw->ConsensusCtx_;

  // 2) Prepare vectors for N FB secondaries
  size_t nSec = second.size();
  fbHeaders_.resize(nSec);
  fbLegacy_.resize(nSec);
  fbWitness_.resize(nSec);
  fbHeaderHashes_.resize(nSec);
  fbWorkMap_ = mmChainId;
  fbConsensusCtx_.resize(nSec);
  fbChainParams_ = BTC::Proto::ChainParams(); // copy default chain params

  // 3) For each FB secondary: copy header + coinbases + toggle AuxPoW + fill AuxPoW fields
  for (size_t i = 0; i < nSec; ++i) {
    auto *fw = static_cast<FbWork*>(second[i]);
    // a) Copy FB header
    fbHeaders_[i] = fw->Header;
    // b) Move coinbase transactions
    fbLegacy_[i]  = std::move(fw->CBTxLegacy_);
    fbWitness_[i] = std::move(fw->CBTxWitness_);
    // c) Copy consensus context
    fbConsensusCtx_[i] = fw->ConsensusCtx_;
    // d) Set AuxPoW version bit
    fbHeaders_[i].nVersion |= FB::Proto::BlockHeader::VERSION_AUXPOW;
    // e) Build Merkle branch for child:
    fbHeaders_[i].MerkleBranch = fw->MerklePath;
    // f) Set index within Merkle tree
    fbHeaders_[i].Index = mmChainId[i];
    // g) For chain Merkle (FB under nothing), keep empty
    fbHeaders_[i].ChainMerkleBranch.clear();
    fbHeaders_[i].ChainIndex = 0;
    // h) Copy parent‐block coinbase Tx and hashBlock and parentBlock from fw->Header
    fbHeaders_[i].ParentBlockCoinbaseTx = fw->Header.ParentBlockCoinbaseTx;
    fbHeaders_[i].HashBlock             = fw->Header.HashBlock;
    fbHeaders_[i].ParentBlock           = fw->Header.ParentBlock;
  }

  // 4) Recompute primary BTCHeader_’s merkle root to include AuxPoW root:
  // Compute child root: take FBHeaders_[0].ParentBlock hash and its MerkleBranch
  uint256 childRoot = merkleTree::calculateRoot(
    (uint256&)fbHeaders_[0].HashBlock,
    fbHeaders_[0].MerkleBranch
  );
  // Convert to big-endian bytes, then reverse
  std::vector<uint8_t> rootBytes(32);
  childRoot.ToBytes(rootBytes.data());
  std::reverse(rootBytes.begin(), rootBytes.end());

  // 5) Prepend pchMergedMiningHeader + reversed childRoot into primary’s coinbase script
  xmstream cbStream;
  cbStream.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
  cbStream.write(rootBytes.data(), 32);
  // Append the rest of original primary coinbase
  xmstream origCb;
  BTCLegacy_.serialize(origCb);
  cbStream.write(origCb.data(), origCb.size());
  BTCLegacy_.deserialize(cbStream); // reset BTCLegacy_ to new script with AuxPoW

  // 6) Recompute BTCHeader_.hashMerkleRoot from modified coinbase:
  uint256 newRoot = merkleTree::calculateRoot(
    (uint256&)BTCHeader_.hashMerkleRoot,
    BTCMerklePath_
  );
  BTCHeader_.hashMerkleRoot = newRoot;
}

//==============================================================================
// shareHash: return the hash used for share validation for workIdx.
//==============================================================================
Proto::BlockHashTy Stratum::MergedWork::shareHash() {
  if (CurrentWork_ == 0) {
    // Primary BTC hash
    return btcWork()->getShareHash();
  } else {
    // FB secondary share: compute SHA256d over AuxPoW header?
    // In merged mining, shares are accepted against primary only. So return primary.
    return btcWork()->getShareHash();
  }
}

//==============================================================================
// blockHash: return the hex string of full block hash for workIdx.
//==============================================================================
std::string Stratum::MergedWork::blockHash(size_t workIdx) {
  if (workIdx == 0) {
    return btcWork()->blockHash();
  } else {
    // For FB secondary, return parentBlock hash (as hex)
    return fbHeaders_[workIdx - 1].ParentBlock.GetHash().GetHex();
  }
}

//==============================================================================
// mutate: randomize extra nonce. Delegate to BTC primary.
//==============================================================================
void Stratum::MergedWork::mutate() {
  btcWork()->mutate();
}

//==============================================================================
// buildNotifyMessage: build the Stratum “notify” JSON. Delegate to BTC primary.
//==============================================================================
void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork) {
  btcWork()->buildNotifyMessage(resetPreviousWork);
}

//==============================================================================
// prepareForSubmit: serialize primary then append “auxpow”:{…} JSON for FB children.
//==============================================================================
bool Stratum::MergedWork::prepareForSubmit(
    const CWorkerConfig &workerCfg,
    const CStratumMessage &msg
) {
  // 1) Serialize primary FB header (as BTC header) via Bitcoin’s WorkTy
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

  // 2) Append "auxpow":{ ... } for each FB secondary
  xmstream &stream = msg.getSubmitStream();
  stream.write(",\"auxpow\":[");
  for (size_t i = 0; i < fbHeaders_.size(); ++i) {
    stream.write("{");
    // parentblock
    stream.write("\"parentblock\":");
    serializeJSON(stream, fbHeaders_[i].ParentBlock);
    // merklebranch
    stream.write(",\"merklebranch\":[");
    for (size_t j = 0; j < fbHeaders_[i].MerkleBranch.size(); ++j) {
      serializeJSON(stream, fbHeaders_[i].MerkleBranch[j]);
      if (j + 1 < fbHeaders_[i].MerkleBranch.size()) stream.write(",");
    }
    stream.write("]");
    // index
    stream.write(",\"index\":"); stream.writeInt(fbHeaders_[i].Index);
    // chainmerklebranch
    stream.write(",\"chainmerklebranch\":[");
    for (size_t j = 0; j < fbHeaders_[i].ChainMerkleBranch.size(); ++j) {
      serializeJSON(stream, fbHeaders_[i].ChainMerkleBranch[j]);
      if (j + 1 < fbHeaders_[i].ChainMerkleBranch.size()) stream.write(",");
    }
    stream.write("]");
    // chainindex
    stream.write(",\"chainindex\":"); stream.writeInt(fbHeaders_[i].ChainIndex);
    // parentcoinbasetx
    stream.write(",\"parentcoinbasetx\":"); serializeJSON(stream, fbHeaders_[i].ParentBlockCoinbaseTx);
    // hashblock
    stream.write(",\"hashblock\":"); serializeJSON(stream, fbHeaders_[i].HashBlock);
    // close object
    stream.write("}");
    if (i + 1 < fbHeaders_.size()) stream.write(",");
  }
  stream.write("]");

  return true;
}

//==============================================================================
// buildBlock: for a given share, rebuild full block hex. Delegate to BTC primary.
//==============================================================================
void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
  if (workIdx == 0) {
    btcWork()->buildBlock(workIdx, blockHexData);
  } else {
    // FB share does not get submitted; only primary is submitted to GBT. Leave empty.
  }
}

//==============================================================================
// checkConsensus: verify PoW for this work index.
//==============================================================================
CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
  if (workIdx == 0) {
    return BTCConsensusCtx_.checkConsensus(BTCHeader_, BTCConsensusCtx_, fbChainParams_);
  } else {
    // Verify FB AuxPoW parent block
    return fbConsensusCtx_[workIdx - 1].status == CCheckStatus::OK
           ? CCheckStatus::OK
           : CCheckStatus::BLOCK_INVALID;
  }
}

} // namespace FB
