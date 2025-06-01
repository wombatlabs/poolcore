#include "blockmaker/frac.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"
#include "poolcommon/arith_uint256.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

namespace FRAC {

//////////////////////////
// 1) buildChainMap(...) – identical to DOGE’s implementation (adjusted for FRAC)
// ─── FRAC::Stratum::buildChainMap ─────────────────────────────────────────────
std::vector<int> Stratum::buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                        uint32_t &nonce,
                                        unsigned &virtualHashesNum)
{
    // RESULT must have one entry per secondary work
    std::vector<int> result(secondary.size());

    // If there is only one secondary, pathSize starts at 0; otherwise compute the minimum:
    unsigned minPathSize = (secondary.size() > 1)
                           ? (31 - __builtin_clz((secondary.size() << 1) - 1))
                           : 0;

    // Try pathSize from minPathSize up to 7 (i.e. up to 128 leaves max)
    for (unsigned pathSize = minPathSize; pathSize < 8; pathSize++) {
        virtualHashesNum = (1u << pathSize);
        // Create a fresh map of length virtualHashesNum, initialized to 0:
        std::vector<int> chainMap(virtualHashesNum, 0);

        bool foundCollisionFree = true;
        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            foundCollisionFree = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            // Attempt to assign each secondary a distinct leaf index
            for (size_t i = 0; i < secondary.size(); i++) {
                auto *work = static_cast<Stratum::FracWork*>(secondary[i]);
                // Extract FRAC’s “chain ID” from the high 16 bits of nVersion:
                uint32_t chainId = (work->Header.nVersion >> 16);

                // Pseudorandom index in [0, virtualHashesNum)
                uint32_t randv = nonce;
                randv = randv * 1103515245 + 12345;
                randv += chainId;
                randv = randv * 1103515245 + 12345;
                uint32_t idx = randv & (virtualHashesNum - 1);  // same as % virtualHashesNum

                if (chainMap[idx] == 0) {
                    chainMap[idx] = 1;
                    result[i] = idx;
                } else {
                    foundCollisionFree = false;
                    break;
                }
            }

            if (foundCollisionFree) {
                // We found a nonce that places every secondary into a unique leaf
                break;
            }
        }

        if (foundCollisionFree) {
            // SUCCESS ➔ return exactly one entry per secondary (e.g. {0} if size==1)
            return result;
        }
        // Otherwise, increase pathSize (and virtualHashesNum doubles) and try again
    }

    // If no collision-free assignment found up to pathSize=7, return empty
    return std::vector<int>();
}

//////////////////////////
// 2) checkConsensusInitialize & checkConsensus – parallel to DOGE but calling BTC
void Proto::checkConsensusInitialize(CheckConsensusCtx &ctx) {
    // nothing to do
}

CCheckStatus Proto::checkConsensus(const Proto::BlockHeader &header,
                                   CheckConsensusCtx &ctx,
                                   Proto::ChainParams &chainParams)
{
    if (header.nVersion & BlockHeader::VERSION_AUXPOW) {
        return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
    } else {
        return BTC::Proto::checkConsensus(header, ctx, chainParams);
    }
}

CCheckStatus Proto::checkConsensus(const Proto::Block &block,
                                   CheckConsensusCtx &ctx,
                                   Proto::ChainParams &chainParams)
{
    return checkConsensus(block.header, ctx, chainParams);
}

//////////////////////////
// 3) newPrimaryWork / newSecondaryWork
Stratum::FracWork* Stratum::newPrimaryWork(int64_t stratumId,
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
    auto *work = new Stratum::FracWork(stratumId,
                                       blockTemplate.UniqueWorkId,
                                       backend,
                                       backendIdx,
                                       miningCfg,
                                       miningAddress,
                                       coinbaseMessage);
    return work->loadFromTemplate(blockTemplate, error) ? work
                                                        : (void(delete work), nullptr);
}

StratumSingleWork* Stratum::newSecondaryWork(int64_t stratumId,
                                            PoolBackend* backend,
                                            size_t backendIdx,
                                            const CMiningConfig& miningCfg,
                                            const std::vector<uint8_t>& miningAddress,
                                            const std::string& coinbaseMessage,
                                            CBlockTemplate& blockTemplate,
                                            std::string& error)
{
    // FRAC’s block templates will always be SHA-256 work:
    if (blockTemplate.WorkType != EWorkBitcoin) {
        error = "incompatible work type for FRAC secondary";
        return nullptr;
    }

    // Exactly the same as newPrimaryWork(): construct a FracWork,
    // load it from the template, and return it (or delete+fail).
    auto* work = new Stratum::FracWork(
        stratumId,
        blockTemplate.UniqueWorkId,
        backend,
        backendIdx,
        miningCfg,
        miningAddress,
        coinbaseMessage
    );
    if (!work->loadFromTemplate(blockTemplate, error)) {
        delete work;
        return nullptr;
    }
    return work;
}

//////////////////////////
// 4) MergedWork constructor  virtual overrides
// ─── FRAC::Stratum::MergedWork::MergedWork ────────────────────────────────────
// ─── FRAC::Stratum::MergedWork::MergedWork ────────────────────────────────────
Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                StratumSingleWork *first,
                                std::vector<StratumSingleWork*> &second,
                                std::vector<int> &mmChainId,
                                uint32_t mmNonce,
                                unsigned virtualHashesNum,
                                const CMiningConfig &miningCfg)
  : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // 1) Copy the primary (BTC-like) fields from the “first” work:
    BaseHeader_       = baseWork()->Header;
    BaseMerklePath_   = baseWork()->MerklePath;
    BaseConsensusCtx_ = baseWork()->ConsensusCtx_;

    // 2) Each secondary → one FRAC header slot:
    FRACHeaders_.resize(second.size());
    FRACLegacy_.resize(second.size());
    FRACWitness_.resize(second.size());

    // 3) We need exactly virtualHashesNum leaves for mm‐merkle:
    FRACHeaderHashes_.resize(virtualHashesNum, uint256());

    // 4) Copy the “chainMap” indices (length == second.size())
    FRACWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 5) Build each FRAC sub‐header in order:
    for (size_t i = 0; i < FRACHeaders_.size(); i++) {
        auto *fw = static_cast<Stratum::FracWork*>(second[i]);

        // 5.1) Copy the template header:
        FRACHeaders_[i] = fw->Header;

        // 5.2) Build a static FRAC coinbase (no extra‐nonce) to calculate Merkle:
        CMiningConfig dummyExtra{};
        dummyExtra.FixedExtraNonceSize   = 0;
        dummyExtra.MutableExtraNonceSize = 0;
        fw->buildCoinbaseTx(nullptr, 0, dummyExtra, FRACLegacy_[i], FRACWitness_[i]);

        // 5.3) Flip on the AuxPoW version bit:
        FRACHeaders_[i].nVersion |= FRAC::Proto::BlockHeader::VERSION_AUXPOW;

        // 5.4) Compute that FRAC header’s Merkle root from its coinbase:
        uint256 coinbaseHash;
        {
            CCtxSha256 sha;
            sha256Init(&sha);
            sha256Update(&sha,
                        FRACLegacy_[i].Data.data(),
                        FRACLegacy_[i].Data.sizeOf());
            sha256Final(&sha, coinbaseHash.begin());

            // If there is a witness, hash it again
            sha256Init(&sha);
            sha256Update(&sha, coinbaseHash.begin(), coinbaseHash.size());
            sha256Final(&sha, coinbaseHash.begin());
        }
        FRACHeaders_[i].hashMerkleRoot = calculateMerkleRootWithPath(
            coinbaseHash,
            fw->MerklePath.data(),
            fw->MerklePath.size(),
            0
        );

        // 5.5) Place this sub‐header’s hash at the correct leaf:
        size_t leafIdx = static_cast<size_t>(FRACWorkMap_[i]);
        FRACHeaderHashes_[leafIdx] = FRACHeaders_[i].GetHash();
    }

    // 6) Build the merged‐mining chain Merkle root:
    uint256 chainRoot = calculateMerkleRoot(FRACHeaderHashes_.data(),
                                            FRACHeaderHashes_.size());
    std::reverse(chainRoot.begin(), chainRoot.end());

    // 7) Prepend “mm” magic + chainRoot + virtualHashesNum + mmNonce to coinbase:
    uint8_t buffer[1024];
    xmstream mmPayload(buffer, sizeof(buffer));
    mmPayload.reset();
    static const unsigned char pchMergedMiningHeader[] = { 0xFA, 0xBE, 'm', 'm' };
    mmPayload.write(pchMergedMiningHeader, sizeof(pchMergedMiningHeader));
    mmPayload.write(chainRoot.begin(), chainRoot.size());
    mmPayload.write<uint32_t>(virtualHashesNum);
    mmPayload.write<uint32_t>(mmNonce);

    // 8) Finally, rebuild the primary (BTC) coinbase by prefixing that “mmPayload”:
    baseWork()->buildCoinbaseTx(
      mmPayload.data(),
      mmPayload.sizeOf(),
      miningCfg,
      BaseLegacy_,
      BaseWitness_
    );
}

FRAC::Proto::BlockHashTy Stratum::MergedWork::shareHash() {
    return baseWork()->Header.GetHash();
}

std::string Stratum::MergedWork::blockHash(size_t workIdx) {
    if (workIdx == 0) {
        return baseWork()->Header.GetHash().ToString();
    } else if (workIdx - 1 < FRACHeaders_.size()) {
        return FRACHeaders_[workIdx - 1].GetHash().ToString();
    } else {
        return std::string();
    }
}

void Stratum::MergedWork::mutate() {
    BaseHeader_.nTime = static_cast<uint32_t>(time(nullptr));
    BTC::Stratum::Work::buildNotifyMessageImpl(
        this,
        BaseHeader_,
        BaseHeader_.nVersion,
        BaseLegacy_,
        BaseMerklePath_,
        MiningCfg_,
        true,
        NotifyMessage_
    );
}

void Stratum::MergedWork::buildNotifyMessage(bool resetPreviousWork) {
    BTC::Stratum::Work::buildNotifyMessageImpl(
        this,
        BaseHeader_,
        BaseHeader_.nVersion,
        BaseLegacy_,
        BaseMerklePath_,
        MiningCfg_,
        resetPreviousWork,
        NotifyMessage_
    );
}

bool Stratum::MergedWork::prepareForSubmit(const CWorkerConfig &workerCfg,
                                           const CStratumMessage &msg)
{
    if (! BTC::Stratum::Work::prepareForSubmitImpl(
              BaseHeader_,
              BaseHeader_.nVersion,
              BaseLegacy_,
              BaseWitness_,
              BaseMerklePath_,
              workerCfg,
              MiningCfg_,
              msg
          )) {
        return false;
    }

    for (size_t i = 0; i < FRACHeaders_.size(); i) {
        CCheckStatus st = FRAC::Stratum::FracWork::checkConsensusImpl(
                             FRACHeaders_[i],
                             FRACConsensusCtx_
                         );
        if (!st.IsBlock) {
            return false;
        }
    }
    return true;
}

void Stratum::MergedWork::buildBlock(size_t workIdx, xmstream &blockHexData) {
    if (workIdx == 0 && baseWork()) {
        baseWork()->buildBlockImpl(BaseHeader_, BaseWitness_, blockHexData);
    } else {
        auto *fw = fracWork(workIdx - 1);
        if (fw) {
            fw->buildBlockImpl(
                FRACHeaders_[workIdx - 1],
                FRACWitness_[workIdx - 1],
                blockHexData
            );
        }
    }
}

CCheckStatus Stratum::MergedWork::checkConsensus(size_t workIdx) {
    if (workIdx == 0 && baseWork()) {
        return BTC::Stratum::Work::checkConsensusImpl(BaseHeader_, BaseConsensusCtx_);
    } else {
        auto *fw = fracWork(workIdx - 1);
        if (fw) {
            return FRAC::Stratum::FracWork::checkConsensusImpl(
                       FRACHeaders_[workIdx - 1],
                       BaseConsensusCtx_
                   );
        }
    }
    return CCheckStatus();
}

//
// 5) newMergedWork / miningConfigInitialize / workerConfigInitialize (already in header)
//    – no further definitions needed here in the cpp because they’re static inline.
//

} // namespace FRAC

//
// ─── EXPLICIT Io<T> SPECIALIZATION FOR FRAC::Proto::BlockHeader ─────────────
//
namespace BTC {

template<>
inline void Io<FRAC::Proto::BlockHeader>::serialize(xmstream &s, const FRAC::Proto::BlockHeader &h)
{
    // 1) Serialize the six-field “pure” header exactly as BTC does:
    Io<FRAC::Proto::PureBlockHeader>::serialize(s, h);

    // 2) Then serialize all the AuxPoW fields in FRAC’s BlockHeader:
    Io<FRAC::Proto::Transaction>::serialize(s, h.ParentBlockCoinbaseTx);
    Io<uint256>::serialize(s, h.HashBlock);
    Io<xvector<uint256>>::serialize(s, h.MerkleBranch);
    Io<int>::serialize(s, h.Index);
    Io<xvector<uint256>>::serialize(s, h.ChainMerkleBranch);
    Io<int>::serialize(s, h.ChainIndex);
    Io<FRAC::Proto::PureBlockHeader>::serialize(s, h.ParentBlock);
}

} // namespace BTC
