#pragma once

#include "blockmaker/btc.h"
#include "poolinstances/stratumWorkStorage.h"

namespace FRAC {

//
// ─── PROTO ────────────────────────────────────────────────────────────────────
//
class Proto {
public:
    static constexpr const char *TickerName = "FRAC";

    //
    // FRAC is a SHA-256 fork of Bitcoin, so we reuse BTC::Proto types:
    //
    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using AddressTy   = BTC::Proto::AddressTy;

    // The “pure” header for FRAC is identical to BTC’s:
    using PureBlockHeader = BTC::Proto::BlockHeader;

    // Reuse BTC’s transaction types:
    using TxIn        = BTC::Proto::TxIn;
    using TxOut       = BTC::Proto::TxOut;
    using TxWitness   = BTC::Proto::TxWitness;
    using Transaction = BTC::Proto::Transaction;

    //
    // ─── BLOCKHEADER ──────────────────────────────────────────────────────────────
    //
    struct BlockHeader : public PureBlockHeader {
        static const int32_t VERSION_AUXPOW = (1 << 8);

        // AuxPoW fields (exactly parallel to DOGE’s layout):
        Transaction                      ParentBlockCoinbaseTx;
        uint256                          HashBlock;
        xvector<uint256>                 MerkleBranch;
        int                              Index;
        xvector<uint256>                 ChainMerkleBranch;
        int                              ChainIndex;
        PureBlockHeader                  ParentBlock;
    };

    using Block          = BTC::Proto::BlockTy<FRAC::Proto>;
    using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
    using ChainParams      = BTC::Proto::ChainParams;

    //
    // Initialize any consensus-related context (no extra state for FRAC):
    //
    static void checkConsensusInitialize(CheckConsensusCtx &ctx) {}

    //
    // If the VERSION_AUXPOW bit is set, we verify the ParentBlock (sha256 PoW)
    // via BTC::Proto::checkConsensus. Otherwise, treat as a plain header.
    //
    static CCheckStatus checkConsensus(const Proto::BlockHeader &header,
                                       CheckConsensusCtx &ctx,
                                       Proto::ChainParams &chainParams)
    {
        if (header.nVersion & Proto::BlockHeader::VERSION_AUXPOW) {
            // AuxPoW: validate parent-block’s PoW under BTC rules
            return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
        } else {
            // No AuxPoW: validate this header directly as a SHA-256 header
            return BTC::Proto::checkConsensus(header, ctx, chainParams);
        }
    }

    static CCheckStatus checkConsensus(const Proto::Block &block,
                                       CheckConsensusCtx &ctx,
                                       Proto::ChainParams &chainParams)
    {
        return checkConsensus(block.header, ctx, chainParams);
    }

    //
    // Difficulty and expectedWork are identical to BTC’s:
    //
    static double getDifficulty(const Proto::BlockHeader &header) {
        return BTC::difficultyFromBits(header.nBits, 29);
    }
    static double expectedWork(const Proto::BlockHeader &header,
                               const CheckConsensusCtx &ctx)
    {
        return getDifficulty(header);
    }

    //
    // Decode Base58 (or Bech32) addresses using BTC’s helper:
    //
    static bool decodeHumanReadableAddress(const std::string &hrAddress,
                                           const std::vector<uint8_t> &pubkeyAddressPrefix,
                                           AddressTy &address)
    {
        return BTC::Proto::decodeHumanReadableAddress(hrAddress,
                                                      pubkeyAddressPrefix,
                                                      address);
    }
};

//
// ─── STRATUM ──────────────────────────────────────────────────────────────────
//
class Stratum {
public:
    // FRAC uses the same “DifficultyFactor” as BTC:
    static constexpr double DifficultyFactor = 1.0;

    //
    // WorkTy: reuse BTC’s Stratum work pipeline (HeaderBuilder, CoinbaseBuilder, etc.)
    //
    using FracWork = BTC::WorkTy< FRAC::Proto,
                                  BTC::Stratum::HeaderBuilder,
                                  BTC::Stratum::CoinbaseBuilder,
                                  BTC::Stratum::Notify,
                                  BTC::Stratum::Prepare >;

    //
    // Enable AuxPoW / merged-mining support:
    //
    static constexpr bool MergedMiningSupport = true;

    //
    // ─── PRIMARY / SECONDARY WORK ────────────────────────────────────────────────
    //
    // Called when a new block template arrives for FRAC-as-standalone (primary):
    //
    static FracWork* newPrimaryWork(int64_t stratumId,
                                    PoolBackend *backend,
                                    size_t backendIdx,
                                    const CMiningConfig &miningCfg,
                                    const std::vector<uint8_t> &miningAddress,
                                    const std::string &coinbaseMessage,
                                    CBlockTemplate &blockTemplate,
                                    std::string &error);

    //
    // This would be invoked if FRAC were used as a “secondary” on its own port.
    // We can leave it unimplemented (PoolCore won’t call it if you treat FRAC exclusively as aux-pow):
    //
    static StratumSingleWork* newSecondaryWork(int64_t stratumId,
                                               PoolBackend *backend,
                                               size_t backendIdx,
                                               const CMiningConfig &miningCfg,
                                               const std::vector<uint8_t> &miningAddress,
                                               const std::string &coinbaseMessage,
                                               CBlockTemplate &blockTemplate,
                                               std::string &error);

    //
    // ─── MERGEDWORK CLASS ───────────────────────────────────────────────────────
    // Implements a single “merged mining” job: primary (e.g. BTC) + one or more FRAC sub-headers
    //
    class MergedWork : public StratumMergedWork {
    public:
        MergedWork(uint64_t stratumWorkId,
                   StratumSingleWork *first,
                   std::vector<StratumSingleWork*> &second,
                   std::vector<int> &mmChainId,
                   uint32_t mmNonce,
                   unsigned virtualHashesNum,
                   const CMiningConfig &miningCfg);

        // Return the hash that miners must target (primary header’s hash):
        virtual Proto::BlockHashTy shareHash() override;

        // Return block-hash for a given work index (0 = primary, ≥1 = FRAC sub-header):
        virtual std::string blockHash(size_t workIdx) override;

        // Called when the daemon asks to update “nTime”:
        virtual void mutate() override;

        // Rebuild the “mining.notify” JSON with the updated header/coinbase:
        virtual void buildNotifyMessage(bool resetPreviousWork) override;

        // On share submission: first check primary PoW, then each FRAC aux-PoW branch:
        virtual bool prepareForSubmit(const CWorkerConfig &workerCfg,
                                      const CStratumMessage &msg) override;

        // Build the final block blob for this index (0=primary, ≥1=FRAC):
        virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override;

        // Consensus check at submit-time:
        virtual CCheckStatus checkConsensus(size_t workIdx) override;

    private:
        // Helpers to cast “Works_[i].Work” to the correct type:
        BTC::Stratum::Work* baseWork() {
            return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        }
        FRAC::Stratum::FracWork* fracWork(unsigned index) {
            return static_cast<FRAC::Stratum::FracWork*>(Works_[index + 1].Work);
        }

    private:
        // Primary (BTC-like) header + coinbase + merkle path + consensus context
        BTC::Proto::BlockHeader          BaseHeader_;
        BTC::CoinbaseTx                  BaseLegacy_;
        BTC::CoinbaseTx                  BaseWitness_;
        std::vector<uint256>             BaseMerklePath_;
        BTC::Proto::CheckConsensusCtx    BaseConsensusCtx_;

        // FRAC sub-headers & coinbases for each aux-pow work
        std::vector<FRAC::Proto::BlockHeader> FRACHeaders_;
        std::vector<BTC::CoinbaseTx>           FRACLegacy_;
        std::vector<BTC::CoinbaseTx>           FRACWitness_;
        std::vector<uint256>                   FRACHeaderHashes_;
        std::vector<int>                       FRACWorkMap_;
        FRAC::Proto::CheckConsensusCtx         FRACConsensusCtx_;
    };

    //
    // ─── buildChainMap(...) ──────────────────────────────────────────────────────
    // Given N FRAC secondary works, find an mm-nonce and a placement index so that
    // each FRAC sub-header occupies a unique leaf in the “mm” merkle tree.
    //
    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                          uint32_t &nonce,
                                          unsigned &virtualHashesNum);

    //
    // ─── STATIC: miningConfigInitialize ───────────────────────────────────────────
    // PoolCore’s StratumInstance<X> always calls X::Stratum::miningConfigInitialize(...)
    //
    static void miningConfigInitialize(CMiningConfig &miningCfg, rapidjson::Value &config) {
        // Forward to BTC::Stratum’s initializer (FRAC has no extra JSON fields here)
        BTC::Stratum::miningConfigInitialize(miningCfg, config);
    }

    //
    // ─── STATIC: newMergedWork ────────────────────────────────────────────────────
    // PoolCore’s StratumWorkStorage<X>::createWork(...) will call X::Stratum::newMergedWork(...)
    //
    static StratumMergedWork* newMergedWork(int64_t stratumId,
                                            StratumSingleWork *primaryWork,
                                            std::vector<StratumSingleWork*> &secondaryWorks,
                                            const CMiningConfig &miningCfg,
                                            std::string &error)
    {
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

        return new MergedWork(stratumId,
                              primaryWork,
                              secondaryWorks,
                              chainMap,
                              nonce,
                              virtualHashesNum,
                              miningCfg);
    }
};

//
// ─── FRAC::X ──────────────────────────────────────────────────────────────────
// Tells PoolCore how to wire up Proto and Stratum, plus serialize/deserialize
//
struct X {
    using Proto   = FRAC::Proto;
    using Stratum = FRAC::Stratum;

    // All low-level (de)serialization is handled by BTC::Io<T>
    template<typename T>
    static inline void serialize(xmstream &src, const T &data) {
        BTC::Io<T>::serialize(src, data);
    }
    template<typename T>
    static inline void deserialize(xmstream &src, T &data) {
        BTC::Io<T>::deserialize(src, data);
    }
};

} // namespace FRAC
