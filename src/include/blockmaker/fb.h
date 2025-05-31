// fract.h
#pragma once

#include "btc.h"
#include "poolinstances/stratumWorkStorage.h"
#include "poolcommon/arith_uint256.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

namespace FRACT {

class Proto {
public:
    static constexpr const char* TickerName = "FB";

    using BlockHashTy       = BTC::Proto::BlockHashTy;
    using TxHashTy          = BTC::Proto::TxHashTy;
    using AddressTy         = BTC::Proto::AddressTy;
    using PureBlockHeader   = BTC::Proto::BlockHeader;
    using Transaction       = BTC::Proto::Transaction;
    using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
    using ChainParams       = BTC::Proto::ChainParams;

    //
    // A "FB" block header is the same as a BTC header + AuxPoW‐fields.
    //
    struct BlockHeader : public PureBlockHeader {
        static const int32_t VERSION_AUXPOW = (1 << 8);

        // AuxPoW fields (exactly as in BTC‐AuxPoW):
        Transaction         ParentBlockCoinbaseTx;
        uint256             HashBlock;
        xvector<uint256>    MerkleBranch;
        int                 Index;
        xvector<uint256>    ChainMerkleBranch;
        int                 ChainIndex;
        PureBlockHeader     ParentBlock;
    };

    using Block = BTC::Proto::BlockTy<FRACT::Proto>;

    template<typename T>
    static inline void serialize(xmstream &dst, const T &data) {
        BTC::Io<T>::serialize(dst, data);
    }
    template<typename T>
    static inline void unserialize(xmstream &src, T &data) {
        BTC::Io<T>::unserialize(src, data);
    }

    //
    // Consensus functions:
    //
    static void checkConsensusInitialize(CheckConsensusCtx&) { /* no‐op */ }

    static CCheckStatus checkConsensus(
        const BlockHeader &header,
        CheckConsensusCtx  &ctx,
        ChainParams        &params
    ) {
        if (header.nVersion & Proto::BlockHeader::VERSION_AUXPOW) {
            // AuxPoW‐mode: verify the parent (BTC) block’s POW:
            return BTC::Proto::checkConsensus(header.ParentBlock, ctx, params);
        } else {
            // Standalone FB (pure SHA256) mode:
            return BTC::Proto::checkConsensus(header, ctx, params);
        }
    }

    static CCheckStatus checkConsensus(
        const Block       &block,
        CheckConsensusCtx &ctx,
        ChainParams       &params
    ) {
        return checkConsensus(block.header, ctx, params);
    }

    static double getDifficulty(const BlockHeader &header) {
        // Use BTC’s difficulty calculation; FB uses identical nBits interpretation.
        return BTC::difficultyFromBits(header.nBits, 29);
    }

    static double expectedWork(
        const BlockHeader       &header,
        const CheckConsensusCtx &ctx
    ) {
        return getDifficulty(header);
    }

    static bool decodeHumanReadableAddress(
        const std::string         &hrAddress,
        const std::vector<uint8_t> &pubkeyAddressPrefix,
        AddressTy                 &address
    ) {
        return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address);
    }
};

//
// Provide IO<> specialization so that FRACT::Proto::BlockHeader serializes just like AuxPoW in BTC.
//
namespace BTC {
template<>
struct Io<FRACT::Proto::BlockHeader> {
    static void serialize(xmstream &dst, const FRACT::Proto::BlockHeader &data);
    static void unserialize(xmstream &src, FRACT::Proto::BlockHeader &data);
};
} // namespace BTC

//
// A helper to render JSON for the FB header (for getblocktemplate responses, etc.)
//
void serializeJsonInside(xmstream &stream, const FRACT::Proto::BlockHeader &header);

namespace FRACT {

class Stratum {
public:
    static constexpr double DifficultyFactor = 65536.0;

    //
    // A “Work” object for FB—templated on Proto=FRACT::Proto and BTC’s header/coinbase builders.
    //
    using FractWork = BTC::WorkTy<
        FRACT::Proto,
        BTC::Stratum::HeaderBuilder,
        BTC::Stratum::CoinbaseBuilder,
        BTC::Stratum::Notify,
        BTC::Stratum::Prepare
    >;

    //
    // MergedWork: wraps one “primary” (BTC) work + many “secondary” (FB) works.
    //
    class MergedWork : public StratumMergedWork {
    public:
        MergedWork(
            uint64_t                          stratumWorkId,
            StratumSingleWork               *first,
            std::vector<StratumSingleWork*>  &second,
            std::vector<int>                 &mmChainId,
            uint32_t                          mmNonce,
            unsigned                          virtualHashesNum,
            const CMiningConfig              &miningCfg
        );

        virtual Proto::BlockHashTy shareHash() override;
        virtual std::string blockHash(size_t workIdx) override;
        virtual void mutate() override;
        virtual void buildNotifyMessage(bool resetPreviousWork) override;
        virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) override;
        virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override;
        virtual CCheckStatus checkConsensus(size_t workIdx) override;

    private:
        // Helpers to cast the StratumSingleWork at index 0 to BTC::Stratum::Work*:
        BTC::Stratum::Work* btcWork() {
            return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        }
        // For FB secondaries: index 'idx' in fractWork() corresponds to Works_[idx+1].Work
        FractWork* fractWork(unsigned idx) {
            return static_cast<FractWork*>(Works_[idx + 1].Work);
        }

        // “Primary” (BTC) header + meta:
        BTC::Proto::BlockHeader         BTCHeader_;
        BTC::CoinbaseTx                 BTCLegacy_;
        BTC::CoinbaseTx                 BTCWitness_;
        std::vector<uint256>            BTCMerklePath_;
        BTC::Proto::CheckConsensusCtx   BTCConsensusCtx_;

        // “Secondary” (FB) headers + meta:
        std::vector<FRACT::Proto::BlockHeader> fractHeaders_;
        std::vector<BTC::CoinbaseTx>           fractLegacy_;
        std::vector<BTC::CoinbaseTx>           fractWitness_;
        std::vector<uint256>                   fractHeaderHashes_;
        std::vector<int>                       fractWorkMap_;
        std::vector<FRACT::Proto::CheckConsensusCtx> fractConsensusCtx_;
        FRACT::Proto::ChainParams             fractChainParams_;

        CMiningConfig                         MiningCfg_;
    };

    //
    // Build a “chain map” for multiple FB secondaries:
    //  – identical logic to DOGE’s buildChainMap, except the cast inside uses FractWork.
    //
    static std::vector<int> buildChainMap(
        std::vector<StratumSingleWork*> &secondaries,
        uint32_t                       &nonce,
        unsigned                       &virtualHashesNum
    );

    static constexpr bool MergedMiningSupport = true;

    static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg, const char *in, size_t size) {
        return BTC::Stratum::decodeStratumMessage(msg, in, size);
    }
    static void miningConfigInitialize(CMiningConfig &miningCfg, rapidjson::Value &instanceCfg) {
        BTC::Stratum::miningConfigInitialize(miningCfg, instanceCfg);
    }
    static void workerConfigInitialize(CWorkerConfig &workerCfg, rapidjson::Value &threadCfg) {
        BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
    }
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
        BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }
    static void workerConfigOnSubscribe(
        CWorkerConfig     &workerCfg,
        CMiningConfig     &miningCfg,
        const CStratumMessage &msg,
        xmstream          &out,
        std::string       &subscribeInfo
    ) {
        BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
    }

    //
    // When FB is used as a standalone coin (no merged mining), this builds a single FB work:
    //
    static BTC::Stratum::Work* newPrimaryWork(
        int64_t                    stratumId,
        PoolBackend               *backend,
        size_t                     backendIdx,
        const CMiningConfig       &miningCfg,
        const std::vector<uint8_t> &miningAddress,
        const std::string         &coinbaseMessage,
        CBlockTemplate            &blockTemplate,
        std::string               &error
    );

    //
    // When FB appears as a “secondary” only (merged under a BTC primary), build a FractWork:
    //
    static FractWork* newSecondaryWork(
        int64_t                    stratumId,
        PoolBackend               *backend,
        size_t                     backendIdx,
        const CMiningConfig       &miningCfg,
        const std::vector<uint8_t> &miningAddress,
        const std::string         &coinbaseMessage,
        CBlockTemplate            &blockTemplate,
        std::string               &error
    );

    //
    // When PoolCore has both a BTC primary + one or more FB secondaries,
    // invoke this to build a MergedWork object:
    //
    static StratumMergedWork* newMergedWork(
        int64_t                       stratumId,
        StratumSingleWork           *first,
        std::vector<StratumSingleWork*> &second,
        const CMiningConfig          &miningCfg,
        std::string                  &error
    );
};

//
// Convenience alias “X” so other code can write FRACT::X::Proto / FRACT::X::Stratum
//
struct X {
    using Proto   = FRACT::Proto;
    using Stratum = FRACT::Stratum;

    template<typename T>
    static inline void serialize(xmstream &dst, const T &data) {
        BTC::Io<T>::serialize(dst, data);
    }
    template<typename T>
    static inline void unserialize(xmstream &src, T &data) {
        BTC::Io<T>::unserialize(src, data);
    }
};

} // namespace FRACT
