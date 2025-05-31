// fb.h
#pragma once

#include "btc.h"
#include "poolinstances/stratumWorkStorage.h"    // defines StratumSingleWork, ThreadConfig, CStratumMessage, etc.
#include "poolcommon/arith_uint256.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

namespace FB {

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

    using Block = BTC::Proto::BlockTy<FB::Proto>;

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
        const CheckConsensusCtx & /*ctx*/    // ctx is not used here, but must be in signature
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

} // namespace FB

//
// Provide IO<> specialization so that FB::Proto::BlockHeader serializes just like AuxPoW in BTC.
//
namespace BTC {
template<>
struct Io<FB::Proto::BlockHeader> {
    static void serialize(xmstream &dst, const FB::Proto::BlockHeader &data);
    static void unserialize(xmstream &src, FB::Proto::BlockHeader &data);
};
} // namespace BTC

//
// A helper to render JSON for the FB header (for getblocktemplate responses, etc.)
//
void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header);

namespace FB {

class Stratum {
public:
    static constexpr double DifficultyFactor = 65536.0;

    //
    // A “Work” object for FB—templated on Proto=FB::Proto and BTC’s header/coinbase builders.
    //
    using FbWork = BTC::WorkTy<
        FB::Proto,
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

        //
        // ←── **FIX #1** ── Match base signature: second parameter must be `const CStratumMessage &`
        //
        virtual bool prepareForSubmit(const CWorkerConfig &workerCfg,
                                      const CStratumMessage &msg) override;

        virtual void buildBlock(size_t workIdx, xmstream &blockHexData) override;
        virtual CCheckStatus checkConsensus(size_t workIdx) override;

    private:
        // Helpers to cast the StratumSingleWork at index 0 to BTC::Stratum::Work*:
        BTC::Stratum::Work* btcWork() {
            return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        }
        // For FB secondaries: index 'idx' in fbWork() corresponds to Works_[idx+1].Work
        FbWork* fbWork(unsigned idx) {
            return static_cast<FbWork*>(Works_[idx + 1].Work);
        }

        // “Primary” (BTC) header + meta:
        BTC::Proto::BlockHeader         BTCHeader_;
        BTC::CoinbaseTx                 BTCLegacy_;
        BTC::CoinbaseTx                 BTCWitness_;
        std::vector<uint256>            BTCMerklePath_;
        BTC::Proto::CheckConsensusCtx   BTCConsensusCtx_;

        // “Secondary” (FB) headers + meta:
        std::vector<FB::Proto::BlockHeader> fbHeaders_;
        std::vector<BTC::CoinbaseTx>        fbLegacy_;
        std::vector<BTC::CoinbaseTx>        fbWitness_;
        std::vector<uint256>                fbHeaderHashes_;
        std::vector<int>                    fbWorkMap_;
        std::vector<FB::Proto::CheckConsensusCtx> fbConsensusCtx_;
        FB::Proto::ChainParams             fbChainParams_;

        CMiningConfig                       MiningCfg_;
    };

    //
    // Build a “chain map” for multiple FB secondaries:
    //  – identical logic to DOGE’s buildChainMap, except the cast inside uses FbWork.
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

    //
    // ←── **FIX #2** ── Must accept `ThreadConfig &` (not rapidjson::Value&) to match BTC::Stratum
    //
    static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) {
        BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
    }

    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg, uint32_t versionMask) {
        BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }

    //
    // ←── **FIX #3** ── Must accept `CStratumMessage &` (non-const) to match BTC::Stratum
    //
    static void workerConfigOnSubscribe(
        CWorkerConfig     &workerCfg,
        CMiningConfig     &miningCfg,
        CStratumMessage   &msg,
        xmstream          &out,
        std::string       &subscribeInfo
    ) {
        BTC::Stratum::workerConfigOnSubscribe(workerCfg, miningCfg, msg, out, subscribeInfo);
    }

    //
    // Builds (Stratum) “set_target” message. PoolCore’s generic code will call this.
    // Doge implements it by delegating to BTC::Stratum::buildSendTargetMessage.
    // We must do the same, otherwise `stratumSendTarget(...)` will not compile.
    //
    static void buildSendTargetMessage(xmstream &stream, double shareDiff) {
        BTC::Stratum::buildSendTargetMessage(stream, shareDiff);
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
    // When FB appears as a “secondary” only (merged under a BTC primary), build a FbWork:
    //
    static FbWork* newSecondaryWork(
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
// Convenience alias “X” so other code can write FB::X::Proto and FB::X::Stratum
//
struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;

    template<typename T>
    static inline void serialize(xmstream &dst, const T &data) {
        BTC::Io<T>::serialize(dst, data);
    }
    template<typename T>
    static inline void unserialize(xmstream &src, T &data) {
        BTC::Io<T>::unserialize(src, data);
    }
};

} // namespace FB
