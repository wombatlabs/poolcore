#pragma once

#include "blockmaker/btc.h"             // bring in BTC-core types (Proto::BlockHeader, WorkTy<…>, etc.)
#include "blockmaker/stratumMsg.h"
#include "blockmaker/poolcommon/jsonSerializer.h"
#include "blockmaker/serializeJson.h"
#include "blockmaker/merkleTree.h"
#include <vector>
#include <string>
#include <cstdint>

namespace FB {

//
// FB::Proto
// ---------
// We assume that there is a Protobuf-generated header somewhere that defines
// FB::Proto::BlockHeader, FB::Proto::PureBlockHeader, FB::Proto::CheckConsensusCtx, etc.
// If your code already has “FB/proto/blockheader.pb.h” or similar, include it instead.
// Here we merely forward-declare the shapes that doge.h would expect.
//
namespace Proto {
    //
    // A “pure” BlockHeader (fields shared with BTC::Proto::BlockHeader).
    // NOTE: Doge/LTC used a “PureBlockHeader = LTC::Proto::BlockHeader” alias.
    // For FB, we want:
    //   using PureBlockHeader = BTC::Proto::BlockHeader;
    //
    using PureBlockHeader     = BTC::Proto::BlockHeader;
    using CheckConsensusCtx   = BTC::Proto::CheckConsensusCtx;
    using Transaction         = BTC::Proto::Transaction;
    using AddressTy           = BTC::Proto::AddressTy; // if you decode addresses in stratum

    struct BlockHeader {
        uint32_t             nVersion;
        uint256              hashPrevBlock;
        uint256              hashMerkleRoot;
        uint32_t             nTime;
        uint32_t             nBits;
        uint32_t             nNonce;

        // AuxPOW fields (only valid if nVersion has VERSION_AUXPOW bit set):
        Transaction          ParentBlockCoinbaseTx;   // the parent (FB) coinbase tx
        uint256              HashBlock;               // FB’s header hash
        std::vector<uint256> MerkleBranch;            // FB’s Merkle path for this share
        uint32_t             Index;                   // FB’s coinbase tx index in that merkle path

        std::vector<uint256> ChainMerkleBranch;       // Merkle path in the FB‐header‐set
        uint32_t             ChainIndex;              // which position in the FB merkle tree
        PureBlockHeader      ParentBlock;             // this is just a copy of the BTC parent‐header

        // The Doge/LTC code used VERSION_AUXPOW = (1 << 8). For FB, pick the same constant:
        static constexpr uint32_t VERSION_AUXPOW = (1 << 8);

        uint256 GetHash() const;   // Protobuf will have a GetHash() if you generated it. If not, implement it.
    };
} // namespace Proto

//
// FB::Stratum
// ------------
// Mirrors the structure of DOGE::Stratum but replaces “DogeWork”→“FbWork”,
// “LTC”→“BTC”, etc.
//
namespace Stratum {

    // Work alias: exactly like Doge did, but using BTC::WorkTy<FB::Proto,…>
    using Work = BTC::WorkTy<
        FB::Proto,
        BTC::Stratum::HeaderBuilder,
        BTC::Stratum::CoinbaseBuilder,
        BTC::Stratum::Notify,
        BTC::Stratum::Prepare
    >;

    // “FbWork” is just a named alias for Work. Doge called it “DogeWork”:
    using FbWork = Work;

    //
    // Stratum class itself:
    //
    class Stratum {
    public:
        //
        // (1) Helpers to cast the generic StratumSingleWork* pointers to BTC::Work* or FB::Work*.
        //     Doge did this:
        //
        //       LTC::Stratum::Work *ltcWork()   { return static_cast<LTC::Stratum::Work*>(Works_[0].Work); }
        //       DOGE::Stratum::DogeWork *dogeWork(unsigned i) { return static_cast<DOGE::Stratum::DogeWork*>(Works_[i+1].Work); }
        //
        //     We do the same:
        //
        BTC::Stratum::Work*       btcWork() { return static_cast<BTC::Stratum::Work*>(Works_[0].Work); }
        FB::Stratum::FbWork*      fbWork(unsigned index) { return static_cast<FB::Stratum::FbWork*>(Works_[index+1].Work); }

        //
        // (2) buildChainMap
        //     Exactly the same signature Doge used:
        //
        static std::vector<int>
        buildChainMap(std::vector<StratumSingleWork*>& secondary,
                      uint32_t& nonce,
                      unsigned& virtualHashesNum
        );

        // Indicate that FB supports merged mining:
        static constexpr bool MergedMiningSupport = true;

        //
        // (3) Config initialization hooks (copied from Doge::Stratum):
        //     Doge.h defined these two static methods so that
        //     StratumInstance<FB::X> can call them at startup.
        //
        static void miningConfigInitialize(CMiningConfig &cfg, const rapidjson::Value &json);
        static void workerConfigInitialize(CWorkerConfig &cfg, const rapidjson::Value &json);

        //
        // (4) The nested MergedWork subclass:
        //
        class MergedWork : public StratumMergedWork {
        public:
            MergedWork(
                uint64_t                       stratumWorkId,
                StratumSingleWork*             first,
                std::vector<StratumSingleWork*>& second,
                std::vector<int>&              mmChainId,
                uint32_t                       mmNonce,
                unsigned                       virtualHashesNum,
                const CMiningConfig &          miningCfg
            );

            bool prepareForSubmit(const CWorkerConfig &workerCfg,
                                  const CStratumMessage &msg
            ) override;

            //
            // (a) The BTC (“parent”)‐chain fields:
            //
            BTC::Proto::BlockHeader          BTCHeader_;
            std::vector<uint256>             BTCMerklePath_;
            BTC::Proto::CheckConsensusCtx    BTCConsensusCtx_;
            BTC::CoinbaseTx                  BTCLegacy_;
            BTC::CoinbaseTx                  BTCWitness_;

            //
            // (b) The FB (“aux”)‐chain fields, one per secondary Work:
            //
            std::vector<FB::Proto::BlockHeader> fbHeaders_;
            std::vector<BTC::CoinbaseTx>         fbLegacy_;
            std::vector<BTC::CoinbaseTx>         fbWitness_;
            std::vector<uint256>                 fbHeaderHashes_;
            std::vector<int>                     fbWorkMap_;
            FB::Proto::CheckConsensusCtx         fbConsensusCtx_;
        };

        //
        // (5) “expectedWork” (copied from Doge/LTC):
        //
        static double expectedWork(const Proto::BlockHeader &header,
                                   const Proto::CheckConsensusCtx &ctx
        );

        //
        // (6) “buildNotifyMessage” (copied from Doge/LTC, except DOGE→FB):
        //
        static void buildNotifyMessage(xmstream                   &stream,
                                       const Proto::BlockHeader    &header,
                                       uint32_t                     coinbaseSize,
                                       int                         &extraNonce,
                                       const std::vector<base_blob<256>> &merkleBranch,
                                       const CMiningConfig         &miningCfg,
                                       bool                         segwitEnabled,
                                       xmstream                   &targetOut
        );

        //
        // (7) “buildSendTargetMessage” (copied from Doge/LTC):
        //
        static void buildSendTargetMessage(xmstream &stream, double shareDiff);

        //
        // (8) Factory methods for new Work objects:
        //     Doge.h declared these as “static DogeWork* newPrimaryWork(…)” and “newSecondaryWork(…)”.
        //     We do exactly the same, but return a “Work*” pointer.
        //
        static Work*
        newPrimaryWork(int64_t                    stratumId,
                       PoolBackend               *backend,
                       size_t                      backendIdx,
                       const CMiningConfig       &miningCfg,
                       const std::vector<uint8_t> &miningAddress,
                       const std::string         &coinbaseMessage,
                       CBlockTemplate            &blockTemplate,
                       std::string               &error
        );

        static Work*
        newSecondaryWork(int64_t                    stratumId,
                         PoolBackend               *backend,
                         size_t                      backendIdx,
                         const CMiningConfig       &miningCfg,
                         const std::vector<uint8_t> &miningAddress,
                         const std::string         &coinbaseMessage,
                         CBlockTemplate            &blockTemplate,
                         std::string               &error
        );

    private:
        // The array of underlying StratumSingleWork pointers (inherited from StratumMergedWork).
        // Doge/LTC code assumed something like StratumSingleWork* Works_[…].
        // You do not need to re-declare it here; it is inherited from StratumMergedWork.
        //
        // std::vector<StratumSingleWork*> Works_;
    };

} // namespace Stratum

//
// (9) X struct for template dispatch (copied from Doge/LTC):
//
struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;

    template<typename T>
    static inline void serialize(xmstream &s, const T &d)   { BTC::Io<T>::serialize(s, d); }

    template<typename T>
    static inline void unserialize(xmstream &s, T &d)       { BTC::Io<T>::unserialize(s, d); }
};

} // namespace FB
