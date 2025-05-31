#pragma once

#include "btc.h"
#include "poolinstances/stratumWorkStorage.h"
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

    static void checkConsensusInitialize(CheckConsensusCtx&) { /* no‐op */ }

    static CCheckStatus checkConsensus(
        const BlockHeader &header,
        CheckConsensusCtx  &ctx,
        ChainParams        &params
    ) {
        if (header.nVersion & Proto::BlockHeader::VERSION_AUXPOW) {
            return BTC::Proto::checkConsensus(header.ParentBlock, ctx, params);
        } else {
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

}

namespace BTC {
template<>
struct Io<FB::Proto::BlockHeader> {
    static void serialize(xmstream &dst, const FB::Proto::BlockHeader &data) {
        // Serialize base BTC header fields:
        BTC::serialize(dst, *(FB::Proto::PureBlockHeader*)&data);
        if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
            // Then serialize AuxPoW fields:
            BTC::serialize(dst, data.ParentBlockCoinbaseTx);
            BTC::serialize(dst, data.HashBlock);
            BTC::serialize(dst, data.MerkleBranch);
            BTC::serialize(dst, data.Index);
            BTC::serialize(dst, data.ChainMerkleBranch);
            BTC::serialize(dst, data.ChainIndex);
            BTC::serialize(dst, data.ParentBlock);
        }
    }

    static void unserialize(xmstream &src, FB::Proto::BlockHeader &data) {
        // Deserialize base BTC header:
        BTC::unserialize(src, *(FB::Proto::PureBlockHeader*)&data);
        if (data.nVersion & FB::Proto::BlockHeader::VERSION_AUXPOW) {
            // Then AuxPoW fields:
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

static void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header) {
    serializeJson(stream, "version", header.nVersion);      stream.write(',');
    serializeJson(stream, "hashPrevBlock", header.hashPrevBlock);  stream.write(',');
    serializeJson(stream, "hashMerkleRoot", header.hashMerkleRoot); stream.write(',');
    serializeJson(stream, "time", header.nTime);            stream.write(',');
    serializeJson(stream, "bits", header.nBits);
}

namespace FB {

class Stratum {
public:
    static constexpr double DifficultyFactor = 65536.0;

    using FbWork = BTC::WorkTy<
        FB::Proto,
        BTC::Stratum::HeaderBuilder,
        BTC::Stratum::CoinbaseBuilder,
        BTC::Stratum::Notify,
        BTC::Stratum::Prepare
    >;

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

        BTC::Stratum::Work* btcWork() {
            return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        }

        FbWork* fbWork(unsigned idx) {
            return static_cast<FbWork*>(Works_[idx + 1].Work);
        }

        BTC::Proto::BlockHeader         BTCHeader_;
        BTC::CoinbaseTx                 BTCLegacy_;
        BTC::CoinbaseTx                 BTCWitness_;
        std::vector<uint256>            BTCMerklePath_;
        BTC::Proto::CheckConsensusCtx   BTCConsensusCtx_;

        std::vector<FB::Proto::BlockHeader> fbHeaders_;
        std::vector<BTC::CoinbaseTx>           fbLegacy_;
        std::vector<BTC::CoinbaseTx>           fbWitness_;
        std::vector<uint256>                   fbHeaderHashes_;
        std::vector<int>                       fbWorkMap_;
        std::vector<FB::Proto::CheckConsensusCtx> fbConsensusCtx_;
        FB::Proto::ChainParams             fbChainParams_;

        CMiningConfig                         MiningCfg_;
    };

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

    static StratumMergedWork* newMergedWork(
        int64_t                       stratumId,
        StratumSingleWork           *first,
        std::vector<StratumSingleWork*> &second,
        const CMiningConfig          &miningCfg,
        std::string                  &error
    );
};

} // namespace FB
