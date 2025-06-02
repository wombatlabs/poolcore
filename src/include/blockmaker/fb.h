#pragma once

#include "poolinstances/stratum.h"            // for SubscribeInfo, CMiningConfig, CWorkerConfig, etc.
#include "btc.h"                               // for BTC::Proto, BTC::Stratum, BTC::WorkTy, etc.
#include "poolinstances/stratumWorkStorage.h"  // for StratumMergedWork, StratumSingleWork

namespace FB {

class Proto {
public:
    static constexpr const char *TickerName = "FB";

    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using AddressTy   = BTC::Proto::AddressTy;

    using PureBlockHeader = BTC::Proto::BlockHeader;

    using TxIn       = BTC::Proto::TxIn;
    using TxOut      = BTC::Proto::TxOut;
    using TxWitness  = BTC::Proto::TxWitness;
    using Transaction= BTC::Proto::Transaction;

    struct BlockHeader : public PureBlockHeader {
        static const int32_t VERSION_AUXPOW = (1 << 8);
        Transaction        ParentBlockCoinbaseTx;
        uint256            HashBlock;
        xvector<uint256>   MerkleBranch;
        int                Index;
        xvector<uint256>   ChainMerkleBranch;
        int                ChainIndex;
        PureBlockHeader    ParentBlock;
    };

    using Block = BTC::Proto::BlockTy<FB::Proto>;

    using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
    using ChainParams      = BTC::Proto::ChainParams;

    static void checkConsensusInitialize(CheckConsensusCtx&) {}

    static CCheckStatus checkConsensus(const Proto::BlockHeader &header,
                                       CheckConsensusCtx &ctx,
                                       Proto::ChainParams &chainParams) {
        if (header.nVersion & Proto::BlockHeader::VERSION_AUXPOW) {
            return BTC::Proto::checkConsensus(header.ParentBlock, ctx, chainParams);
        } else {
            return BTC::Proto::checkConsensus(header, ctx, chainParams);
        }
    }

    static CCheckStatus checkConsensus(const Proto::Block &block,
                                       CheckConsensusCtx &ctx,
                                       Proto::ChainParams &chainParams) {
        return checkConsensus(block.header, ctx, chainParams);
    }

    static double getDifficulty(const Proto::BlockHeader &header) {
        return BTC::difficultyFromBits(header.nBits, 29);
    }

    static double expectedWork(const Proto::BlockHeader &header,
                               const CheckConsensusCtx&) {
        return getDifficulty(header);
    }

    static bool decodeHumanReadableAddress(const std::string &hrAddress,
                                           const std::vector<uint8_t> &pubkeyAddressPrefix,
                                           AddressTy &address) {
        return BTC::Proto::decodeHumanReadableAddress(hrAddress, pubkeyAddressPrefix, address);
    }
};

class Stratum {
public:
    static constexpr double DifficultyFactor = 65536.0;

    using FbWork = BTC::WorkTy<FB::Proto,
                               BTC::Stratum::HeaderBuilder,
                               BTC::Stratum::CoinbaseBuilder,
                               BTC::Stratum::Notify,
                               BTC::Stratum::Prepare>;

    class MergedWork : public StratumMergedWork {
    public:
        MergedWork(uint64_t stratumWorkId,
                   StratumSingleWork *first,
                   std::vector<StratumSingleWork*> &second,
                   std::vector<int> &mmChainId,
                   uint32_t mmNonce,
                   unsigned int virtualHashesNum,
                   const CMiningConfig &miningCfg);

        virtual Proto::BlockHashTy shareHash() override {
            return BTCHeader_.GetHash();
        }

        virtual std::string blockHash(size_t workIdx) override {
            if (workIdx == 0)
                return BTCHeader_.GetHash().ToString();
            else if (workIdx - 1 < FBHeader_.size())
                return FBHeader_[workIdx - 1].GetHash().ToString();
            else
                return std::string();
        }

        virtual void mutate() override {
            BTCHeader_.nTime = static_cast<uint32_t>(time(nullptr));
            BTC::Stratum::Work::buildNotifyMessageImpl(
                this,
                BTCHeader_,
                BTCHeader_.nVersion,
                BTCLegacy_,
                BTCMerklePath_,
                MiningCfg_,
                true,
                NotifyMessage_
            );
        }

        virtual void buildNotifyMessage(bool resetPreviousWork) override {
            BTC::Stratum::Work::buildNotifyMessageImpl(
                this,
                BTCHeader_,
                BTCHeader_.nVersion,
                BTCLegacy_,
                BTCMerklePath_,
                MiningCfg_,
                resetPreviousWork,
                NotifyMessage_
            );
        }

        virtual bool prepareForSubmit(const CWorkerConfig &workerCfg,
                                      const CStratumMessage &msg) override;

        virtual void buildBlock(size_t workIdx,
                                xmstream &blockHexData) override {
            if (workIdx == 0 && btcWork()) {
                btcWork()->buildBlockImpl(BTCHeader_, BTCWitness_, blockHexData);
            } else if (fbWork(workIdx - 1)) {
                fbWork(workIdx - 1)->buildBlockImpl(
                    FBHeader_[workIdx - 1],
                    FBWitness_[workIdx - 1],
                    blockHexData
                );
            }
        }

        virtual CCheckStatus checkConsensus(size_t workIdx) override {
            if (workIdx == 0 && btcWork()) {
                return BTC::Stratum::Work::checkConsensusImpl(
                    BTCHeader_,
                    FBConsensusCtx_
                );
            } else if (fbWork(workIdx - 1)) {
                return FB::Stratum::FbWork::checkConsensusImpl(
                    FBHeader_[workIdx - 1],
                    BTCConsensusCtx_
                );
            }
            return CCheckStatus();
        }

    private:
        BTC::Stratum::Work *btcWork() {
            return static_cast<BTC::Stratum::Work*>(Works_[0].Work);
        }
        FB::Stratum::FbWork *fbWork(unsigned index) {
            return static_cast<FB::Stratum::FbWork*>(Works_[index + 1].Work);
        }

    private:
        BTC::Proto::BlockHeader       BTCHeader_;
        BTC::CoinbaseTx               BTCLegacy_;
        BTC::CoinbaseTx               BTCWitness_;
        std::vector<uint256>          BTCMerklePath_;
        BTC::Proto::CheckConsensusCtx BTCConsensusCtx_;

        std::vector<FB::Proto::BlockHeader> FBHeader_;
        std::vector<BTC::CoinbaseTx>        FBLegacy_;
        std::vector<BTC::CoinbaseTx>        FBWitness_;
        std::vector<uint256>                FBHeaderHashes_;
        std::vector<int>                    FBWorkMap_;
        FB::Proto::CheckConsensusCtx        FBConsensusCtx_;
    };

    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary,
                                          uint32_t &nonce,
                                          unsigned int &virtualHashesNum);

    static constexpr bool MergedMiningSupport = true;

    //──────────────────────────────────────────────────────────────────────────
    // Below are all the static methods required by StratumInstance<FB::X>.
    // They mirror DOGE::Stratum’s signatures, with DOGE → FB substitutions.
    //──────────────────────────────────────────────────────────────────────────

    // (1) Called when a miner sends “mining.subscribe”.
    static void workerConfigOnSubscribe(CWorkerConfig     &workerCfg,
                                        CMiningConfig     &miningCfg,
                                        CStratumMessage   &msg,
                                        xmstream          &out,
                                        std::string       &subscribeInfo)
    {
        BTC::Stratum::workerConfigOnSubscribe(
            workerCfg,
            miningCfg,
            msg,
            out,
            subscribeInfo
        );
    }

    // (2) Builds “mining.set_difficulty” JSON to send target → miner.
    static void buildSendTargetMessage(xmstream &stream, double shareDifficulty)
    {
        BTC::Stratum::buildSendTargetMessageImpl(
            stream,
            shareDifficulty,
            DifficultyFactor
        );
    }

    // (3) Create a new primary Work (standard BTC work).
    static BTC::Stratum::Work* newPrimaryWork(int64_t                    stratumId,
                                              PoolBackend               *backend,
                                              size_t                      backendIdx,
                                              const CMiningConfig       &miningCfg,
                                              const std::vector<uint8_t> &miningAddress,
                                              const std::string         &coinbaseMessage,
                                              CBlockTemplate            &blockTemplate,
                                              std::string               &error)
    {
        if (blockTemplate.WorkType != EWorkBitcoin) {
            error = "incompatible work type";
            return nullptr;
        }
        std::unique_ptr<BTC::Stratum::Work> work(
            new BTC::Stratum::Work(
                stratumId,
                blockTemplate.UniqueWorkId,
                backend,
                backendIdx,
                miningCfg,
                miningAddress,
                coinbaseMessage
            )
        );
        return work->loadFromTemplate(blockTemplate, error)
               ? work.release()
               : nullptr;
    }

    // (4) Create a new secondary Work (FB single-chain work).
    static FbWork* newSecondaryWork(int64_t                    stratumId,
                                    PoolBackend               *backend,
                                    size_t                      backendIdx,
                                    const CMiningConfig       &miningCfg,
                                    const std::vector<uint8_t> &miningAddress,
                                    const std::string         &coinbaseMessage,
                                    CBlockTemplate            &blockTemplate,
                                    std::string               &error)
    {
        if (blockTemplate.WorkType != EWorkBitcoin) {
            error = "incompatible work type";
            return nullptr;
        }
        std::unique_ptr<FbWork> work(
            new FbWork(
                stratumId,
                blockTemplate.UniqueWorkId,
                backend,
                backendIdx,
                miningCfg,
                miningAddress,
                coinbaseMessage
            )
        );
        return work->loadFromTemplate(blockTemplate, error)
               ? work.release()
               : nullptr;
    }

    // (5) Create a new MergedWork (BTC + FB merged mining).
    static StratumMergedWork* newMergedWork(int64_t                    stratumId,
                                            StratumSingleWork         *primaryWork,
                                            std::vector<StratumSingleWork*> &secondaryWorks,
                                            const CMiningConfig       &miningCfg,
                                            std::string               &error)
    {
        if (secondaryWorks.empty()) {
            error = "no secondary works";
            return nullptr;
        }

        uint32_t nonce = 0;
        unsigned virtualHashesNum = 0;
        std::vector<int> chainMap =
            buildChainMap(secondaryWorks, nonce, virtualHashesNum);

        if (chainMap.empty()) {
            error = "chainId conflict";
            return nullptr;
        }

        return new MergedWork(
            stratumId,
            primaryWork,
            secondaryWorks,
            chainMap,
            nonce,
            virtualHashesNum,
            miningCfg
        );
    }

    // (6) Decode a JSON string from the miner → our CStratumMessage.
    static EStratumDecodeStatusTy decodeStratumMessage(CStratumMessage &msg,
                                                       const char      *in,
                                                       size_t           size)
    {
        return BTC::Stratum::decodeStratumMessage(msg, in, size);
    }

    // (7) Initialize miningCfg from the instance’s JSON.
    static void miningConfigInitialize(CMiningConfig  &miningCfg,
                                       rapidjson::Value &instanceCfg)
    {
        BTC::Stratum::miningConfigInitialize(miningCfg, instanceCfg);
    }

    // (8) Initialize workerCfg before mining.subscribe.
    static void workerConfigInitialize(CWorkerConfig &workerCfg,
                                       ThreadConfig   &threadCfg)
    {
        BTC::Stratum::workerConfigInitialize(workerCfg, threadCfg);
    }

    // (9) Setup version-rolling mask if requested.
    static void workerConfigSetupVersionRolling(CWorkerConfig &workerCfg,
                                                uint32_t        versionMask)
    {
        BTC::Stratum::workerConfigSetupVersionRolling(workerCfg, versionMask);
    }
    //───────────────────────────────────────────────────────────────────────────

}; // class Stratum

//────────────────── Io specialization for AuxPoW protobuf header ───────────
namespace BTC {
    template<>
    struct Io<FB::Proto::BlockHeader> {
        static void serialize(xmstream &dst, const FB::Proto::BlockHeader &data);
        static void unserialize(xmstream &src, FB::Proto::BlockHeader &data);
    };
}

void serializeJsonInside(xmstream &stream, const FB::Proto::BlockHeader &header);

} // namespace FB
