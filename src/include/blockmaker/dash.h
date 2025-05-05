// Copyright (c) 2020 Ivan K.
// Copyright (c) 2020 The BCNode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "btc.h"

namespace DASH {
  class Proto {
  public:
    static constexpr const char *TickerName = "DASH";

    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using AddressTy   = BTC::Proto::AddressTy;
    using BlockHeader = BTC::Proto::BlockHeader;
    using Block       = BTC::Proto::Block;
    using TxIn        = BTC::Proto::TxIn;
    using TxOut       = BTC::Proto::TxOut;

    struct Transaction {
        int32_t           version;
        xvector<TxIn>     txIn;
        xvector<TxOut>    txOut;
        uint32_t          lockTime;
        xvector<uint8_t>  vExtraPayload;  // only for special TX types

        // Memory-only cache fields
        uint32_t          SerializedDataOffset = 0;
        uint32_t          SerializedDataSize   = 0;
        TxHashTy          Hash;

        bool hasWitness() const { return false; }
    };

    using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
    using ChainParams       = BTC::Proto::ChainParams;

    static CCheckStatus checkPow(const BlockHeader &header, uint32_t nBits);
    static void checkConsensusInitialize(CheckConsensusCtx&) {}
    static CCheckStatus checkConsensus(const BlockHeader &header, CheckConsensusCtx&, ChainParams&) {
        return checkPow(header, header.nBits);
    }
    static CCheckStatus checkConsensus(const Block &block, CheckConsensusCtx&, ChainParams&) {
        return checkPow(block.header, block.header.nBits);
    }
    static double getDifficulty(const BlockHeader &header) {
        return BTC::difficultyFromBits(header.nBits, 29);
    }
    static double expectedWork(const BlockHeader &header, const CheckConsensusCtx&) {
        return getDifficulty(header);
    }
    static bool decodeHumanReadableAddress(const std::string &hrAddress,
                                            const std::vector<uint8_t> &prefix,
                                            AddressTy &address) {
        return BTC::Proto::decodeHumanReadableAddress(hrAddress, prefix, address);
    }
  };
}

namespace BTC {

  // Serialize/unserialize DASH transactions
  template<>
  struct Io<DASH::Proto::Transaction> {
      static void serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool /*serializeWitness*/ = false) {
          BTC::serialize(dst, data.version);
          BTC::serialize(dst, data.txIn);
          BTC::serialize(dst, data.txOut);
          BTC::serialize(dst, data.lockTime);
          BTC::serialize(dst, data.vExtraPayload);
      }
  
      static void unserialize(xmstream &src, DASH::Proto::Transaction &data) {
          BTC::unserialize(src, data.version);
          BTC::unserialize(src, data.txIn);
          BTC::unserialize(src, data.txOut);
          BTC::unserialize(src, data.lockTime);
          BTC::unserialize(src, data.vExtraPayload);
      }
  
      static void unpack(xmstream &src, DynamicPtr<DASH::Proto::Transaction> dst) {
          unserialize(src, *dst.ptr());
      }
  
      static void unpackFinalize(DynamicPtr<DASH::Proto::Transaction>) {}
  };
  
}
namespace DASH {
  class Stratum {
  public:
    static constexpr double DifficultyFactor = 1;

    using MiningConfig = BTC::Stratum::MiningConfig;
    using WorkerConfig = BTC::Stratum::WorkerConfig;
    using StratumMessage = BTC::Stratum::StratumMessage;

    using Work = BTC::WorkTy<DASH::Proto, BTC::Stratum::HeaderBuilder, BTC::Stratum::CoinbaseBuilder, BTC::Stratum::Notify, BTC::Stratum::Prepare, MiningConfig, WorkerConfig, StratumMessage>;
    using SecondWork = StratumSingleWorkEmpty<Proto::BlockHashTy, MiningConfig, WorkerConfig, StratumMessage>;
    using MergedWork = StratumMergedWorkEmpty<Proto::BlockHashTy, MiningConfig, WorkerConfig, StratumMessage>;
    static constexpr bool MergedMiningSupport = false;
    static bool isMainBackend(const std::string&) { return true; }
    static bool keepOldWorkForBackend(const std::string&) { return false; }
    static void buildSendTargetMessage(xmstream &stream, double difficulty) { BTC::Stratum::buildSendTargetMessageImpl(stream, difficulty, DifficultyFactor); }
  };    


  struct X {
    using Proto = DASH::Proto;
    using Stratum = DASH::Stratum;
    template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
    template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
  };
}
