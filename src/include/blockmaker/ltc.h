// Copyright (c) 2020 Ivan K.
// Copyright (c) 2020 The BCNode developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "btc.h"

namespace LTC {
class Proto {
public:
  static constexpr const char *TickerName = "LTC";

  using BlockHashTy = BTC::Proto::BlockHashTy;
  using TxHashTy = BTC::Proto::TxHashTy;
  using AddressTy = BTC::Proto::AddressTy;
  using BlockHeader = BTC::Proto::BlockHeader;
  using Block = BTC::Proto::Block;
  using TxIn = BTC::Proto::TxIn;
  using TxOut = BTC::Proto::TxOut;
  using TxWitness = BTC::Proto::TxWitness;
  using Transaction = BTC::Proto::Transaction;

  using CheckConsensusCtx = BTC::Proto::CheckConsensusCtx;
  using ChainParams = BTC::Proto::ChainParams;

  static void checkConsensusInitialize(CheckConsensusCtx &ctx) {}
  static bool checkConsensus(const LTC::Proto::BlockHeader &header, CheckConsensusCtx&, LTC::Proto::ChainParams &chainParams, double *shareDiff);
  static bool checkConsensus(const LTC::Proto::Block &block, CheckConsensusCtx &ctx, LTC::Proto::ChainParams &chainParams, double *shareDiff) { return checkConsensus(block.header, ctx, chainParams, shareDiff); }
};

using Stratum = BTC::Stratum;

struct X {
  using Proto = LTC::Proto;
  using Stratum = LTC::Stratum;
  template<typename T> static inline void serialize(xmstream &src, const T &data) { BTC::Io<T>::serialize(src, data); }
  template<typename T> static inline void unserialize(xmstream &dst, T &data) { BTC::Io<T>::unserialize(dst, data); }
};
}
