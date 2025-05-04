#pragma once
#include "serialize.h"
#include "xvector.h"
#include "poolcommon/uint256.h"
#include "blockmaker/x11.h"

namespace DASH {
namespace Proto {

struct TxIn {
    uint256 prevoutHash;
    uint32_t prevoutN;
    xvector<uint8_t> scriptSig;
    uint32_t sequence;
};

struct TxOut {
    uint64_t value;
    xvector<uint8_t> scriptPubKey;
};

struct Transaction {
    int32_t nVersion;
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    uint32_t nLockTime;
    xvector<uint8_t> vExtraPayload;
};

struct BlockHeader {
    int32_t version;
    uint256 prevBlockHash;
    uint256 merkleRoot;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
};

using AddressTy = std::vector<uint8_t>;  // Dash-style address placeholder

} // namespace Proto

struct Stratum {
    static constexpr bool MergedMiningSupport = false;

    static void miningConfigInitialize(auto &cfg, const rapidjson::Value &config) {
        // Minimal stub; extend if needed
    }
};

struct X {
    using Transaction = Proto::Transaction;
    using BlockHeader = Proto::BlockHeader;
    using Proto = DASH::Proto;
    using Stratum = DASH::Stratum;

    template<typename T>
    static inline void serialize(xmstream &dst, const T &data) {
        Io<T>::serialize(dst, data, false);
    }

    template<typename T>
    static inline void unserialize(xmstream &src, T &data) {
        Io<T>::unserialize(src, data);
    }

    static inline uint256 getPoWHash(const BlockHeader &header) {
        return getPoWHashX11((const uint8_t*)&header, sizeof(header));
    }
};

} // namespace DASH
