#pragma once
#include "serialize.h"
#include "xvector.h"
#include "poolcommon/uint256.h"
#include "blockmaker/x11.h"

template<typename T> struct Io;

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

using AddressTy = std::vector<uint8_t>;

static inline bool decodeHumanReadableAddress(const std::string &addr, uint8_t prefix, AddressTy &out) {
    // Minimal stub – implement real decoding logic later
    out.clear();
    return true;
}

} // namespace Proto

struct Stratum {
    static constexpr bool MergedMiningSupport = false;

    static void miningConfigInitialize(CMiningConfig &cfg, const rapidjson::Value &config) {
        // Stub: fill in config from JSON if needed
    }

    static void workerConfigInitialize(CWorkerConfig &workerCfg, const CThreadConfig &threadCfg) {
        // Stub: handle thread-specific config
    }
};

struct X {
    static constexpr const char* name = "Dash";
    static constexpr const char* symbol = "DASH";
    static constexpr uint32_t defaultPort = 9999;

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
        return x11_hash((const uint8_t*)&header, sizeof(header));
    }
};

} // namespace DASH
