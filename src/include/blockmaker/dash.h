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
    (void)addr; (void)prefix;
    out.clear();
    return true;
}

} // namespace Proto

struct Stratum {
    static constexpr bool MergedMiningSupport = false;

    static void miningConfigInitialize(CMiningConfig &cfg, const rapidjson::Value &config) {
        (void)cfg; (void)config;
    }

    static void workerConfigInitialize(CWorkerConfig &workerCfg, const ThreadConfig &threadCfg) {
        (void)workerCfg; (void)threadCfg;
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
        uint8_t hash[32];
        x11_hash((const uint8_t*)&header, sizeof(header), hash);
        return uint256::fromBlob(hash);
    }
};

} // namespace DASH
