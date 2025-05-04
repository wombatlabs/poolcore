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

} // namespace Proto

struct X {
    static constexpr const char* name = "Dash";
    static constexpr const char* symbol = "DASH";
    static constexpr uint32_t defaultPort = 9999;

    using Transaction = Proto::Transaction;
    using BlockHeader = Proto::BlockHeader;

    template<typename T>
    static inline void serialize(xmstream &dst, const T &data) {
        ::Io<T>::serialize(dst, data, false);
    }

    template<typename T>
    static inline void unserialize(xmstream &src, T &data) {
        ::Io<T>::unserialize(src, data);
    }

    static inline uint256 getPoWHash(const BlockHeader &header) {
        return getPoWHashX11((const uint8_t*)&header, sizeof(header));
    }
};

} // namespace DASH
