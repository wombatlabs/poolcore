#pragma once
#include "serialize.h"
#include "xvector.h"
#include "uint256.h"

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
    xvector<uint8_t> vExtraPayload;  // Dash-specific
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
} // namespace DASH

template <>
void Io<DASH::Proto::Transaction>::serialize(xmstream &dst, const DASH::Proto::Transaction &data, bool serializeWitness);

template <>
void Io<DASH::Proto::Transaction>::unserialize(xmstream &src, DASH::Proto::Transaction &data);
