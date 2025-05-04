#include "poolcommon/arith_uint256.h"
#include "blockmaker/dash.h"
#include "blockmaker/x11.h"

namespace DASH {
using namespace Proto;

// X11 proof-of-work
CCheckStatus Proto::checkPow(const BlockHeader &header, uint32_t nBits) {
    CCheckStatus status;
    arith_uint256 x11Hash;
    x11_hash(reinterpret_cast<const uint8_t*>(&header), sizeof(header), x11Hash.begin());
    status.ShareDiff = BTC::difficultyFromBits(x11Hash.GetCompact(), 29);

    bool fNegative = false, fOverflow = false;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow)
        return status;
    if (x11Hash > bnTarget)
        return status;
    status.IsBlock = true;
    return status;
}

// Transaction serialization: no segwit, extra payload at end
void Io<Transaction>::serialize(xmstream &dst, const Transaction &data, bool /*serializeWitness*/) {
    DASH::serialize(dst, data.version);
    DASH::serialize(dst, data.txIn);
    DASH::serialize(dst, data.txOut);
    DASH::serialize(dst, data.lockTime);
    DASH::serialize(dst, data.vExtraPayload);
}

// Transaction deserialization
void Io<Transaction>::unserialize(xmstream &src, Transaction &data) {
    DASH::unserialize(src, data.version);
    DASH::unserialize(src, data.txIn);
    DASH::unserialize(src, data.txOut);
    DASH::unserialize(src, data.lockTime);
    DASH::unserialize(src, data.vExtraPayload);
}

// For dynamic allocations
void Io<Transaction>::unpack(xmstream &src, DynamicPtr<Transaction> dst) {
    unserialize(src, *dst.ptr());
}

} // namespace DASH