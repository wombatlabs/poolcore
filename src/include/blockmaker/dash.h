#include "btc.h"
#include "blockmaker/x11.h"

namespace DASH {

class Proto {
public:
    static constexpr const char *TickerName = "DASH";

    using BlockHashTy = BTC::Proto::BlockHashTy;
    using TxHashTy    = BTC::Proto::TxHashTy;
    using AddressTy   = BTC::Proto::AddressTy;

    // Reuse Bitcoin block header
    using BlockHeader = BTC::Proto::BlockHeader;

    // Dash transaction with extra payload support
    struct Transaction {
        int32_t               version;
        xvector<TxIn>         txIn;
        xvector<TxOut>        txOut;
        uint32_t              lockTime;
        xvector<uint8_t>      vExtraPayload;  // only for special TX types

        // Memory-only fields for caching
        uint32_t              SerializedDataOffset = 0;
        uint32_t              SerializedDataSize   = 0;
        TxHashTy              Hash;

        // Dash has no segwit
        bool hasWitness() const { return false; }
    };

    // X11-based proof-of-work check
    static CCheckStatus checkPow(const BlockHeader &header, uint32_t nBits);
};

// Serializer specialization for Transaction
template<> struct Io<Proto::Transaction> {
    static void serialize(xmstream &dst, const Proto::Transaction &data, bool serializeWitness = false);
    static void unserialize(xmstream &src, Proto::Transaction &data);
    static void unpack(xmstream &src, DynamicPtr<Proto::Transaction> dst);
};

} // namespace DASH