#include "blockmaker/dash.h"
#include "blockmaker/x11.h"
#include "util/serialize.h"

// -------------------- CbTx Implementation --------------------

void CbTx::serialize(std::vector<uint8_t>& out) const {
    serializeUint16(out, version);
    serializeUint32(out, height);
    serializeHash(out, merkleRootMNList);
    serializeHash(out, merkleRootQuorums);
    serializeUint16(out, bestCLHeightDiff);
    serializeVarBytes(out, bestCLSignature);
    serializeVarInt(out, creditPoolBalance);
}

void CbTx::unserialize(const std::vector<uint8_t>& in) {
    size_t offset = 0;
    version = unserializeUint16(in, offset);
    height = unserializeUint32(in, offset);
    merkleRootMNList = unserializeHash(in, offset);
    merkleRootQuorums = unserializeHash(in, offset);
    bestCLHeightDiff = unserializeUint16(in, offset);
    bestCLSignature = unserializeVarBytes(in, offset);
    creditPoolBalance = unserializeVarInt(in, offset);
}

// ---------------- ProviderRegisterTx Implementation ----------------

void ProviderRegisterTx::serialize(std::vector<uint8_t>& out) const {
    serializeUint16(out, version);
    serializeString(out, collateralAddress);
    serializeString(out, serviceAddress);
    serializeVarBytes(out, pubKeyOperator);
    serializeVarBytes(out, operatorReward);
    serializeString(out, payoutAddress);
}

void ProviderRegisterTx::unserialize(const std::vector<uint8_t>& in) {
    size_t offset = 0;
    version = unserializeUint16(in, offset);
    collateralAddress = unserializeString(in, offset);
    serviceAddress = unserializeString(in, offset);
    pubKeyOperator = unserializeVarBytes(in, offset);
    operatorReward = unserializeVarBytes(in, offset);
    payoutAddress = unserializeString(in, offset);
}

// -------------------- DashCoin Implementation --------------------

DashCoin::DashCoin() {
    name = "dash";
    algo = "x11";
    port = 9999;
    symbol = "DASH";
    supportsSegwit = false;
}

void DashCoin::hash(const uint8_t* input, uint32_t len, uint8_t* output) {
    x11_hash(input, len, output);
}

void DashCoin::buildCoinbaseTx(CoinbaseTemplate& cb, const BlockTemplate& bt) {
    BtcLikeCoin::buildCoinbaseTx(cb, bt);

    cb.version = (5 << 16) | 3; // Type 5 (cbTx), Version 3

    CbTx cbtx;
    cbtx.version = 3;
    cbtx.height = bt.height;
    cbtx.merkleRootMNList = bt.merkleRootMNList;
    cbtx.merkleRootQuorums = bt.merkleRootQuorums;
    cbtx.bestCLHeightDiff = 0;
    cbtx.bestCLSignature = bt.bestCLSignature;
    cbtx.creditPoolBalance = static_cast<uint64_t>(bt.creditPoolBalance * 1e8);

    cbtx.serialize(cb.extraPayload);
}

extern "C" BtcLikeCoin* createCoin() {
    return new DashCoin();
}
