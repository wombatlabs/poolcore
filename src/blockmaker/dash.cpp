#include "blockmaker/dash.h"
#include "blockmaker/x11.h"
#include "util/serialize.h"

DashCoin::DashCoin() {
    name = "DASH";
    symbol = "DASH";
    segwit = false;
    version = 0x20000000;  // if using version bits, else adjust
    txVersion = 3;
}

void DashCoin::hash(const uint8_t* input, uint32_t len, uint8_t* output) {
    x11_hash(input, len, output);
}

void DashCoin::buildCoinbaseTx(CoinbaseTx& cb, const BlockTemplate& bt) {
    cb.version = (5 << 16) | 3; // Type 5 (coinbase), Version 3
    cb.lockTime = 0;

    CbTx extra;
    extra.version = 3;
    extra.height = bt.height;
    extra.merkleRootMNList = bt.merkleRootMNList;
    extra.merkleRootQuorums = bt.merkleRootQuorums;
    extra.bestCLHeightDiff = 0;
    extra.bestCLSignature = {}; // Set properly if ChainLocks are used
    extra.creditPoolBalance = 0;

    std::vector<uint8_t> payload;
    extra.serialize(payload);
    cb.extraPayload = payload;
}

// CbTx serialization helpers
void CbTx::serialize(std::vector<uint8_t>& out) const {
    xmstream stream;
    serializeVarInt(stream, version);
    serializeLE(stream, height);
    serializeLE(stream, merkleRootMNList);
    serializeLE(stream, merkleRootQuorums);
    serializeLE(stream, bestCLHeightDiff);
    serializeVarBytes(stream, bestCLSignature);
    serializeLE(stream, creditPoolBalance);
    out.assign(stream.data(), stream.data() + stream.size());
}

void CbTx::unserialize(const std::vector<uint8_t>& in) {
    xmstream stream(in.data(), in.size());
    version = readVarInt<uint16_t>(stream);
    height = unserializeLE<uint32_t>(stream);
    unserializeLE(stream, merkleRootMNList);
    unserializeLE(stream, merkleRootQuorums);
    bestCLHeightDiff = unserializeLE<uint16_t>(stream);
    bestCLSignature = readVarBytes(stream);
    creditPoolBalance = unserializeLE<uint64_t>(stream);
}

extern "C" BtcLikeCoin* createCoin() {
    return new DashCoin();
}
