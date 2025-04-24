// dash.h
#pragma once

#include "blockmaker/btcLike.h"
#include <vector>
#include <string>
#include "poolcommon/uint256.h"

struct CbTx {
    uint16_t version;
    uint32_t height;
    uint256 merkleRootMNList;
    uint256 merkleRootQuorums;
    uint16_t bestCLHeightDiff;
    std::vector<uint8_t> bestCLSignature;
    uint64_t creditPoolBalance;

    void serialize(std::vector<uint8_t>& out) const;
    void unserialize(const std::vector<uint8_t>& in);
};

struct ProviderRegisterTx {
    uint16_t version;
    std::string collateralAddress;
    std::string serviceAddress;
    std::vector<uint8_t> pubKeyOperator;
    std::vector<uint8_t> operatorReward;
    std::string payoutAddress;

    void serialize(std::vector<uint8_t>& out) const;
    void unserialize(const std::vector<uint8_t>& in);
};

class DashCoin : public BtcLikeCoin {
public:
    DashCoin();
    void hash(const uint8_t* input, uint32_t len, uint8_t* output) override;
    void buildCoinbaseTx(CoinbaseTemplate& cb, const BlockTemplate& bt) override;
};

extern "C" BtcLikeCoin* createCoin();
