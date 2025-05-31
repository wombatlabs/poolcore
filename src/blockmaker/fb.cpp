// fb.cpp

#include "blockmaker/fb.h"
#include "blockmaker/merkleTree.h"
#include "blockmaker/serializeJson.h"

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

static unsigned merklePathSize(unsigned count) {
    return count > 1 ? (31 - __builtin_clz((count << 1) - 1)) : 0;
}

static uint32_t getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h) {
    uint32_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    return rand % (1 << h);
}

namespace FB {

//
// buildChainMap: identical to DOGE::buildChainMap except
// we cast to FbWork* instead of DogeWork*.
//

std::vector<int> Stratum::buildChainMap(
    std::vector<StratumSingleWork*> &secondaries,
    uint32_t                       &nonce,
    unsigned                       &virtualHashesNum
) {
    std::vector<int> result(secondaries.size());
    std::vector<int> chainMap;
    bool finished = true;

    for (unsigned pathSize = merklePathSize(secondaries.size()); pathSize < 8; pathSize++) {
        virtualHashesNum = 1u << pathSize;
        chainMap.resize(virtualHashesNum);

        for (nonce = 0; nonce < virtualHashesNum; nonce++) {
            finished = true;
            std::fill(chainMap.begin(), chainMap.end(), 0);

            for (size_t workIdx = 0; workIdx < secondaries.size(); workIdx++) {
                FbWork *work = static_cast<FbWork*>(secondaries[workIdx]);
                uint32_t chainId = work->Header.nVersion >> 16;
                uint32_t indexInMerkle = getExpectedIndex(nonce, chainId, pathSize);

                if (chainMap[indexInMerkle] == 0) {
                    chainMap[indexInMerkle] = 1;
                    result[workIdx] = indexInMerkle;
                } else {
                    finished = false;
                    break;
                }
            }

            if (finished) break;
        }

        if (finished) break;
    }

    return finished ? result : std::vector<int>();
}

//
// MergedWork constructor: copy+adapt from DOGE::Stratum::MergedWork, replacing DOGE/LTC with FB/BTC.
//

Stratum::MergedWork::MergedWork(
    uint64_t                         stratumWorkId,
    StratumSingleWork              *first,
    std::vector<StratumSingleWork*> &second,
    std::vector<int>                &mmChainId,
    uint32_t                         mmNonce,
    unsigned                         virtualHashesNum,
    const CMiningConfig             &miningCfg
) : StratumMergedWork(stratumWorkId, first, second, miningCfg)
{
    // 1) Copy “primary” (BTC) header + merkle + consensus‐ctx:
    BTCHeader_      = btcWork()->Header;
    BTCMerklePath_  = btcWork()->MerklePath;
    BTCConsensusCtx_ = btcWork()->ConsensusCtx;

    // 2) Prepare FB secondaries:
    fbHeaders_.resize(second.size());
    fbLegacy_.resize(second.size());
    fbWitness_.resize(second.size());
    fbHeaderHashes_.resize(virtualHashesNum, uint256());
    fbWorkMap_.assign(mmChainId.begin(), mmChainId.end());

    // 3) Build “static” FB coinbase + compute each secondary’s merkle root hash:
    for (size_t workIdx = 0; workIdx < fbHeaders_.size(); workIdx++) {
        FbWork *work = fbWork(workIdx);
        FB::Proto::BlockHeader &header = fbHeaders_[workIdx];
        BTC::CoinbaseTx &legacy = fbLegacy_[workIdx];
        BTC::CoinbaseTx &witness = fbWitness_[workIdx];

        header = work->Header;

        // Build a “stat
