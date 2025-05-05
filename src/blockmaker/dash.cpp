#include "poolcommon/arith_uint256.h"
#include "blockmaker/dash.h"
#include "blockmaker/x11.h"
#include "blockmaker/btc.h"

// Existing POW check
CCheckStatus DASH::Proto::checkPow(const Dash::Proto::BlockHeader &header, uint32_t nBits) {
    CCheckStatus status;
    // Compute X11 hash
    arith_uint256 x11Hash;
    x11_hash(reinterpret_cast<const uint8_t*>(&header), sizeof(header), x11Hash.begin());
    // Calculate share difficulty from bits
    status.ShareDiff = BTC::difficultyFromBits(x11Hash.GetCompact(), 29);

    // Build target from compact
    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Range check
    if (fNegative || bnTarget == 0 || fOverflow)
        return status;

    // Proof-of-work check
    if (x11Hash > bnTarget)
        return status;

    status.IsBlock = true;
    return status;
}

// MergedWork implementation
DASH::Stratum::MergedWork::MergedWork(uint64_t stratumWorkId,
                                     CSingleWork *btcWork,
                                     CSingleWork *dashWork,
                                     MiningConfig &miningCfg)
  : CMergedWork(stratumWorkId, btcWork, dashWork, miningCfg)
{
  // 1) Save mining cfg
  miningCfg_ = miningCfg;

  // 2) Extract Bitcoin header + merkle path
  BTCHeader_     = btcWork->header_;
  BTCWitness_    = btcWork->witness_;
  BTCConsensusCtx_ = btcWork->consensusCtx_;

  // 3) Prepare Dash header for AuxPoW
  dashWork->header_.nVersion |= DASH::Proto::VERSION_AUXPOW;
  DASHHeader_      = dashWork->header_;
  dashWork->buildCoinbaseTx(nullptr, 0, miningCfg, DASHHeader_, DASHWitness_);
  DASHConsensusCtx_ = dashWork->consensusCtx_;

  // 4) Compute hashBlock (reversed)
  auto hash = DASHHeader_.GetHash();
  std::reverse(hash.begin(), hash.end());
  DASHHeader_.hashBlock = hash;

  // 5) Merkle branches
  DASHHeader_.merkleBranch = BTCHeader_.merkleBranch;
  DASHHeader_.index       = 0;
  DASHHeader_.chainMerkleBranch.clear();
  DASHHeader_.chainIndex = 0;

  // 6) Parent block header
  DASHHeader_.parentBlock = BTC::Proto::BlockHeader();
}

bool DASH::Stratum::MergedWork::prepareForSubmit(const WorkerConfig &workerCfg,
                                                const StratumMessage &msg)
{
  // 1) Submit the Bitcoin job
  if (!BTC::Stratum::Work::prepareForSubmitImpl(
         BTCHeader_, BTCHeader_.nVersion, BTCWitness_, workerCfg, miningCfg_, msg))
    return false;

  // 2) Attach AuxPoW to Dash submission
  xmstream &cb = BTCWitness_.Data;
  cb.seekSet(0);
  BTC::Io<Transaction>::unserialize(cb, DASHHeader_.parentCoinbaseTx);

  // 3) Inject AuxPoW fields into stream for Dash
  xmstream &stream = DASHWitness_.Data;
  BTC::Io<DASH::Proto::BlockHeader>::serialize(stream, DASHHeader_);

  return true;
}
