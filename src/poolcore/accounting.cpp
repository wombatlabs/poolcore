#include "poolcore/accounting.h"
#include "poolcommon/coroutineJoin.h"
#include "poolcommon/mergeSorted.h"
#include "poolcommon/utils.h"
#include "poolcore/base58.h"
#include "poolcore/statistics.h"
#include "loguru.hpp"
#include <stdarg.h>
#include <poolcommon/file.h>
#include "poolcommon/debug.h"
#include <math.h>

#define ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE   10000

struct CSharesWorkWithTimeOld {
  int64_t TimeLabel;
  double SharesWork;
};

struct CStatsExportDataOld {
  std::string UserId;
  std::vector<CSharesWorkWithTimeOld> Recent;
};

template<>
struct DbIo<CSharesWorkWithTimeOld> {
  static inline void unserialize(xmstream &in, CSharesWorkWithTimeOld &data) {
    uint32_t sharesNum;
    DbIo<decltype(sharesNum)>::unserialize(in, sharesNum);
    DbIo<decltype(data.SharesWork)>::unserialize(in, data.SharesWork);
    DbIo<decltype(data.TimeLabel)>::unserialize(in, data.TimeLabel);
  }
};

template<>
struct DbIo<CStatsExportDataOld> {
  static inline void unserialize(xmstream &in, CStatsExportDataOld &data) {
    DbIo<decltype(data.UserId)>::unserialize(in, data.UserId);
    DbIo<decltype(data.Recent)>::unserialize(in, data.Recent);
  }
};

void AccountingDb::printRecentStatistic()
{
  if (RecentStats_.empty()) {
    LOG_F(INFO, "[%s] Recent statistic: empty", CoinInfo_.Name.c_str());
    return;
  }

  LOG_F(INFO, "[%s] Recent statistic:", CoinInfo_.Name.c_str());
  for (const auto &user: RecentStats_) {
    std::string line = user.UserId;
    line.append(": ");
    bool firstIter = true;
    for (const auto &stat: user.Recent) {
      if (!firstIter)
        line.append(", ");
      line.append(std::to_string(stat.SharesWork));
      firstIter = false;
    }

    LOG_F(INFO, " * %s", line.c_str());
  }
}

bool AccountingDb::parseAccoutingStorageFile(CAccountingFile &file)
{
  LastKnownShareId_ = 0;
  LastBlockTime_ = 0;
  RecentStats_.clear();
  CurrentScores_.clear();

  FileDescriptor fd;
  if (!fd.open(file.Path.u8string().c_str())) {
    LOG_F(ERROR, "AccountingDb: can't open file %s", file.Path.string().c_str());
    return false;
  }

  size_t fileSize = fd.size();
  xmstream stream(fileSize);
  size_t bytesRead = fd.read(stream.reserve(fileSize), 0, fileSize);
  fd.close();
  if (bytesRead != fileSize) {
    LOG_F(ERROR, "AccountingDb: can't read file %s", file.Path.string().c_str());
    return false;
  }

  stream.seekSet(0);
  CAccountingFileData fileData;

  if (file.IsOldFormat) {
    // Unserialize, we need read:
    //   * LastShareId (file.LastShareId)
    //   * LastBlockTime
    //   * RecentStats
    //   * Scores
    DbIo<decltype(fileData.LastShareId)>::unserialize(stream, fileData.LastShareId);
    DbIo<decltype(fileData.LastBlockTime)>::unserialize(stream, fileData.LastBlockTime);
    {
      std::vector<CStatsExportDataOld> recentStatsOld;
      DbIo<decltype(recentStatsOld)>::unserialize(stream, recentStatsOld);
      fileData.Recent.resize(recentStatsOld.size());
      for (size_t i = 0; i < recentStatsOld.size(); i++) {
        fileData.Recent[i].UserId = std::move(recentStatsOld[i].UserId);
        fileData.Recent[i].Recent.resize(recentStatsOld[i].Recent.size());
        for (size_t j = 0; j < recentStatsOld[i].Recent.size(); j++) {
          fileData.Recent[i].Recent[j].SharesWork = recentStatsOld[i].Recent[j].SharesWork;
          fileData.Recent[i].Recent[j].TimeLabel = recentStatsOld[i].Recent[j].TimeLabel;
        }
      }
    }

    {
      uint64_t size;
      DbIo<decltype(size)>::unserialize(stream, size);
      for (uint64_t i = 0; i < size; i++) {
        std::string userId;
        double score;
        DbIo<std::string>::unserialize(stream, userId);
        DbIo<double>::unserialize(stream, score);
        fileData.CurrentScores[userId] = score;
      }
    }
  } else {
    DbIo<CAccountingFileData>::unserialize(stream, fileData);
  }

  file.LastShareId = fileData.LastShareId;
  if (!stream.remaining() && !stream.eof()) {
    LastKnownShareId_ = fileData.LastShareId;
    LastBlockTime_ = fileData.LastBlockTime;
    RecentStats_ = std::move(fileData.Recent);
    CurrentScores_ = std::move(fileData.CurrentScores);
    return true;
  } else {
    LastKnownShareId_ = 0;
    LastBlockTime_ = 0;
    RecentStats_.clear();
    CurrentScores_.clear();
    LOG_F(ERROR, "AccountingDb: file %s is corrupted", file.Path.generic_string().c_str());
    return false;
  }
}

void AccountingDb::flushAccountingStorageFile(int64_t timeLabel)
{
  CAccountingFile &file = AccountingDiskStorage_.emplace_back();
  file.Path = _cfg.dbPath / "accounting.storage.2" / (std::to_string(timeLabel) + ".dat");
  file.LastShareId = LastKnownShareId_;
  file.TimeLabel = timeLabel;

  FileDescriptor fd;
  if (!fd.open(file.Path)) {
    LOG_F(ERROR, "AccountingDb: can't write file %s", file.Path.generic_string().c_str());
    return;
  }

  xmstream stream;
  DbIo<uint32_t>::serialize(stream, CAccountingFileData::CurrentRecordVersion);
  DbIo<decltype(LastKnownShareId_)>::serialize(stream, LastKnownShareId_);
  DbIo<decltype(LastBlockTime_)>::serialize(stream, LastBlockTime_);
  // Statistics
  DbIo<decltype(RecentStats_)>::serialize(stream, RecentStats_);
  // Current round aggregated data
  DbIo<decltype(CurrentScores_)>::serialize(stream, CurrentScores_);

  fd.write(stream.data(), stream.sizeOf());
  fd.close();

  // Cleanup old files
  auto removeTimePoint = timeLabel - std::chrono::seconds(300).count();
  while (!AccountingDiskStorage_.empty() && AccountingDiskStorage_.front().TimeLabel < removeTimePoint) {
    if (isDebugAccounting())
      LOG_F(1, "Removing old accounting file %s", AccountingDiskStorage_.front().Path.string().c_str());
    std::filesystem::remove(AccountingDiskStorage_.front().Path);
    AccountingDiskStorage_.pop_front();
  }
}

AccountingDb::AccountingDb(asyncBase *base, const PoolBackendConfig &config, const CCoinInfo &coinInfo, UserManager &userMgr, CNetworkClientDispatcher &clientDispatcher, StatisticDb &statisticDb) :
  Base_(base),
  _cfg(config),
  CoinInfo_(coinInfo),
  UserManager_(userMgr),
  ClientDispatcher_(clientDispatcher),
  StatisticDb_(statisticDb),
  _roundsDb(config.dbPath / "rounds.v2"),
  _balanceDb(config.dbPath / "balance"),
  _foundBlocksDb(config.dbPath / "foundBlocks"),
  _poolBalanceDb(config.dbPath / "poolBalance"),
  _payoutDb(config.dbPath / "payouts"),
  TaskHandler_(this, base)
{
  FlushTimerEvent_ = newUserEvent(base, 1, nullptr, nullptr);

  int64_t currentTime = time(nullptr);
  FlushInfo_.Time = currentTime;
  FlushInfo_.ShareId = 0;

  {
    // TEMPORARY
    enumerateStatsFiles(AccountingDiskStorage_, config.dbPath / "accounting.storage", true);
  }
  enumerateStatsFiles(AccountingDiskStorage_, config.dbPath / "accounting.storage.2", false);

  while (!AccountingDiskStorage_.empty()) {
    auto &file = AccountingDiskStorage_.back();
    if (parseAccoutingStorageFile(file)) {
      FlushInfo_.Time = file.TimeLabel;
      FlushInfo_.ShareId = file.LastShareId;
      break;
    } else {
      // Remove corrupted file
      std::filesystem::remove(file.Path);
      AccountingDiskStorage_.pop_back();
    }
  }

  {
    unsigned payoutsNum = 0;
    _payoutsFd.open(_cfg.dbPath / "payouts.raw");
    if (!_payoutsFd.isOpened())
      LOG_F(ERROR, "can't open payouts file %s (%s)", (_cfg.dbPath / "payouts.raw").string().c_str(), strerror(errno));

    auto fileSize = _payoutsFd.size();
    if (fileSize > 0) {
      xmstream stream;
      _payoutsFd.read(stream.reserve(fileSize), 0, fileSize);

      stream.seekSet(0);
      while (stream.remaining()) {
        PayoutDbRecord element;
        if (!element.deserializeValue(stream))
          break;
        _payoutQueue.push_back(element);
        KnownTransactions_.insert(element.TransactionId);
        payoutsNum++;
      }
    }

    LOG_F(INFO, "loaded %u payouts from payouts.raw file", payoutsNum);
    if (payoutsNum != _payoutQueue.size())
      updatePayoutFile();
  }

  {
    std::unique_ptr<rocksdbBase::IteratorType> It(_roundsDb.iterator());
    It->seekFirst();
    for (; It->valid(); It->next()) {
      MiningRound *R = new MiningRound;
      RawData data = It->value();
      if (R->deserializeValue(data.data, data.size)) {
        _allRounds.emplace_back(R);
        if (!R->Payouts.empty())
          UnpayedRounds_.insert(R);
      } else {
        LOG_F(ERROR, "rounds db contains invalid record");
        delete R;
      }
    }

    LOG_F(INFO, "loaded %u rounds from db", (unsigned)_allRounds.size());
  }

  {
    std::unique_ptr<rocksdbBase::IteratorType> It(_balanceDb.iterator());
    It->seekFirst();
    for (; It->valid(); It->next()) {
      UserBalanceRecord ub;
      RawData data = It->value();
      if (ub.deserializeValue(data.data, data.size))
        _balanceMap[ub.Login] = ub;
    }

    LOG_F(INFO, "loaded %u user balance data from db", (unsigned)_balanceMap.size());
  }
}

void AccountingDb::enumerateStatsFiles(std::deque<CAccountingFile> &cache, const std::filesystem::path &directory, bool isOldFormat)
{
  std::error_code errc;
  std::filesystem::create_directories(directory, errc);
  for (std::filesystem::directory_iterator I(directory), IE; I != IE; ++I) {
    std::string fileName = I->path().filename().string();
    auto dotDatPos = fileName.find(".dat");
    if (dotDatPos == fileName.npos) {
      LOG_F(ERROR, "AccountingDb: invalid statitic cache file name format: %s", fileName.c_str());
      continue;
    }

    fileName.resize(dotDatPos);

    cache.emplace_back();
    cache.back().Path = *I;
    cache.back().TimeLabel = xatoi<uint64_t>(fileName.c_str());
    cache.back().IsOldFormat = isOldFormat;
  }

  std::sort(cache.begin(), cache.end(), [](const CAccountingFile &l, const CAccountingFile &r){ return l.TimeLabel < r.TimeLabel; });
}

void AccountingDb::start()
{
  TaskHandler_.start();

  coroutineCall(coroutineNewWithCb([](void *arg) {
    AccountingDb *db = static_cast<AccountingDb*>(arg);
    for (;;) {
      if (db->ShutdownRequested_)
        break;
      ioSleep(db->FlushTimerEvent_, std::chrono::microseconds(std::chrono::minutes(1)).count());
      db->flushAccountingStorageFile(time(nullptr));
    }
  }, this, 0x20000, coroutineFinishCb, &FlushFinished_));
}

void AccountingDb::stop()
{
  ShutdownRequested_ = true;
  userEventActivate(FlushTimerEvent_);
  TaskHandler_.stop(CoinInfo_.Name.c_str(), "accounting: task handler");
  coroutineJoin(CoinInfo_.Name.c_str(), "accounting: flush thread", &FlushFinished_);
}

void AccountingDb::updatePayoutFile()
{
  xmstream stream;
  for (auto &p: _payoutQueue)
    p.serializeValue(stream);

  _payoutsFd.write(stream.data(), 0, stream.sizeOf());
  _payoutsFd.truncate(stream.sizeOf());
}

void AccountingDb::cleanupRounds()
{
  time_t timeLabel = time(0) - _cfg.KeepRoundTime;
  auto I = _allRounds.begin();
  while (I != _allRounds.end()) {
    MiningRound *round = I->get();
    if (round->Time >= timeLabel || UnpayedRounds_.count(round))
      break;
    _roundsDb.deleteRow(*round);
    ++I;
  }

  if (I != _allRounds.begin()) {
    LOG_F(INFO, "delete %u old rounds", (unsigned)std::distance(_allRounds.begin(), I));
    _allRounds.erase(_allRounds.begin(), I);
  }
}

bool AccountingDb::hasUnknownReward()
{
  return CoinInfo_.HasDagFile;
}

void AccountingDb::calculatePayments(MiningRound *R, int64_t generatedCoins)
{
  int64_t rationalPartSize = CoinInfo_.RationalPartSize * CoinInfo_.ExtraMultiplier;

  R->AvailableCoins = generatedCoins;
  R->Payouts.clear();

  int64_t totalPayout = 0;
  std::vector<PayoutDbRecord> payouts;
  std::map<std::string, int64_t> feePayouts;
  std::unordered_map<std::string, UserManager::UserFeeConfig> feePlans;
  for (const auto &record: R->UserShares) {
    // Calculate payout
    int64_t payoutValue = static_cast<int64_t>(R->AvailableCoins * (record.shareValue / R->TotalShareValue));

    totalPayout += payoutValue;

    // get fee plan for user
    std::string feePlanId = UserManager_.getFeePlanId(record.userId);
    auto It = feePlans.find(feePlanId);
    if (It == feePlans.end())
      It = feePlans.insert(It, std::make_pair(feePlanId, UserManager_.getFeeRecord(feePlanId, CoinInfo_.Name)));

    UserManager::UserFeeConfig &feeRecord = It->second;

    int64_t feeValuesSum = 0;
    std::vector<int64_t> feeValues;
    for (const auto &poolFeeRecord: feeRecord) {
      int64_t value = static_cast<int64_t>(payoutValue * (poolFeeRecord.Percentage / 100.0));
      feeValues.push_back(value);
      feeValuesSum += value;
    }

    std::string debugString;
    if (feeValuesSum <= payoutValue) {
      for (size_t i = 0, ie = feeRecord.size(); i != ie; ++i) {
        debugString.append(feeRecord[i].UserId);
        debugString.push_back('(');
        debugString.append(FormatMoney(feeValues[i], rationalPartSize));
        debugString.append(") ");
        feePayouts[feeRecord[i].UserId] += feeValues[i];
      }

      payoutValue -= feeValuesSum;
    } else {
      feeValuesSum = 0;
      feeValues.clear();
      debugString = "NONE";
      LOG_F(ERROR, "   * user %s: fee over 100%% can't be applied", record.userId.c_str());
    }

    payouts.emplace_back(record.userId, payoutValue);
    LOG_F(INFO, " * %s %s -> %sremaining %s", record.userId.c_str(), FormatMoney(payoutValue+feeValuesSum, rationalPartSize).c_str(), debugString.c_str(), FormatMoney(payoutValue, rationalPartSize).c_str());
  }

  mergeSorted(payouts.begin(), payouts.end(), feePayouts.begin(), feePayouts.end(),
    [](const PayoutDbRecord &l, const std::pair<std::string, int64_t> &r) { return l.UserId < r.first; },
    [](const std::pair<std::string, int64_t> &l, const PayoutDbRecord &r) { return l.first < r.UserId; },
    [R](const PayoutDbRecord &record) {
      if (record.Value)
        R->Payouts.emplace_back(record);
    }, [R](const std::pair<std::string, int64_t> &fee) {
      if (fee.second)
        R->Payouts.emplace_back(fee.first, fee.second);
    }, [R](const PayoutDbRecord &record, const std::pair<std::string, int64_t> &fee) {
      if (record.Value + fee.second)
        R->Payouts.emplace_back(record.UserId, record.Value + fee.second);
    });

  // Correct payouts for use all available coins
  if (!R->Payouts.empty()) {
    int64_t diff = totalPayout - generatedCoins;
    int64_t div = diff / (int64_t)R->Payouts.size();
    int64_t mv = diff >= 0 ? 1 : -1;
    int64_t mod = (diff > 0 ? diff : -diff) % R->Payouts.size();

    totalPayout = 0;
    int64_t i = 0;
    for (auto I = R->Payouts.begin(), IE = R->Payouts.end(); I != IE; ++I, ++i) {
      I->Value -= div;
      if (i < mod)
        I->Value -= mv;
      totalPayout += I->Value;
      LOG_F(INFO, "   * %s: payout: %s", I->UserId.c_str(), FormatMoney(I->Value, rationalPartSize).c_str());
    }

    LOG_F(INFO, " * total payout (after correct): %s", FormatMoney(totalPayout, rationalPartSize).c_str());
  }
}

void AccountingDb::addShare(const CShare &share)
{
  // increment score
  CurrentScores_[share.userId] += share.WorkValue;
  LastKnownShareId_ = share.UniqueShareId;

  if (share.isBlock) {
    double accumulatedWork = 0.0;
    for (const auto &score: CurrentScores_)
      accumulatedWork += score.second;

    {
      // save to database
      FoundBlockRecord blk;
      blk.Height = share.height;
      blk.Hash = share.hash.c_str();
      blk.Time = time(0);
      blk.AvailableCoins = share.generatedCoins;
      blk.FoundBy = share.userId;
      blk.ExpectedWork = share.ExpectedWork;
      blk.AccumulatedWork = accumulatedWork;
      if (hasUnknownReward())
        blk.PublicHash = "?";
      _foundBlocksDb.put(blk);
    }

    MiningRound *R = new MiningRound;

    int64_t rationalPartSize = CoinInfo_.RationalPartSize * CoinInfo_.ExtraMultiplier;
    int64_t generatedCoins = share.generatedCoins * CoinInfo_.ExtraMultiplier;
    LOG_F(INFO, " * block height: %u, hash: %s, value: %s", (unsigned)share.height, share.hash.c_str(), FormatMoney(generatedCoins, rationalPartSize).c_str());

    R->Height = share.height;
    R->BlockHash = share.hash.c_str();
    R->Time = share.Time;
    R->FoundBy = share.userId;
    R->ExpectedWork = share.ExpectedWork;
    R->AccumulatedWork = accumulatedWork;
    R->TotalShareValue = 0;

    // Merge shares for current block with older shares (PPLNS)
    {
      int64_t acceptSharesTime = share.Time - 1800;
      mergeSorted(RecentStats_.begin(), RecentStats_.end(), CurrentScores_.begin(), CurrentScores_.end(),
        [](const StatisticDb::CStatsExportData &stats, const std::pair<std::string, double> &scores) { return stats.UserId < scores.first; },
        [](const std::pair<std::string, double> &scores, const StatisticDb::CStatsExportData &stats) { return scores.first < stats.UserId; },
        [&](const StatisticDb::CStatsExportData &stats) {
          // User disconnected recently, no new shares
          double shareValue = stats.recentShareValue(acceptSharesTime);
          if (shareValue != 0.0) {
            R->UserShares.emplace_back(stats.UserId, shareValue);
          }
        }, [&](const std::pair<std::string, double> &scores) {
          // User joined recently, no extra shares in statistic
          R->UserShares.emplace_back(scores.first, scores.second);
        }, [&](const StatisticDb::CStatsExportData &stats, const std::pair<std::string, double> &scores) {
          // Need merge new shares and recent share statistics
          R->UserShares.emplace_back(stats.UserId, scores.second + stats.recentShareValue(acceptSharesTime));
        });
    }

    CurrentScores_.clear();

    // Calculate total share value
    for (const auto &element: R->UserShares)
      R->TotalShareValue += element.shareValue;

    // Calculate payments
    if (!hasUnknownReward())
      calculatePayments(R, generatedCoins);

    // store round to DB and clear shares map
    _allRounds.emplace_back(R);
    _roundsDb.put(*R);
    UnpayedRounds_.insert(R);

    // Query statistics
    StatisticDb_.exportRecentStats(RecentStats_);
    printRecentStatistic();

    // Reset aggregated data
    CurrentScores_.clear();

    // Remove old data
    for (const auto &file: AccountingDiskStorage_)
      std::filesystem::remove(file.Path);
    AccountingDiskStorage_.clear();

    // Save recent statistics
    flushAccountingStorageFile(share.Time);
  }
}

void AccountingDb::replayShare(const CShare &share)
{
  if (share.UniqueShareId > FlushInfo_.ShareId) {
    // increment score
    CurrentScores_[share.userId] += share.WorkValue;
  }

  LastKnownShareId_ = std::max(LastKnownShareId_, share.UniqueShareId);
  if (isDebugAccounting()) {
    Dbg_.MinShareId = std::min(Dbg_.MinShareId, share.UniqueShareId);
    Dbg_.MaxShareId = std::max(Dbg_.MaxShareId, share.UniqueShareId);
    if (share.UniqueShareId > FlushInfo_.ShareId)
      Dbg_.Count++;
  }
}

void AccountingDb::initializationFinish(int64_t timeLabel)
{
  printRecentStatistic();

  if (!CurrentScores_.empty()) {
    LOG_F(INFO, "[%s] current scores:", CoinInfo_.Name.c_str());
    for (const auto &It: CurrentScores_) {
      LOG_F(INFO, " * %s: %.3lf", It.first.c_str(), It.second);
    }
  } else {
    LOG_F(INFO, "[%s] current scores is empty", CoinInfo_.Name.c_str());
  }

  if (isDebugStatistic()) {
    LOG_F(1, "initializationFinish: timeLabel: %" PRIu64 "", timeLabel);
    LOG_F(1, "%s: replayed %" PRIu64 " shares from %" PRIu64 " to %" PRIu64 "", CoinInfo_.Name.c_str(), Dbg_.Count, Dbg_.MinShareId, Dbg_.MaxShareId);
  }
}

void AccountingDb::mergeRound(const Round*)
{
}

void AccountingDb::checkBlockConfirmations()
{
  if (UnpayedRounds_.empty())
    return;

  LOG_F(INFO, "Checking %zu blocks for confirmations...", UnpayedRounds_.size());
  std::vector<MiningRound*> rounds(UnpayedRounds_.begin(), UnpayedRounds_.end());

  std::vector<CNetworkClient::GetBlockConfirmationsQuery> confirmationsQuery(rounds.size());
  for (size_t i = 0, ie = rounds.size(); i != ie; ++i) {
    confirmationsQuery[i].Hash = rounds[i]->BlockHash;
    confirmationsQuery[i].Height = rounds[i]->Height;
  }

  if (!ClientDispatcher_.ioGetBlockConfirmations(Base_, _cfg.RequiredConfirmations, confirmationsQuery)) {
    LOG_F(ERROR, "ioGetBlockConfirmations api call failed");
    return;
  }

  for (size_t i = 0; i < confirmationsQuery.size(); i++) {
    MiningRound *R = rounds[i];

    if (confirmationsQuery[i].Confirmations == -1) {
      LOG_F(INFO, "block %" PRIu64 "/%s marked as orphan, can't do any payout", R->Height, confirmationsQuery[i].Hash.c_str());
      R->Payouts.clear();
      UnpayedRounds_.erase(R);
      _roundsDb.put(*R);
    } else if (confirmationsQuery[i].Confirmations >= _cfg.RequiredConfirmations) {
      LOG_F(INFO, "Make payout for block %" PRIu64 "/%s", R->Height, R->BlockHash.c_str());
      for (auto I = R->Payouts.begin(), IE = R->Payouts.end(); I != IE; ++I) {
        requestPayout(I->UserId, I->Value);
      }

      R->Payouts.clear();

      UnpayedRounds_.erase(R);
      _roundsDb.put(*R);
    }
  }

  updatePayoutFile();
}

void AccountingDb::checkBlockExtraInfo()
{
  if (UnpayedRounds_.empty())
    return;

  LOG_F(INFO, "Checking %zu blocks for extra info...", UnpayedRounds_.size());
  std::vector<MiningRound*> unpayedRounds(UnpayedRounds_.begin(), UnpayedRounds_.end());

  std::vector<CNetworkClient::GetBlockExtraInfoQuery> confirmationsQuery;
  for (const auto &round: unpayedRounds)
    confirmationsQuery.emplace_back(round->BlockHash, round->Height, round->TxFee, round->AvailableCoins);

  if (!ClientDispatcher_.ioGetBlockExtraInfo(Base_, _cfg.RequiredConfirmations, confirmationsQuery)) {
    LOG_F(ERROR, "ioGetBlockExtraInfo api call failed");
    return;
  }

  for (size_t i = 0; i < confirmationsQuery.size(); i++) {
    MiningRound *R = unpayedRounds[i];

    if (R->AvailableCoins != confirmationsQuery[i].BlockReward) {
      // Update found block database
      FoundBlockRecord blk;
      blk.Height = R->Height;
      blk.Hash = R->BlockHash;
      blk.Time = R->Time;
      blk.AvailableCoins = confirmationsQuery[i].BlockReward;
      blk.FoundBy = R->FoundBy;
      blk.ExpectedWork = R->ExpectedWork;
      blk.AccumulatedWork = R->AccumulatedWork;
      blk.PublicHash = confirmationsQuery[i].PublicHash;
      _foundBlocksDb.put(blk);

      // Update payment info
      R->TxFee = confirmationsQuery[i].TxFee;
      calculatePayments(R, confirmationsQuery[i].BlockReward);
      _roundsDb.put(*R);
    }

    if (confirmationsQuery[i].Confirmations == -1) {
      LOG_F(INFO, "block %" PRIu64 "/%s marked as orphan, can't do any payout", R->Height, confirmationsQuery[i].Hash.c_str());
      R->Payouts.clear();
      UnpayedRounds_.erase(R);
      _roundsDb.put(*R);
    } else if (confirmationsQuery[i].Confirmations >= _cfg.RequiredConfirmations) {
      LOG_F(INFO, "Make payout for block %" PRIu64 "/%s", R->Height, R->BlockHash.c_str());
      for (auto I = R->Payouts.begin(), IE = R->Payouts.end(); I != IE; ++I) {
        requestPayout(I->UserId, I->Value);
      }

      R->Payouts.clear();

      UnpayedRounds_.erase(R);
      _roundsDb.put(*R);
    }
  }

  updatePayoutFile();
}

void AccountingDb::buildTransaction(PayoutDbRecord &payout, unsigned index, std::string &recipient, bool *needSkipPayout)
{
  *needSkipPayout = false;
  if (payout.Value < _cfg.MinimalAllowedPayout) {
    LOG_F(INFO,
          "[%u] Accounting: ignore this payout to %s, value is %s, minimal is %s",
          index,
          payout.UserId.c_str(),
          FormatMoney(payout.Value, CoinInfo_.RationalPartSize).c_str(),
          FormatMoney(_cfg.MinimalAllowedPayout, CoinInfo_.RationalPartSize).c_str());
    *needSkipPayout = true;
    return;
  }

  // Get address for payment
  UserSettingsRecord settings;
  bool hasSettings = UserManager_.getUserCoinSettings(payout.UserId, CoinInfo_.Name, settings);
  if (!hasSettings || settings.Address.empty()) {
    LOG_F(WARNING, "user %s did not setup payout address, ignoring", payout.UserId.c_str());
    *needSkipPayout = true;
    return;
  }

  recipient = settings.Address;
  if (!CoinInfo_.checkAddress(settings.Address, CoinInfo_.PayoutAddressType)) {
    LOG_F(ERROR, "Invalid payment address %s for %s", settings.Address.c_str(), payout.UserId.c_str());
    *needSkipPayout = true;
    return;
  }

  // Build transaction
  // For bitcoin-based API it's sequential call of createrawtransaction, fundrawtransaction and signrawtransaction
  CNetworkClient::BuildTransactionResult transaction;
  CNetworkClient::EOperationStatus status =
    ClientDispatcher_.ioBuildTransaction(Base_, settings.Address.c_str(), _cfg.MiningAddresses.get().MiningAddress, payout.Value, transaction);
  if (status == CNetworkClient::EStatusOk) {
    // Nothing to do
  } else if (status == CNetworkClient::EStatusInsufficientFunds) {
    LOG_F(INFO, "No money left to pay");
    return;
  } else {
    LOG_F(ERROR, "Payment %s to %s failed with error \"%s\"", FormatMoney(payout.Value, CoinInfo_.RationalPartSize).c_str(), settings.Address.c_str(), transaction.Error.c_str());
    return;
  }

  int64_t delta = payout.Value - (transaction.Value + transaction.Fee);
  if (delta > 0) {
    // Correct payout value and request balance
    payout.Value -= delta;

    // Update user balance
    auto It = _balanceMap.find(payout.UserId);
    if (It == _balanceMap.end()) {
      LOG_F(ERROR, "payout to unknown address %s", payout.UserId.c_str());
      return;
    }

    LOG_F(INFO, "   * correct requested balance for %s by %s", payout.UserId.c_str(), FormatMoney(delta, CoinInfo_.RationalPartSize).c_str());
    UserBalanceRecord &balance = It->second;
    balance.Requested -= delta;
    _balanceDb.put(balance);
  } else if (delta < 0) {
    LOG_F(ERROR, "Payment %s to %s failed: too big transaction amount", FormatMoney(payout.Value, CoinInfo_.RationalPartSize).c_str(), settings.Address.c_str());
    return;
  }

  // Save transaction to database
  if (!KnownTransactions_.insert(transaction.TxId).second) {
    LOG_F(ERROR, "Node generated duplicate for transaction %s !!!", transaction.TxId.c_str());
    return;
  }

  payout.TransactionData = transaction.TxData;
  payout.TransactionId = transaction.TxId;
  payout.Time = time(nullptr);
  payout.Status = PayoutDbRecord::ETxCreated;
  _payoutDb.put(payout);
}

bool AccountingDb::sendTransaction(PayoutDbRecord &payout)
{
  // Send transaction and change it status to 'Sent'
  // For bitcoin-based API it's 'sendrawtransaction'
  std::string error;
  CNetworkClient::EOperationStatus status = ClientDispatcher_.ioSendTransaction(Base_, payout.TransactionData, payout.TransactionId, error);
  if (status == CNetworkClient::EStatusOk) {
    // Nothing to do
  } else if (status == CNetworkClient::EStatusVerifyRejected) {
    // Sending failed, transaction is rejected
    LOG_F(ERROR, "Transaction %s to %s marked as rejected, removing from database...", payout.TransactionId.c_str(), payout.UserId.c_str());

    // Update transaction in database
    payout.Status = PayoutDbRecord::ETxRejected;
    _payoutDb.put(payout);

    // Clear all data and re-schedule payout
    payout.TransactionId.clear();
    payout.TransactionData.clear();
    payout.Status = PayoutDbRecord::EInitialized;
    return false;
  } else {
    LOG_F(WARNING, "Sending transaction %s to %s error \"%s\", will try send later...", payout.TransactionId.c_str(), payout.UserId.c_str(), error.c_str());
    return false;
  }

  payout.Status = PayoutDbRecord::ETxSent;
  _payoutDb.put(payout);
  return true;
}

bool AccountingDb::checkTxConfirmations(PayoutDbRecord &payout)
{
  int64_t confirmations = 0;
  std::string error;
  CNetworkClient::EOperationStatus status = ClientDispatcher_.ioGetTxConfirmations(Base_, payout.TransactionId, &confirmations, &payout.TxFee, error);
  if (status == CNetworkClient::EStatusOk) {
    // Nothing to do
  } else if (status == CNetworkClient::EStatusInvalidAddressOrKey) {
    // Wallet don't know about this transaction
    payout.Status = PayoutDbRecord::ETxCreated;
  } else if (status == CNetworkClient::EStatusVerifyRejected) {
    // Sending failed, transaction is rejected
    LOG_F(ERROR, "Transaction %s to %s marked as rejected, removing from database...", payout.TransactionId.c_str(), payout.UserId.c_str());

    // Update transaction in database
    payout.Status = PayoutDbRecord::ETxRejected;
    _payoutDb.put(payout);

    // Clear all data and re-schedule payout
    payout.TransactionId.clear();
    payout.TransactionData.clear();
    payout.Status = PayoutDbRecord::EInitialized;
    return false;
  } else {
    LOG_F(WARNING, "Checking transaction %s to %s error \"%s\", will do it later...", payout.TransactionId.c_str(), payout.UserId.c_str(), error.c_str());
    return false;
  }

  // Update database
  if (confirmations > _cfg.RequiredConfirmations) {
    payout.Status = PayoutDbRecord::ETxConfirmed;
    _payoutDb.put(payout);

    // Update user balance
    auto It = _balanceMap.find(payout.UserId);
    if (It == _balanceMap.end()) {
      LOG_F(ERROR, "payout to unknown address %s", payout.UserId.c_str());
      return false;
    }

    UserBalanceRecord &balance = It->second;
    balance.Balance.subRational(payout.Value + payout.TxFee, CoinInfo_.ExtraMultiplier);
    balance.Requested -= payout.Value;
    balance.Paid += payout.Value;
    _balanceDb.put(balance);
    return true;
  }

  return false;
}

void AccountingDb::makePayout()
{
  if (!_payoutQueue.empty()) {
    LOG_F(INFO, "Accounting: checking %u payout requests...", (unsigned)_payoutQueue.size());

    // Merge small payouts and payouts to invalid address
    {
      std::map<std::string, int64_t> payoutAccMap;
      for (auto I = _payoutQueue.begin(), IE = _payoutQueue.end(); I != IE;) {
        if (I->Status != PayoutDbRecord::EInitialized) {
          ++I;
          continue;
        }

        if (I->Value < _cfg.MinimalAllowedPayout) {
          payoutAccMap[I->UserId] += I->Value;
          LOG_F(INFO,
                "Accounting: merge payout %s for %s (total already %s)",
                FormatMoney(I->Value, CoinInfo_.RationalPartSize).c_str(),
                I->UserId.c_str(),
                FormatMoney(payoutAccMap[I->UserId], CoinInfo_.RationalPartSize).c_str());
          _payoutQueue.erase(I++);
        } else {
          ++I;
        }
      }

      for (const auto &I: payoutAccMap)
        _payoutQueue.push_back(PayoutDbRecord(I.first, I.second));
    }

    unsigned index = 0;
    for (auto &payout: _payoutQueue) {
      if (payout.Status == PayoutDbRecord::EInitialized) {
        // Build transaction
        // For bitcoin-based API it's sequential call of createrawtransaction, fundrawtransaction and signrawtransaction
        bool needSkipPayout;
        std::string recipientAddress;
        buildTransaction(payout, index, recipientAddress, &needSkipPayout);
        if (needSkipPayout)
          continue;

        if (payout.Status == PayoutDbRecord::ETxCreated) {
          // Send transaction and change it status to 'Sent'
          // For bitcoin-based API it's 'sendrawtransaction'
          if (sendTransaction(payout))
            LOG_F(INFO, " * sent %s to %s(%s) with txid %s", FormatMoney(payout.Value, CoinInfo_.RationalPartSize).c_str(), payout.UserId.c_str(), recipientAddress.c_str(), payout.TransactionId.c_str());
        } else {
          break;
        }
      } else if (payout.Status == PayoutDbRecord::ETxCreated) {
        // Resend transaction
        if (sendTransaction(payout))
          LOG_F(INFO, " * retry send txid %s to %s", payout.TransactionId.c_str(), payout.UserId.c_str());
      } else if (payout.Status == PayoutDbRecord::ETxSent) {
        // Check confirmations
        if (checkTxConfirmations(payout))
          LOG_F(INFO, " * transaction txid %s to %s confirmed", payout.TransactionId.c_str(), payout.UserId.c_str());
      } else {
        // Invalid status
      }
    }

    // Cleanup confirmed payouts
    for (auto I = _payoutQueue.begin(), IE = _payoutQueue.end(); I != IE;) {
      if (I->Status == PayoutDbRecord::ETxConfirmed) {
        KnownTransactions_.erase(I->TransactionId);
        _payoutQueue.erase(I++);
      } else {
        ++I;
      }
    }

    updatePayoutFile();
  }

  if (!_cfg.poolZAddr.empty() && !_cfg.poolTAddr.empty()) {
    // move all to Z-Addr
    CNetworkClient::ListUnspentResult unspent;
    if (ClientDispatcher_.ioListUnspent(Base_, unspent) == CNetworkClient::EStatusOk && !unspent.Outs.empty()) {
      std::unordered_map<std::string, int64_t> coinbaseFunds;
      for (const auto &out: unspent.Outs) {
        if (out.IsCoinbase)
          coinbaseFunds[out.Address] += out.Amount;
      }

      for (const auto &out: coinbaseFunds) {
        if (out.second < ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE)
          continue;

        CNetworkClient::ZSendMoneyResult zsendResult;
        CNetworkClient::EOperationStatus status = ClientDispatcher_.ioZSendMoney(Base_, out.first, _cfg.poolZAddr, out.second, "", 1, 0, zsendResult);
        if (status == CNetworkClient::EStatusOk && !zsendResult.AsyncOperationId.empty()) {
          LOG_F(INFO,
                " * moving %s coins from %s to %s started (%s)",
                FormatMoney(out.second, CoinInfo_.RationalPartSize).c_str(),
                out.first.c_str(),
                _cfg.poolZAddr.c_str(),
                zsendResult.AsyncOperationId.c_str());
        } else {
          LOG_F(INFO,
                " * async operation start error %s: source=%s, destination=%s, amount=%s",
                !zsendResult.Error.empty() ? zsendResult.Error.c_str() : "<unknown error>",
                out.first.c_str(),
                _cfg.poolZAddr.c_str(),
                FormatMoney(out.second, CoinInfo_.RationalPartSize).c_str());
        }
      }
    }

    // move Z-Addr to T-Addr
    int64_t zbalance;
    if (ClientDispatcher_.ioZGetBalance(Base_, _cfg.poolZAddr, &zbalance) == CNetworkClient::EStatusOk && zbalance > 0) {
      LOG_F(INFO, "Accounting: move %s coins to transparent address", FormatMoney(zbalance, CoinInfo_.RationalPartSize).c_str());
      CNetworkClient::ZSendMoneyResult zsendResult;
      if (ClientDispatcher_.ioZSendMoney(Base_, _cfg.poolZAddr, _cfg.poolTAddr, zbalance, "", 1, 0, zsendResult) == CNetworkClient::EStatusOk) {
        LOG_F(INFO,
              "moving %s coins from %s to %s started (%s)",
              FormatMoney(zbalance, CoinInfo_.RationalPartSize).c_str(),
              _cfg.poolZAddr.c_str(),
              _cfg.poolTAddr.c_str(),
              !zsendResult.AsyncOperationId.empty() ? zsendResult.AsyncOperationId.c_str() : "<none>");
      }
    }
  }

  // Check consistency
  bool needRebuild = false;
  std::unordered_map<std::string, int64_t> enqueued;
  for (const auto &payout: _payoutQueue)
    enqueued[payout.UserId] += payout.Value;

  for (auto &userIt: _balanceMap) {
    int64_t enqueuedBalance = enqueued[userIt.first];
    if (userIt.second.Requested != enqueuedBalance) {
      LOG_F(ERROR,
            "User %s: enqueued: %s, control sum: %s",
            userIt.first.c_str(),
            FormatMoney(enqueuedBalance, CoinInfo_.RationalPartSize).c_str(),
            FormatMoney(userIt.second.Requested, CoinInfo_.RationalPartSize).c_str());
    }
  }

  if (needRebuild)
    LOG_F(ERROR, "Payout database inconsistent, restart pool for rebuild recommended");

  // Make a service after every payment session
  {
    std::string serviceError;
    if (ClientDispatcher_.ioWalletService(Base_, serviceError) != CNetworkClient::EStatusOk)
      LOG_F(ERROR, "Wallet service ERROR: %s", serviceError.c_str());
  }
}

void AccountingDb::checkBalance()
{
  int64_t balance = 0;
  int64_t requestedInBalance = 0;
  int64_t requestedInQueue = 0;
  int64_t confirmationWait = 0;
  int64_t immature = 0;
  int64_t userBalance = 0;
  int64_t queued = 0;
  int64_t net = 0;

  int64_t zbalance = 0;
  if (!_cfg.poolZAddr.empty()) {
    if (ClientDispatcher_.ioZGetBalance(Base_, _cfg.poolZAddr, &zbalance) != CNetworkClient::EStatusOk) {
      LOG_F(ERROR, "can't get balance of Z-address %s", _cfg.poolZAddr.c_str());
      return;
    }
  }

  CNetworkClient::GetBalanceResult getBalanceResult;
  if (!ClientDispatcher_.ioGetBalance(Base_, getBalanceResult)) {
    LOG_F(ERROR, "can't retrieve balance");
    return;
  }

  balance = getBalanceResult.Balance + zbalance;
  immature = getBalanceResult.Immatured;

  for (auto &userIt: _balanceMap) {
    userBalance += userIt.second.Balance.get();
    requestedInBalance += userIt.second.Requested;
  }
  userBalance /= CoinInfo_.ExtraMultiplier;

  for (auto &p: _payoutQueue) {
    requestedInQueue += p.Value;
    if (p.Status == PayoutDbRecord::ETxSent)
      confirmationWait += p.Value + p.TxFee;
  }

  for (auto &roundIt: UnpayedRounds_) {
    for (auto &pIt: roundIt->Payouts)
      queued += pIt.Value;
  }
  queued /= CoinInfo_.ExtraMultiplier;

  net = balance + immature - userBalance - queued + confirmationWait;

  {
    PoolBalanceRecord pb;
    pb.Time = time(0);
    pb.Balance = balance;
    pb.Immature = immature;
    pb.Users = userBalance;
    pb.Queued = queued;
    pb.ConfirmationWait = confirmationWait;
    pb.Net = net;
    _poolBalanceDb.put(pb);
  }

  LOG_F(INFO,
        "accounting: balance=%s req/balance=%s req/queue=%s immature=%s users=%s queued=%s, confwait=%s, net=%s",
        FormatMoney(balance, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(requestedInBalance, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(requestedInQueue, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(immature, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(userBalance, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(queued, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(confirmationWait, CoinInfo_.RationalPartSize).c_str(),
        FormatMoney(net, CoinInfo_.RationalPartSize).c_str());
}

bool AccountingDb::requestPayout(const std::string &address, int64_t value, bool force)
{
  bool result = false;
  auto It = _balanceMap.find(address);
  if (It == _balanceMap.end())
    It = _balanceMap.insert(It, std::make_pair(address, UserBalanceRecord(address, _cfg.DefaultPayoutThreshold)));

  UserBalanceRecord &balance = It->second;
  balance.Balance.add(value);

  UserSettingsRecord settings;
  bool hasSettings = UserManager_.getUserCoinSettings(balance.Login, CoinInfo_.Name, settings);
  int64_t nonQueuedBalance = balance.Balance.getRational(CoinInfo_.ExtraMultiplier) - balance.Requested;
  if (hasSettings && (force || (settings.AutoPayout && nonQueuedBalance >= settings.MinimalPayout))) {
    _payoutQueue.push_back(PayoutDbRecord(address, nonQueuedBalance));
    balance.Requested += nonQueuedBalance;
    result = true;
  }

  _balanceDb.put(balance);
  return result;
}

void AccountingDb::manualPayoutImpl(const std::string &user, DefaultCb callback)
{
  auto It = _balanceMap.find(user);
  if (It != _balanceMap.end()) {
    auto &B = It->second;
    int64_t nonQueuedBalance = B.Balance.getRational(CoinInfo_.ExtraMultiplier) - B.Requested;
    if (nonQueuedBalance >= _cfg.MinimalAllowedPayout) {
      bool result = requestPayout(user, 0, true);
      const char *status = result ? "ok" : "payout_error";
      if (result) {
        LOG_F(INFO, "Manual payout success for %s", user.c_str());
        updatePayoutFile();
      }
      callback(status);
      return;
    } else {
      callback("insufficient_balance");
      return;
    }
  } else {
    callback("no_balance");
    return;
  }
}

void AccountingDb::queryFoundBlocksImpl(int64_t heightFrom, const std::string &hashFrom, uint32_t count, QueryFoundBlocksCallback callback)
{
  auto &db = getFoundBlocksDb();
  std::unique_ptr<rocksdbBase::IteratorType> It(db.iterator());
  if (heightFrom != -1) {
    FoundBlockRecord blk;
    blk.Height = heightFrom;
    blk.Hash = hashFrom;
    It->seek(blk);
    It->prev();
  } else {
    It->seekLast();
  }

  std::vector<CNetworkClient::GetBlockConfirmationsQuery> confirmationsQuery;
  std::vector<FoundBlockRecord> foundBlocks;
  for (unsigned i = 0; i < count && It->valid(); i++) {
    FoundBlockRecord dbBlock;
    RawData data = It->value();
    if (!dbBlock.deserializeValue(data.data, data.size))
      break;

    // Replace login with public name
    UserManager::Credentials credentials;
    if (UserManager_.getUserCredentials(dbBlock.FoundBy, credentials) && !credentials.Name.empty())
      dbBlock.FoundBy = credentials.Name;

    foundBlocks.push_back(dbBlock);
    confirmationsQuery.emplace_back(dbBlock.Hash, dbBlock.Height);
    It->prev();
  }

  // query confirmations
  if (count)
    ClientDispatcher_.ioGetBlockConfirmations(Base_, _cfg.RequiredConfirmations, confirmationsQuery);

  callback(foundBlocks, confirmationsQuery);
}

void AccountingDb::poolLuckImpl(const std::vector<int64_t> &intervals, PoolLuckCallback callback)
{
  int64_t currentTime = time(nullptr);
  std::vector<double> result;

  auto &db = getFoundBlocksDb();
  std::unique_ptr<rocksdbBase::IteratorType> It(db.iterator());
  It->seekLast();

  auto intervalIt = intervals.begin();
  if (intervalIt == intervals.end()) {
    callback(result);
    return;
  }

  double acceptedWork = 0.0;
  double expectedWork = 0.0;
  for (const auto &score: CurrentScores_)
    acceptedWork += score.second;

  int64_t currentTimePoint = currentTime - *intervalIt;
  while (It->valid()) {
    FoundBlockRecord dbBlock;
    RawData data = It->value();
    if (!dbBlock.deserializeValue(data.data, data.size))
      break;

    while (dbBlock.Time < currentTimePoint) {
      result.push_back(expectedWork != 0.0 ? acceptedWork / expectedWork : 0.0);
      if (++intervalIt == intervals.end()) {
        callback(result);
        return;
      }

      currentTimePoint = currentTime - *intervalIt;
    }

    if (dbBlock.ExpectedWork != 0.0) {
      acceptedWork += dbBlock.AccumulatedWork;
      expectedWork += dbBlock.ExpectedWork;
    }

    It->prev();
  }

  while (intervalIt++ != intervals.end())
    result.push_back(expectedWork != 0.0 ? acceptedWork / expectedWork : 0.0);
  callback(result);
}

void AccountingDb::queryBalanceImpl(const std::string &user, QueryBalanceCallback callback)
{
  UserBalanceInfo info;

  // Calculate queued balance
  info.Queued = 0;
  for (const auto &It: UnpayedRounds_) {
    auto payout = std::lower_bound(It->Payouts.begin(), It->Payouts.end(), user, [](const PayoutDbRecord &record, const std::string &user) -> bool { return record.UserId < user; });
    if (payout != It->Payouts.end() && payout->UserId == user)
      info.Queued += payout->Value;
  }
  info.Queued /= CoinInfo_.ExtraMultiplier;

  auto &balanceMap = getUserBalanceMap();
  auto It = balanceMap.find(user);
  if (It != balanceMap.end()) {
    info.Data = It->second;
  } else {
    UserBalanceRecord record;
    info.Data.Login = user;
    info.Data.Balance = 0;
    info.Data.Requested = 0;
    info.Data.Paid = 0;
  }

  callback(info);
}
