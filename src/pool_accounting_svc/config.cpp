#include "config.h"

static inline void setErrorDescription(EErrorType error, EErrorType *errorAcc, const std::string &place, const char *name, const char *requiredType, std::string &errorDescription)
{
  *errorAcc = error;
  if (error == ENotExists) {
    errorDescription = (std::string)"Required parameter '" + name + "' does not exists at " + place;
  } else if (error == ETypeMismatch) {
    errorDescription = (std::string)"Type mismatch: parameter '" + place + " -> " + name + "' must be a " + requiredType;
  }
}

static inline void jsonParseString(const rapidjson::Value &value, const char *name, std::string &out, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsString())
      out = value[name].GetString();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "string", errorDescription);
  } else {
    setErrorDescription(ENotExists, validAcc, place, name, "string", errorDescription);
  }
}

static inline void jsonParseString(const rapidjson::Value &value, const char *name, std::string &out, const std::string &defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsString())
      out = value[name].GetString();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "string", errorDescription);
  } else {
    out = defaultValue;
  }
}

static inline void jsonParseBoolean(const rapidjson::Value &value, const char *name, bool *out, bool defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsBool())
      *out = value[name].GetBool();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "boolean", errorDescription);
  } else {
    *out = defaultValue;
  }
}

static inline void jsonParseUInt(const rapidjson::Value &value, const char *name, unsigned *out, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsUint())
      *out = value[name].GetUint();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "unsigned integer", errorDescription);
  } else {
    setErrorDescription(ENotExists, validAcc, place, name, "unsigned integer", errorDescription);
  }
}

static inline void jsonParseUInt(const rapidjson::Value &value, const char *name, unsigned *out, unsigned defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsUint())
      *out = value[name].GetUint();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "unsigned integer", errorDescription);
  } else {
    *out = defaultValue;
  }
}

static inline void jsonParseDouble(const rapidjson::Value &value, const char *name, double *out, double defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsFloat())
      *out = value[name].GetDouble();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "floating point number (like 1.0)", errorDescription);
  } else {
    *out = defaultValue;
  }
}

void CNodeConfig::load(const rapidjson::Value &value, const std::string &path, std::string &errorDescription, EErrorType *error)
{
  std::string localPath = path + " -> nodes";
  jsonParseString(value, "type", Type, error, localPath, errorDescription);
  jsonParseString(value, "address", Address, error, localPath, errorDescription);
  jsonParseString(value, "login", Login, "", error, localPath, errorDescription);
  jsonParseString(value, "password", Password, "", error, localPath, errorDescription);
  jsonParseBoolean(value, "longPollEnabled", &LongPollEnabled, true, error, localPath, errorDescription);
}

bool CCoinConfig::load(const rapidjson::Value &value, std::string &errorDescription)
{
  EErrorType error = EOk;

  jsonParseString(value, "name", Name, &error, "coins", errorDescription);

  // Parse nodes
  std::string localPath = (std::string)"coins" + " -> " + Name;
  jsonParseString(value, "dbPath", DbPath, &error, localPath, errorDescription);

  if (!value.HasMember("getWorkNodes")) {
    setErrorDescription(ENotExists, &error, localPath, "getWorkNodes", "array of objects", errorDescription);
    return false;
  }
  if (!value["getWorkNodes"].IsArray()) {
    setErrorDescription(ETypeMismatch, &error, localPath, "getWorkNodes", "array of objects", errorDescription);
    return false;
  }
  if (!value.HasMember("RPCNodes")) {
    setErrorDescription(ENotExists, &error, localPath, "RPCNodes", "array of objects", errorDescription);
    return false;
  }
  if (!value["RPCNodes"].IsArray()) {
    setErrorDescription(ETypeMismatch, &error, localPath, "RPCNodes", "array of objects", errorDescription);
    return false;
  }

  {
    auto array = value["getWorkNodes"].GetArray();
    GetWorkNodes.resize(array.Size());
    for (rapidjson::SizeType i = 0, ie = array.Size(); i != ie; ++i)
      GetWorkNodes[i].load(array[i], localPath, errorDescription, &error);
  }

  {
    auto array = value["RPCNodes"].GetArray();
    RPCNodes.resize(array.Size());
    for (rapidjson::SizeType i = 0, ie = array.Size(); i != ie; ++i)
      RPCNodes[i].load(array[i], localPath, errorDescription, &error);
  }

  jsonParseUInt(value, "requiredConfirmations", &RequiredConfirmations, &error, localPath, errorDescription);
  jsonParseString(value, "defaultPayoutThreshold", DefaultPayoutThreshold, &error, localPath, errorDescription);
  jsonParseString(value, "minimalAllowedPayout", MinimalAllowedPayout, &error, localPath, errorDescription);
  jsonParseUInt(value, "keepRoundTime", &KeepRoundTime, &error, localPath, errorDescription);
  jsonParseUInt(value, "keepStatsTime", &KeepStatsTime, &error, localPath, errorDescription);
  jsonParseUInt(value, "confirmationsCheckInterval", &ConfirmationsCheckInterval, &error, localPath, errorDescription);
  jsonParseUInt(value, "payoutInterval", &PayoutInterval, &error, localPath, errorDescription);
  jsonParseUInt(value, "balanceCheckInterval", &BalanceCheckInterval, &error, localPath, errorDescription);
  jsonParseUInt(value, "statisticCheckInterval", &StatisticCheckInterval, &error, localPath, errorDescription);
  jsonParseUInt(value, "shareTarget", &ShareTarget, &error, localPath, errorDescription);
  jsonParseUInt(value, "stratumWorkLifeTime", &StratumWorkLifeTime, 0, &error, localPath, errorDescription);
  if (!value.HasMember("miningAddresses") || !value["miningAddresses"].IsArray()) {
    setErrorDescription(ETypeMismatch, &error, localPath, "miningAddress", "array of objects", errorDescription);
    return false;
  }

  {
    auto array = value["miningAddresses"].GetArray();
    MiningAddresses.resize(array.Size());
    for (rapidjson::SizeType i = 0, ie = array.Size(); i != ie; ++i) {
      jsonParseString(array[i], "address", MiningAddresses[i].Address, &error, localPath + " -> miningAddresses", errorDescription);
      jsonParseString(array[i], "privateKey", MiningAddresses[i].PrivateKey, "", &error, localPath + " -> privateKey", errorDescription);
      jsonParseUInt(array[i], "weight", &MiningAddresses[i].Weight, &error, localPath + " -> miningAddresses", errorDescription);
    }
  }

  jsonParseString(value, "coinbaseMsg", CoinbaseMsg, "", &error, localPath, errorDescription);
  jsonParseDouble(value, "profitSwitchCoeff", &ProfitSwitchCoeff, 0.0, &error, localPath, errorDescription);

  // ZEC specific
  jsonParseString(value, "pool_zaddr", PoolZAddr, "", &error, localPath, errorDescription);
  jsonParseString(value, "pool_taddr", PoolTAddr, "", &error, localPath, errorDescription);
  return error == EOk;
}
