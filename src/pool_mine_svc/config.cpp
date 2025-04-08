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

static inline void jsonParseStringArray(const rapidjson::Value &value, const char *name, std::vector<std::string> &out, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsArray()) {
      rapidjson::Value::ConstArray array = value[name].GetArray();
      for (rapidjson::SizeType i = 0; i < array.Size(); i++) {
        if (!array[i].IsString()) {
          setErrorDescription(ETypeMismatch, validAcc, place, name, "array of string", errorDescription);
          break;
        }

        out.emplace_back(array[i].GetString());
      }
    } else {
      setErrorDescription(ETypeMismatch, validAcc, place, name, "array of string", errorDescription);
    }
  } else {
    setErrorDescription(ENotExists, validAcc, place, name, "array of string", errorDescription);
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

void CNodeConfig::load(const rapidjson::Value &value, const std::string &path, std::string &errorDescription, EErrorType *error)
{
  std::string localPath = path + " -> nodes";
  jsonParseString(value, "type", Type, error, localPath, errorDescription);
  jsonParseString(value, "address", Address, error, localPath, errorDescription);
  jsonParseString(value, "login", Login, "", error, localPath, errorDescription);
  jsonParseString(value, "password", Password, "", error, localPath, errorDescription);
  jsonParseBoolean(value, "longPollEnabled", &LongPollEnabled, true, error, localPath, errorDescription);
}

void CCoinConfig::load(const rapidjson::Value &value, std::string &errorDescription, EErrorType *error)
{
  jsonParseString(value, "name", Name, error, "coins", errorDescription);

  // Parse nodes
  std::string localPath = (std::string)"coins" + " -> " + Name;
  if (!value.HasMember("getWorkNodes")) {
    setErrorDescription(ENotExists, error, localPath, "getWorkNodes", "array of objects", errorDescription);
    return;
  }
  if (!value["getWorkNodes"].IsArray()) {
    setErrorDescription(ETypeMismatch, error, localPath, "getWorkNodes", "array of objects", errorDescription);
    return;
  }
  {
    auto array = value["getWorkNodes"].GetArray();
    GetWorkNodes.resize(array.Size());
    for (rapidjson::SizeType i = 0, ie = array.Size(); i != ie; ++i)
      GetWorkNodes[i].load(array[i], localPath, errorDescription, error);
  }

  if (!value.HasMember("miningAddresses") || !value["miningAddresses"].IsArray()) {
    setErrorDescription(ETypeMismatch, error, localPath, "miningAddress", "array of objects", errorDescription);
    return;
  }

  {
    auto array = value["miningAddresses"].GetArray();
    MiningAddresses.resize(array.Size());
    for (rapidjson::SizeType i = 0, ie = array.Size(); i != ie; ++i) {
      jsonParseString(array[i], "address", MiningAddresses[i].Address, error, localPath + " -> miningAddresses", errorDescription);
      jsonParseUInt(array[i], "weight", &MiningAddresses[i].Weight, error, localPath + " -> miningAddresses", errorDescription);
    }
  }

  jsonParseString(value, "coinbaseMsg", CoinbaseMsg, "", error, localPath, errorDescription);
}

bool CConfig::load(rapidjson::Document &value, std::string &errorDescription)
{
  InstanceConfig = rapidjson::Value(value, value.GetAllocator());

  EErrorType error = EOk;
  std::string localPath = "root";
  jsonParseString(value, "name", Name, &error, localPath, errorDescription);
  jsonParseString(value, "uniqueId", UniqueId, &error, localPath, errorDescription);
  jsonParseString(value, "dbPath", DbPath, &error, localPath, errorDescription);
  jsonParseString(value, "type", Type, &error, localPath, errorDescription);
  jsonParseString(value, "protocol", Protocol, &error, localPath, errorDescription);
  jsonParseStringArray(value, "backends", Backends, &error, localPath, errorDescription);
  jsonParseUInt(value, "port", &Port, 0, &error, localPath, errorDescription);

  if (Protocol == "stratum") {
    if (value.HasMember("shareDiff")) {
      if (value["shareDiff"].IsUint64()) {
        StratumShareDiff = static_cast<double>(value["shareDiff"].GetUint64());
      } else if (value["shareDiff"].IsDouble()) {
        StratumShareDiff = value["shareDiff"].GetDouble();
      } else {
        StratumShareDiff = 0.0;
      }
    }
  }

  jsonParseUInt(value, "workerThreadsNum", &WorkerThreadsNum, 0, &error, localPath, errorDescription);

  // coins
  if (!value.HasMember("coins")) {
    setErrorDescription(ENotExists, &error, ".", "coins", "array of objects", errorDescription);
    return false;
  }
  if (!value["coins"].IsArray()) {
    setErrorDescription(ETypeMismatch, &error, ".", "coins", "array of objects", errorDescription);
    return false;
  }
  {
    auto array = value["coins"].GetArray();
    Coins.resize(array.Size());
    for (rapidjson::SizeType i = 0, ie = array.Size(); i != ie; ++i)
      Coins[i].load(array[i], errorDescription, &error);
  }

  return error == EOk;
}
