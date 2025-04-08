#include "http.h"
#include "poolcommon/utils.h"
#include "poolcore/thread.h"
#include "asyncio/coroutine.h"
#include "asyncio/socket.h"
#include "loguru.hpp"
#include "rapidjson/document.h"
#include "poolcommon/jsonSerializer.h"

std::unordered_map<std::string, std::pair<int, PoolHttpConnection::FunctionTy>> PoolHttpConnection::FunctionNameMap_ = {
  // User manager functions
  {"userAction", {hmPost, fnUserAction}},
  {"userCreate", {hmPost, fnUserCreate}},
  {"userResendEmail", {hmPost, fnUserResendEmail}},
  {"userLogin", {hmPost, fnUserLogin}},
  {"userLogout", {hmPost, fnUserLogout}},
  {"userChangeEmail", {hmPost, fnUserChangeEmail}},
  {"userChangePasswordForce", {hmPost, fnUserChangePasswordForce}},
  {"userChangePasswordInitiate", {hmPost, fnUserChangePasswordInitiate}},
  {"userGetCredentials", {hmPost, fnUserGetCredentials}},
  {"userGetSettings", {hmPost, fnUserGetSettings}},
  {"userUpdateCredentials", {hmPost, fnUserUpdateCredentials}},
  {"userUpdateSettings", {hmPost, fnUserUpdateSettings}},
  {"userEnumerateAll", {hmPost, fnUserEnumerateAll}},
  {"userEnumerateFeePlan", {hmPost, fnUserEnumerateFeePlan}},
  {"userGetFeePlan", {hmPost, fnUserGetFeePlan}},
  {"userUpdateFeePlan", {hmPost, fnUserUpdateFeePlan}},
  {"userChangeFeePlan", {hmPost, fnUserChangeFeePlan}},
  {"userActivate2faInitiate", {hmPost, fnUserActivate2faInitiate}},
  {"userDeactivate2faInitiate", {hmPost, fnUserDeactivate2faInitiate}},
  // Backend functions
  {"backendManualPayout", {hmPost, fnBackendManualPayout}},
  {"backendQueryCoins", {hmPost, fnBackendQueryCoins}},
  {"backendQueryFoundBlocks", {hmPost, fnBackendQueryFoundBlocks}},
  {"backendQueryPayouts", {hmPost, fnBackendQueryPayouts}},
  {"backendQueryPoolBalance", {hmPost, fnBackendQueryPoolBalance}},
  {"backendQueryPoolStats", {hmPost, fnBackendQueryPoolStats}},
  {"backendQueryPoolStatsHistory", {hmPost, fnBackendQueryPoolStatsHistory}},
  {"backendQueryProfitSwitchCoeff", {hmPost, fnBackendQueryProfitSwitchCoeff}},
  {"backendQueryUserBalance", {hmPost, fnBackendQueryUserBalance}},
  {"backendQueryUserStats", {hmPost, fnBackendQueryUserStats}},
  {"backendQueryUserStatsHistory", {hmPost, fnBackendQueryUserStatsHistory}},
  {"backendQueryWorkerStatsHistory", {hmPost, fnBackendQueryWorkerStatsHistory}},
  {"backendUpdateProfitSwitchCoeff", {hmPost, fnBackendUpdateProfitSwitchCoeff}},
  {"backendPoolLuck", {hmPost, fnBackendPoolLuck}},
  // Instance functions
  {"instanceEnumerateAll", {hmPost, fnInstanceEnumerateAll}},
  // Complex mining stats functions
  {"complexMiningStatsGetInfo", {hmPost, fnComplexMiningStatsGetInfo}}
};

static inline bool rawcmp(Raw data, const char *operand) {
  size_t opSize = strlen(operand);
  return data.size == opSize && memcmp(data.data, operand, opSize) == 0;
}

static inline void jsonParseString(rapidjson::Value &document, const char *name, std::string &out, bool *validAcc) {
  if (document.HasMember(name) && document[name].IsString())
    out = document[name].GetString();
  else
    *validAcc = false;
}

static inline void jsonParseString(rapidjson::Value &document, const char *name, std::string &out, const std::string &defaultValue, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsString())
      out = document[name].GetString();
    else
      *validAcc = false;
  } else {
    out = defaultValue;
  }
}


static inline void jsonParseInt64(rapidjson::Value &document, const char *name, int64_t *out, int64_t defaultValue, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsInt64())
      *out = document[name].GetInt64();
    else
      *validAcc = false;
  } else {
    *out = defaultValue;
  }
}


static inline void jsonParseUInt64(rapidjson::Value &document, const char *name, uint64_t *out, int64_t defaultValue, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsUint64())
      *out = document[name].GetUint64();
    else
      *validAcc = false;
  } else {
    *out = defaultValue;
  }
}

static inline void jsonParseUInt(rapidjson::Value &document, const char *name, unsigned *out, unsigned defaultValue, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsUint())
      *out = document[name].GetUint();
    else
      *validAcc = false;
  } else {
    *out = defaultValue;
  }
}

static inline void jsonParseBoolean(rapidjson::Value &document, const char *name, bool *out, bool *validAcc) {
  if (document.HasMember(name) && document[name].IsBool())
    *out = document[name].GetBool();
  else
    *validAcc = false;
}

static inline void jsonParseBoolean(rapidjson::Value &document, const char *name, bool *out, bool defaultValue, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsBool())
      *out = document[name].GetBool();
    else
      *validAcc = false;
  } else {
    *out = defaultValue;
  }
}

static inline void jsonParseNumber(rapidjson::Value &document, const char *name, double *out, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsNumber())
      *out = document[name].GetDouble();
    else
      *validAcc = false;
  } else {
    *validAcc = false;
  }
}

static inline void jsonParseNumber(rapidjson::Value &document, const char *name, double *out, double defaultValue, bool *validAcc) {
  if (document.HasMember(name)) {
    if (document[name].IsNumber())
      *out = document[name].GetDouble();
    else
      *validAcc = false;
  } else {
    *out = defaultValue;
  }
}

static inline void parseUserCredentials(rapidjson::Value &document, UserManager::Credentials &credentials, bool *validAcc)
{
  jsonParseString(document, "login", credentials.Login, "", validAcc);
  jsonParseString(document, "password", credentials.Password, "", validAcc);
  jsonParseString(document, "name", credentials.Name, "", validAcc);
  jsonParseString(document, "email", credentials.EMail, "", validAcc);
  jsonParseString(document, "totp", credentials.TwoFactor, "", validAcc);
  jsonParseBoolean(document, "isActive", &credentials.IsActive, false, validAcc);
  jsonParseBoolean(document, "isReadOnly", &credentials.IsReadOnly, false, validAcc);
  jsonParseString(document, "feePlanId", credentials.FeePlan, "", validAcc);
}

static void addUserFeeConfig(xmstream &stream, const UserFeeConfig &config)
{
  JSON::Array cfg(stream);
  for (const auto &pair: config) {
    cfg.addField();
    JSON::Object pairObject(stream);
    pairObject.addString("userId", pair.UserId);
    pairObject.addDouble("percentage", pair.Percentage);
  }
}

static void addUserFeePlan(xmstream &stream, const UserFeePlanRecord &plan)
{
  JSON::Object result(stream);
  result.addString("feePlanId", plan.FeePlanId);
  result.addField("default");
    addUserFeeConfig(stream, plan.Default);
  result.addField("coinSpecificFee");
  {
    JSON::Array coinSpecificFee(stream);
    for (const auto &specificFee: plan.CoinSpecificFee) {
      {
        coinSpecificFee.addField();
        JSON::Object coin(stream);
        coin.addString("coin", specificFee.CoinName);
        coin.addField("config");
          addUserFeeConfig(stream, specificFee.Config);
      }
    }
  }
}

void PoolHttpConnection::run()
{
  aioRead(Socket_, buffer, sizeof(buffer), afNone, 0, readCb, this);
}

int PoolHttpConnection::onParse(HttpRequestComponent *component)
{
  if (component->type == httpRequestDtMethod) {
    Context.method = component->method;
    Context.function = fnUnknown;
    return 1;
  }

  if (component->type == httpRequestDtUriPathElement) {
    // Wait 'api'
    if (Context.function == fnUnknown && rawcmp(component->data, "api")) {
      Context.function = fnApi;
    } else if (Context.function == fnApi) {
      std::string functionName(component->data.data, component->data.data + component->data.size);
      auto It = FunctionNameMap_.find(functionName);
      if (It == FunctionNameMap_.end() || It->second.first != Context.method) {
        reply404();
        return 0;
      }

      Context.function = It->second.second;
      return 1;
    } else {
      reply404();
      return 0;
    }
  } else if (component->type == httpRequestDtData) {
    Context.Request.append(component->data.data, component->data.data + component->data.size);
    return 1;
  } else if (component->type == httpRequestDtDataLast) {
    Context.Request.append(component->data.data, component->data.data + component->data.size);
    rapidjson::Document document;
    document.Parse(!Context.Request.empty() ? Context.Request.c_str() : "{}");
    if (document.HasParseError() || !document.IsObject()) {
      replyWithStatus("invalid_json");
      return 1;
    }

    switch (Context.function) {
      case fnUserAction: onUserAction(document); break;
      case fnUserCreate: onUserCreate(document); break;
      case fnUserResendEmail: onUserResendEmail(document); break;
      case fnUserLogin: onUserLogin(document); break;
      case fnUserLogout: onUserLogout(document); break;
      case fnUserChangeEmail: onUserChangeEmail(document); break;
      case fnUserChangePasswordInitiate: onUserChangePasswordInitiate(document); break;
      case fnUserChangePasswordForce: onUserChangePasswordForce(document); break;
      case fnUserGetCredentials: onUserGetCredentials(document); break;
      case fnUserGetSettings: onUserGetSettings(document); break;
      case fnUserUpdateCredentials: onUserUpdateCredentials(document); break;
      case fnUserUpdateSettings: onUserUpdateSettings(document); break;
      case fnUserEnumerateAll: onUserEnumerateAll(document); break;
      case fnUserEnumerateFeePlan: onUserEnumerateFeePlan(document); break;
      case fnUserGetFeePlan: onUserGetFeePlan(document); break;
      case fnUserUpdateFeePlan: onUserUpdateFeePlan(document); break;
      case fnUserChangeFeePlan: onUserChangeFeePlan(document); break;
      case fnUserActivate2faInitiate: onUserActivate2faInitiate(document); break;
      case fnUserDeactivate2faInitiate: onUserDeactivate2faInitiate(document); break;
      case fnBackendManualPayout: onBackendManualPayout(document); break;
      case fnBackendQueryUserBalance: onBackendQueryUserBalance(document); break;
      case fnBackendQueryUserStats: onBackendQueryUserStats(document); break;
      case fnBackendQueryUserStatsHistory: onBackendQueryUserStatsHistory(document); break;
      case fnBackendQueryWorkerStatsHistory: onBackendQueryWorkerStatsHistory(document); break;
      case fnBackendQueryCoins : onBackendQueryCoins(document); break;
      case fnBackendQueryFoundBlocks: onBackendQueryFoundBlocks(document); break;
      case fnBackendQueryPayouts: onBackendQueryPayouts(document); break;
      case fnBackendQueryPoolBalance: onBackendQueryPoolBalance(document); break;
      case fnBackendQueryPoolStats: onBackendQueryPoolStats(document); break;
      case fnBackendQueryPoolStatsHistory : onBackendQueryPoolStatsHistory(document); break;
      case fnBackendQueryProfitSwitchCoeff : onBackendQueryProfitSwitchCoeff(document); break;
      case fnBackendUpdateProfitSwitchCoeff : onBackendUpdateProfitSwitchCoeff(document); break;
      case fnBackendPoolLuck : onBackendPoolLuck(document); break;
      case fnInstanceEnumerateAll : onInstanceEnumerateAll(document); break;
      case fnComplexMiningStatsGetInfo : onComplexMiningStatsGetInfo(document); break;
      default:
        reply404();
        return 0;
    }
  }

  return 1;
}

void PoolHttpConnection::onWrite()
{
  // TODO: check keep alive
  socketShutdown(aioObjectSocket(Socket_), SOCKET_SHUTDOWN_READWRITE);
  aioRead(Socket_, buffer, sizeof(buffer), afNone, 0, readCb, this);
}

void PoolHttpConnection::onRead(AsyncOpStatus status, size_t bytesRead)
{
  if (status != aosSuccess) {
    close();
    return;
  }

  httpRequestSetBuffer(&ParserState, buffer, bytesRead + oldDataSize);

  switch (httpRequestParse(&ParserState, [](HttpRequestComponent *component, void *arg) -> int { return static_cast<PoolHttpConnection*>(arg)->onParse(component); }, this)) {
    case ParserResultOk : {
      // TODO: check keep-alive
      break;
    }

    case ParserResultNeedMoreData : {
      // copy 'tail' to begin of buffer
      oldDataSize = httpRequestDataRemaining(&ParserState);
      if (oldDataSize)
        memcpy(buffer, httpRequestDataPtr(&ParserState), oldDataSize);
      aioRead(Socket_, buffer+oldDataSize, sizeof(buffer)-oldDataSize, afNone, 0, readCb, this);
      break;
    }

    case ParserResultError : {
      close();
      break;
    }

    case ParserResultCancelled : {
      close();
      break;
    }
  }
}

void PoolHttpConnection::reply200(xmstream &stream)
{
  const char reply200[] = "HTTP/1.1 200 OK\r\nServer: bcnode\r\nTransfer-Encoding: chunked\r\n\r\n";
  stream.write(reply200, sizeof(reply200)-1);
}

void PoolHttpConnection::reply404()
{
  const char reply404[] = "HTTP/1.1 404 Not Found\r\nServer: bcnode\r\nTransfer-Encoding: chunked\r\n\r\n";
  const char html[] = "<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>";

  char buffer[4096];
  xmstream stream(buffer, sizeof(buffer));
  stream.write(reply404, sizeof(reply404)-1);

  size_t offset = startChunk(stream);
  stream.write(html);
  finishChunk(stream, offset);

  aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
}

size_t PoolHttpConnection::startChunk(xmstream &stream)
{
  size_t offset = stream.offsetOf();
  stream.write("00000000\r\n", 10);
  return offset;
}

void PoolHttpConnection::finishChunk(xmstream &stream, size_t offset)
{
  char hex[16];
  char finishData[] = "\r\n0\r\n\r\n";
  sprintf(hex, "%08x", static_cast<unsigned>(stream.offsetOf() - offset - 10));
  memcpy(stream.data<uint8_t>() + offset, hex, 8);
  stream.write(finishData, sizeof(finishData));
}

void PoolHttpConnection::close()
{
  if (Deleted_++ == 0)
    deleteAioObject(Socket_);
}

void PoolHttpConnection::onUserAction(rapidjson::Document &document)
{
  std::string actionId;
  std::string newPassword;
  std::string totp;
  bool validAcc = true;
  jsonParseString(document, "actionId", actionId, &validAcc);
  jsonParseString(document, "newPassword", newPassword, "", &validAcc);
  jsonParseString(document, "totp", totp, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userAction(actionId, newPassword, totp, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserCreate(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  UserManager::Credentials credentials;

  jsonParseString(document, "id", sessionId, "", &validAcc);
  parseUserCredentials(document, credentials, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  std::string login;
  if (!sessionId.empty()) {
    if (!Server_.userManager().validateSession(sessionId, "", login, false)) {
      replyWithStatus("unknown_id");
      return;
    }
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userCreate(login, std::move(credentials), [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserResendEmail(rapidjson::Document &document)
{
  bool validAcc = true;
  UserManager::Credentials credentials;
  parseUserCredentials(document, credentials, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userResendEmail(std::move(credentials), [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserLogin(rapidjson::Document &document)
{
  bool validAcc = true;
  UserManager::Credentials credentials;
  parseUserCredentials(document, credentials, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userLogin(std::move(credentials), [this](const std::string &sessionId, const char *status, bool isReadOnly) {
    xmstream stream;
    reply200(stream);
    size_t offset = startChunk(stream);

    {
      JSON::Object result(stream);
      result.addString("status", status);
      result.addString("sessionid", sessionId);
      result.addBoolean("isReadOnly", isReadOnly);
    }

    finishChunk(stream, offset);
    aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserLogout(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  jsonParseString(document, "id", sessionId, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userLogout(sessionId, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserChangeEmail(rapidjson::Document&)
{
  xmstream stream;
  reply200(stream);
  size_t offset = startChunk(stream);
  stream.write("{\"error\": \"not implemented\"}\n");
  finishChunk(stream, offset);
  aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
}

void PoolHttpConnection::onUserChangePasswordInitiate(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string login;
  jsonParseString(document, "login", login, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userChangePasswordInitiate(login, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserChangePasswordForce(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string id;
  std::string login;
  std::string newPassword;
  jsonParseString(document, "id", id, &validAcc);
  jsonParseString(document, "login", login, &validAcc);
  jsonParseString(document, "newPassword", newPassword, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().userChangePasswordForce(id, login, newPassword, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserGetCredentials(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  xmstream stream;
  reply200(stream);
  size_t offset = startChunk(stream);

  std::string login;
  UserManager::Credentials credentials;
  if (Server_.userManager().validateSession(sessionId, targetLogin, login, false)) {
    JSON::Object result(stream);
    if (Server_.userManager().getUserCredentials(login, credentials)) {
      result.addString("status", "ok");
      result.addString("login", login);
      result.addString("name", credentials.Name);
      result.addString("email", credentials.EMail);
      result.addInt("registrationDate", credentials.RegistrationDate);
      result.addBoolean("isActive", credentials.IsActive);
      result.addBoolean("isReadOnly", credentials.IsReadOnly);
      result.addBoolean("has2fa", credentials.HasTwoFactor);
    } else {
      result.addString("status", "unknown_id");
    }
  } else {
    JSON::Object result(stream);
    result.addString("status", "unknown_id");
  }

  finishChunk(stream, offset);
  aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
}

void PoolHttpConnection::onUserGetSettings(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  xmstream stream;
  reply200(stream);
  size_t offset = startChunk(stream);

  {
    JSON::Object object(stream);
    std::string login;
    if (Server_.userManager().validateSession(sessionId, targetLogin, login, false)) {
      object.addString("status", "ok");
      object.addField("coins");
      JSON::Array coins(stream);
      for (const auto &coinInfo: Server_.userManager().coinInfo()) {
        coins.addField();
        JSON::Object coin(stream);
        UserSettingsRecord settings;
        coin.addString("name", coinInfo.Name.c_str());
        if (Server_.userManager().getUserCoinSettings(login, coinInfo.Name, settings)) {
          coin.addString("address", settings.Address);
          coin.addString("payoutThreshold", FormatMoney(settings.MinimalPayout, coinInfo.RationalPartSize));
          coin.addBoolean("autoPayoutEnabled", settings.AutoPayout);
        } else {
          coin.addNull("address");
          coin.addNull("payoutThreshold");
          coin.addBoolean("autoPayoutEnabled", false);
        }
      }
    } else {
      object.addString("status", "unknown_id");
    }
  }

  finishChunk(stream, offset);
  aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
}

void PoolHttpConnection::onUserUpdateCredentials(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  UserManager::Credentials credentials;

  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  parseUserCredentials(document, credentials, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().updateCredentials(sessionId, targetLogin, std::move(credentials), [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserUpdateSettings(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  UserSettingsRecord settings;
  std::string payoutThreshold;
  std::string totp;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", settings.Coin, &validAcc);
  jsonParseString(document, "address", settings.Address, &validAcc);
  jsonParseString(document, "payoutThreshold", payoutThreshold, &validAcc);
  jsonParseBoolean(document, "autoPayoutEnabled", &settings.AutoPayout, &validAcc);
  jsonParseString(document, "totp", totp, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  auto It = Server_.userManager().coinIdxMap().find(settings.Coin);
  if (It == Server_.userManager().coinIdxMap().end()) {
    replyWithStatus("invalid_coin");
    return;
  }

  CCoinInfo &coinInfo = Server_.userManager().coinInfo()[It->second];
  if (!parseMoneyValue(payoutThreshold.c_str(), coinInfo.RationalPartSize, &settings.MinimalPayout)) {
    replyWithStatus("request_format_error");
    return;
  }

  if (!coinInfo.checkAddress(settings.Address, coinInfo.PayoutAddressType)) {
    replyWithStatus("invalid_address");
    return;
  }

  if (!Server_.userManager().validateSession(sessionId, targetLogin, settings.Login, true)) {
    replyWithStatus("unknown_id");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().updateSettings(std::move(settings), totp, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserEnumerateAll(rapidjson::Document &document)
{
  reply404();
}

void PoolHttpConnection::onUserUpdateFeePlan(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  UserFeePlanRecord record;

  auto jsonParseUserFeeConfig = [](rapidjson::Value &value, const char *fieldName, UserFeeConfig &config, bool *validAcc) {
    if (!value.HasMember(fieldName) || !value[fieldName].IsArray()) {
      *validAcc = false;
      return;
    }

    rapidjson::Value::Array pairs = value[fieldName].GetArray();
    for (rapidjson::SizeType i = 0, ie = pairs.Size(); i != ie; ++i) {
      if (!pairs[i].IsObject()) {
        *validAcc = false;
        return;
      }

      config.emplace_back();
      jsonParseString(pairs[i], "userId", config.back().UserId, validAcc);
      jsonParseNumber(pairs[i], "percentage", &config.back().Percentage, validAcc);
    }
  };

  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "feePlanId", record.FeePlanId, &validAcc);
  jsonParseUserFeeConfig(document, "default", record.Default, &validAcc);
  if (document.HasMember("coinSpecificFee") && document["coinSpecificFee"].IsArray()) {
    rapidjson::Value::Array coinSpecificFee = document["coinSpecificFee"].GetArray();
    for (rapidjson::SizeType i = 0, ie = coinSpecificFee.Size(); i != ie; ++i) {
      if (!coinSpecificFee[i].IsObject()) {
        validAcc = false;
        break;
      }

      record.CoinSpecificFee.emplace_back();
      jsonParseString(coinSpecificFee[i], "coin", record.CoinSpecificFee.back().CoinName, &validAcc);
      jsonParseUserFeeConfig(coinSpecificFee[i], "config", record.CoinSpecificFee.back().Config, &validAcc);
    }
  }

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  // Check coin
  // TODO: check coin
  replyWithStatus("invalid_coin");
  return;

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().updateFeePlan(sessionId, std::move(record), [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserEnumerateFeePlan(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  jsonParseString(document, "id", sessionId, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  std::string status;
  std::vector<UserFeePlanRecord> result;
  if (Server_.userManager().enumerateFeePlan(sessionId, status, result)) {
    xmstream stream;
    reply200(stream);
    size_t offset = startChunk(stream);

    {
      JSON::Object answer(stream);
      answer.addString("status", "ok");
      answer.addField("plans");
      {
        JSON::Array plans(stream);
        for (const auto &plan: result) {
          plans.addField();
          addUserFeePlan(stream, plan);
        }
      }
    }

    finishChunk(stream, offset);
    aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
  } else {
    replyWithStatus(status.c_str());
  }
}

void PoolHttpConnection::onUserGetFeePlan(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string feePlanId;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "feePlanId", feePlanId, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  std::string status;
  UserFeePlanRecord result;
  if (Server_.userManager().getFeePlan(sessionId, feePlanId, status, result)) {
    xmstream stream;
    reply200(stream);
    size_t offset = startChunk(stream);

    {
      JSON::Object answer(stream);
      answer.addString("status", "ok");
      answer.addField("plan");
      addUserFeePlan(stream, result);
    }

    finishChunk(stream, offset);
    aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
  } else {
    replyWithStatus(status.c_str());
  }
}

void PoolHttpConnection::onUserChangeFeePlan(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  std::string feePlanId;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, &validAcc);
  jsonParseString(document, "feePlanId", feePlanId, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().changeFeePlan(sessionId, targetLogin, feePlanId, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserActivate2faInitiate(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  jsonParseString(document, "sessionId", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().activate2faInitiate(sessionId, targetLogin, [this](const char *status, const char *key) {
    xmstream stream;
    reply200(stream);
    size_t offset = startChunk(stream);

    {
      JSON::Object result(stream);
      result.addString("status", status);
      result.addString("key", key);
    }

    finishChunk(stream, offset);
    aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onUserDeactivate2faInitiate(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  jsonParseString(document, "sessionId", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  objectIncrementReference(aioObjectHandle(Socket_), 1);
  Server_.userManager().deactivate2faInitiate(sessionId, targetLogin, [this](const char *status) {
    replyWithStatus(status);
    objectDecrementReference(aioObjectHandle(Socket_), 1);
  });
}

void PoolHttpConnection::onBackendManualPayout(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  std::string coin;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", coin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  // id -> login
  std::string login;
  if (!Server_.userManager().validateSession(sessionId, targetLogin, login, true)) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryUserBalance(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  std::string coin;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", coin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  // id -> login
  std::string login;
  if (!Server_.userManager().validateSession(sessionId, targetLogin, login, false)) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryUserStats(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  std::string coin;
  uint64_t offset = 0;
  uint64_t size = 0;
  std::string sortBy;
  bool sortDescending;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", coin, "", &validAcc);
  jsonParseUInt64(document, "offset", &offset, 0, &validAcc);
  jsonParseUInt64(document, "size", &size, 4096, &validAcc);
  jsonParseString(document, "sortBy", sortBy, "name", &validAcc);
  jsonParseBoolean(document, "sortDescending", &sortDescending, false, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::queryStatsHistory(const std::string &login, const std::string &worker, int64_t timeFrom, int64_t timeTo, int64_t groupByInterval, int64_t currentTime)
{
  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryUserStatsHistory(rapidjson::Document &document)
{
  bool validAcc = true;
  int64_t currentTime = time(nullptr);
  std::string sessionId;
  std::string targetLogin;
  std::string coin;
  int64_t timeFrom;
  int64_t timeTo;
  int64_t groupByInterval;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", coin, "", &validAcc);
  jsonParseInt64(document, "timeFrom", &timeFrom, currentTime - 24*3600, &validAcc);
  jsonParseInt64(document, "timeTo", &timeTo, currentTime, &validAcc);
  jsonParseInt64(document, "groupByInterval", &groupByInterval, 3600, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  // id -> login
  std::string login;
  if (!Server_.userManager().validateSession(sessionId, targetLogin, login, false)) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryWorkerStatsHistory(rapidjson::Document &document)
{
  bool validAcc = true;
  int64_t currentTime = time(nullptr);
  std::string sessionId;
  std::string targetLogin;
  std::string coin;
  std::string workerId;
  int64_t timeFrom;
  int64_t timeTo;
  int64_t groupByInterval;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", coin, &validAcc);
  jsonParseString(document, "workerId", workerId, &validAcc);
  jsonParseInt64(document, "timeFrom", &timeFrom, currentTime - 24*3600, &validAcc);
  jsonParseInt64(document, "timeTo", &timeTo, currentTime, &validAcc);
  jsonParseInt64(document, "groupByInterval", &groupByInterval, 3600, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  // id -> login
  std::string login;
  if (!Server_.userManager().validateSession(sessionId, targetLogin, login, false)) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryCoins(rapidjson::Document&)
{
  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryFoundBlocks(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string coin;
  int64_t heightFrom;
  std::string hashFrom;
  uint32_t count;
  jsonParseString(document, "coin", coin, &validAcc);
  jsonParseInt64(document, "heightFrom", &heightFrom, -1, &validAcc);
  jsonParseString(document, "hashFrom", hashFrom, "", &validAcc);
  jsonParseUInt(document, "count", &count, 20, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryPayouts(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string targetLogin;
  std::string coin;
  uint64_t timeFrom = 0;
  unsigned count;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "targetLogin", targetLogin, "", &validAcc);
  jsonParseString(document, "coin", coin, "", &validAcc);
  jsonParseUInt64(document, "timeFrom", &timeFrom, 0, &validAcc);
  jsonParseUInt(document, "count", &count, 20, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  // id -> login
  std::string login;
  if (!Server_.userManager().validateSession(sessionId, targetLogin, login, false)) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendQueryPoolBalance(rapidjson::Document&)
{
  xmstream stream;
  reply200(stream);
  size_t offset = startChunk(stream);
  stream.write("{\"error\": \"not implemented\"}\n");
  finishChunk(stream, offset);
  aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
}

void PoolHttpConnection::onBackendQueryPoolStats(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string coin;
  jsonParseString(document, "coin", coin, "", &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  reply404();
}

void PoolHttpConnection::onBackendQueryPoolStatsHistory(rapidjson::Document &document)
{
  bool validAcc = true;
  int64_t currentTime = time(nullptr);
  std::string coin;
  int64_t timeFrom;
  int64_t timeTo;
  int64_t groupByInterval;
  jsonParseString(document, "coin", coin, "", &validAcc);
  jsonParseInt64(document, "timeFrom", &timeFrom, currentTime - 24*3600, &validAcc);
  jsonParseInt64(document, "timeTo", &timeTo, currentTime, &validAcc);
  jsonParseInt64(document, "groupByInterval", &groupByInterval, 3600, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  reply404();
}

void PoolHttpConnection::onBackendQueryProfitSwitchCoeff(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  jsonParseString(document, "id", sessionId, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  std::string login;
  if (!Server_.userManager().validateSession(sessionId, "", login, false) || (login != "admin" && login != "observer")) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendUpdateProfitSwitchCoeff(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  std::string coin;
  double profitSwitchCoeff = 0.0;
  jsonParseString(document, "id", sessionId, &validAcc);
  jsonParseString(document, "coin", coin, "", &validAcc);
  jsonParseNumber(document, "profitSwitchCoeff", &profitSwitchCoeff, &validAcc);

  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  std::string login;
  if (!Server_.userManager().validateSession(sessionId, "", login, false) || (login != "admin")) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onBackendPoolLuck(rapidjson::Document &document)
{
  if (!document.HasMember("coin") || !document["coin"].IsString() ||
      !document.HasMember("intervals") || !document["intervals"].IsArray()) {
    replyWithStatus("json_format_error");
    return;
  }

  reply404();
  return;
}

void PoolHttpConnection::onInstanceEnumerateAll(rapidjson::Document&)
{
  reply404();
  return;
}

void PoolHttpConnection::onComplexMiningStatsGetInfo(rapidjson::Document &document)
{
  bool validAcc = true;
  std::string sessionId;
  jsonParseString(document, "id", sessionId, &validAcc);
  if (!validAcc) {
    replyWithStatus("json_format_error");
    return;
  }

  std::string login;
  if (!Server_.userManager().validateSession(sessionId, "", login, false) || (login != "admin")) {
    replyWithStatus("unknown_id");
    return;
  }

  reply404();
  return;
}

PoolHttpServer::PoolHttpServer(uint16_t port,
                               UserManager &userMgr,
                               const CPoolFrontendConfig &config,
                               size_t threadsNum) :
  Port_(port),
  UserMgr_(userMgr),
  Config_(config),
  ThreadsNum_(threadsNum)
{
  Base_ = createAsyncBase(amOSDefault);
}

bool PoolHttpServer::start()
{
  HostAddress address;
  address.family = AF_INET;
  address.ipv4 = inet_addr("127.0.0.1");
  address.port = htons(Port_);
  socketTy hSocket = socketCreate(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1);
  socketReuseAddr(hSocket);

  if (socketBind(hSocket, &address) != 0) {
    LOG_F(ERROR, "PoolHttpServer: can't bind port %u\n", static_cast<unsigned>(Port_));
    return false;
  }

  if (socketListen(hSocket) != 0) {
    LOG_F(ERROR, "PoolHttpServer: can't listen port %u\n", static_cast<unsigned>(Port_));
    return false;
  }

  ListenerSocket_ = newSocketIo(Base_, hSocket);
  aioAccept(ListenerSocket_, 0, acceptCb, this);

  Threads_.reset(new std::thread[ThreadsNum_]);
  for (size_t i = 0; i < ThreadsNum_; i++) {
    Threads_[i] = std::thread([i](PoolHttpServer *server) {
      char threadName[16];
      snprintf(threadName, sizeof(threadName), "http%zu", i);
      loguru::set_thread_name(threadName);
      InitializeWorkerThread();
      LOG_F(INFO, "http server started tid=%u", GetGlobalThreadId());
      asyncLoop(server->Base_);
    }, this);
  }

  return true;
}

void PoolHttpServer::stop()
{
  postQuitOperation(Base_);
  for (size_t i = 0; i < ThreadsNum_; i++) {
    LOG_F(INFO, "http worker %zu finishing", i);
    Threads_[i].join();
  }
}


void PoolHttpServer::acceptCb(AsyncOpStatus status, aioObject *object, HostAddress address, socketTy socketFd, void *arg)
{
  if (status == aosSuccess) {
    aioObject *connectionSocket = newSocketIo(aioGetBase(object), socketFd);
    PoolHttpConnection *connection = new PoolHttpConnection(*static_cast<PoolHttpServer*>(arg), address, connectionSocket);
    connection->run();
  } else {
    LOG_F(ERROR, "HTTP api accept connection failed");
  }

  aioAccept(object, 0, acceptCb, arg);
}

void PoolHttpConnection::replyWithStatus(const char *status)
{
  xmstream stream;
  reply200(stream);
  size_t offset = startChunk(stream);

  {
    JSON::Object object(stream);
    object.addString("status", status);
  }

  finishChunk(stream, offset);
  aioWrite(Socket_, stream.data(), stream.sizeOf(), afWaitAll, 0, writeCb, this);
}
