#include "poolcore/priceFetcher.h"
#include "asyncio/socketSSL.h"
#include "asyncio/socket.h"
#include "rapidjson/document.h"
#include "loguru.hpp"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

static void buildGetQuery(const std::string address, const std::string &host, xmstream &out)
{
  out.write("GET ");
    out.write(address.data(), address.size());
    out.write(" HTTP/1.1\r\n");
  out.write("Host: ");
    out.write(host.data(), host.size());
    out.write("\r\n");
  out.write("\r\n");
}

CPriceFetcher::CPriceFetcher(asyncBase *monitorBase, std::vector<CCoinInfo> &coinInfo) : MonitorBase_(monitorBase), CoinInfo_(coinInfo)
{
  CurrentPrices_.reset(new std::atomic<double>[coinInfo.size()]);
  for (size_t i = 0; i < coinInfo.size(); i++)
    CurrentPrices_[i].store(0.0);

  // coingecko resolve
  {
    struct hostent *host = gethostbyname("api.coingecko.com");
    if (host) {
      struct in_addr **hostAddrList = (struct in_addr**)host->h_addr_list;
      if (hostAddrList[0]) {
        Address_.ipv4 = hostAddrList[0]->s_addr;
        Address_.port = htons(443);
        Address_.family = AF_INET;
      } else {
        LOG_F(ERROR, "Can't lookup address %s\n", "coingecko.com");
        exit(1);
      }
    }
  }

  {
    // build request for all coins
    std::string query = "/api/v3/simple/price?ids=bitcoin";
    for (size_t i = 0; i < CoinInfo_.size(); i++) {
      const auto &coin = CoinInfo_[i];
      if (coin.CoinGeckoName.empty()) {
        LOG_F(ERROR, "PriceFetcher: %s not have at coingecko.com", coin.Name.c_str());
        continue;
      }

      // Query BTC/USDT rate anyway
      if (coin.CoinGeckoName == "BTC") {
        CurrentPrices_[i] = 1.0;
        continue;
      }

      query.push_back(',');
      query.append(coin.CoinGeckoName);
    }

    query.append("&vs_currencies=USD");
    buildGetQuery(query, "api.coingecko.com", PreparedQuery_);
  }

  Client_ = nullptr;
  httpParseDefaultInit(&ParseCtx_);
  TimerEvent_ = newUserEvent(monitorBase, 0, [](aioUserEvent*, void *arg){
    static_cast<CPriceFetcher*>(arg)->updatePrice();
  }, this);

  updatePrice();
}

void CPriceFetcher::updatePrice()
{
  SSLSocket *object = sslSocketNew(MonitorBase_, nullptr);
  Client_ = httpsClientNew(MonitorBase_, object);
  dynamicBufferClear(&ParseCtx_.buffer);
  aioHttpConnect(Client_, &Address_, "api.coingecko.com", 3000000, [](AsyncOpStatus status, HTTPClient*, void *arg) {
    static_cast<CPriceFetcher*>(arg)->onConnect(status);
  }, this);
}

void CPriceFetcher::onConnect(AsyncOpStatus status)
{
  if (status != aosSuccess) {
    LOG_F(ERROR, "PriceFetcher connect error %i", status);
    httpClientDelete(Client_);
    userEventStartTimer(TimerEvent_, 60*1000000, 1);
    return;
  }

  aioHttpRequest(Client_, PreparedQuery_.data<const char>(), PreparedQuery_.sizeOf(), 10*1000000, httpParseDefault, &ParseCtx_, [](AsyncOpStatus status, HTTPClient*, void *arg) {
    static_cast<CPriceFetcher*>(arg)->onRequest(status);
  }, this);
}

void CPriceFetcher::onRequest(AsyncOpStatus status)
{
  if (status == aosSuccess && ParseCtx_.resultCode == 200) {
    processRequest(ParseCtx_.body.data, ParseCtx_.body.size);
  } else {
    LOG_F(ERROR, "PriceFetcher request error %i; http code: %i", status, ParseCtx_.resultCode);
  }

  httpClientDelete(Client_);
  userEventStartTimer(TimerEvent_, 60*1000000, 1);
}

void CPriceFetcher::processRequest(const char *data, size_t size)
{
  char buffer[256];
  std::string priceFetcherLog = "priceFetcher: ";
  rapidjson::Document document;
  document.Parse(data, size);
  if (document.HasParseError())
    return;

  double btcPrice = 0.0;
  for (size_t i = 0; i < CoinInfo_.size(); i++) {
    const auto &coin = CoinInfo_[i];

    if (!document.HasMember(coin.CoinGeckoName.c_str()) || !document[coin.CoinGeckoName.c_str()].IsObject())
      continue;
    rapidjson::Value &coinPrice = document[coin.CoinGeckoName.c_str()];
    if (!coinPrice.HasMember("usd") || !coinPrice["usd"].IsNumber())
      continue;

    double price = coinPrice["usd"].GetDouble();
    if (coin.Name == "BTC") {
      btcPrice = price;
      snprintf(buffer, sizeof(buffer), "%s/USD: %.2lf ", "BTC", btcPrice);
      priceFetcherLog.append(buffer);
    } else {
      CurrentPrices_[i].store(price / btcPrice);
      snprintf(buffer, sizeof(buffer), "%s/USD: %.2lf %s/BTC: %.8lf ", coin.Name.c_str(), price, coin.Name.c_str(), price / btcPrice);
      priceFetcherLog.append(buffer);
    }
  }

  LOG_F(INFO, "%s", priceFetcherLog.c_str());
}
