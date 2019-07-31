// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "HttpServer.h"

#include <functional>
#include <unordered_map>

#include <Logging/LoggerRef.h>
#include "CoreRpcServerCommandsDefinitions.h"

namespace CryptoNote {

class core;
class NodeServer;
class ICryptoNoteProtocolQuery;

class RpcServer : public HttpServer {
public:
  RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, core& c, NodeServer& p2p, const ICryptoNoteProtocolQuery& protocolQuery);

  typedef std::function<bool(RpcServer*, const HttpRequest& request, HttpResponse& response)> HandlerFunction;
  bool restrictRPC(bool is_resctricted);

  static void addJsonHeaders(HttpResponse& response);

private:

  template <class Handler>
  struct RpcHandler {
    const Handler handler;
    const bool allowBusyCore;
  };

  typedef void (RpcServer::*HandlerPtr)(const HttpRequest& request, HttpResponse& response);
  static std::unordered_map<std::string, RpcHandler<HandlerFunction>> s_handlers;

  void processRequest(const HttpRequest& request, HttpResponse& response) override;
  bool processJsonRpcRequest(const HttpRequest& request, HttpResponse& response);
  bool isCoreReady();

  // binary handlers
  bool on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res);
  bool on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res);
  bool on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res);
  bool on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res);
  bool on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res);
  bool onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp);
  bool onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp);

  // json handlers
  bool on_get_info(const COMMAND_RPC_GET_INFO::request& request, COMMAND_RPC_GET_INFO::response& response);
  bool on_get_height(const COMMAND_RPC_GET_HEIGHT::request& request, COMMAND_RPC_GET_HEIGHT::response& response);
  bool on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& request, COMMAND_RPC_GET_TRANSACTIONS::response& response);
  bool on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& request, COMMAND_RPC_SEND_RAW_TX::response& response);
  bool on_start_mining(const COMMAND_RPC_START_MINING::request& request, COMMAND_RPC_START_MINING::response& response);
  bool on_stop_mining(const COMMAND_RPC_STOP_MINING::request& request, COMMAND_RPC_STOP_MINING::response& response);
  bool on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& request, COMMAND_RPC_STOP_DAEMON::response& response);

  // json rpc
  bool on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& request, COMMAND_RPC_GETBLOCKCOUNT::response& response);
  bool on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& request, COMMAND_RPC_GETBLOCKHASH::response& response);
  bool on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& request, COMMAND_RPC_GETBLOCKTEMPLATE::response& response);
  bool on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& req, COMMAND_RPC_GET_CURRENCY_ID::response& response);
  bool on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& request, COMMAND_RPC_SUBMITBLOCK::response& response);
  bool on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& request, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& response);
  bool on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& response);
  bool on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& response);

  void fill_block_header_response(const Block& blk, bool orphan_status, uint64_t height, const Crypto::Hash& hash, block_header_response& response);

  Logging::LoggerRef logger;
  core& m_core;
  NodeServer& m_p2p;
  const ICryptoNoteProtocolQuery& m_protocolQuery;
  bool m_restricted_rpc;
};

}
