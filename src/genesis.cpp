// Copyright (c) 2017 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "unlimited.h"
#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "clientversion.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "consensus/merkle.h"
#include "core_io.h"
#include "expedited.h"
#include "hash.h"
#include "leakybucket.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "parallel.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "requestManager.h"
#include "rpc/server.h"
#include "stat.h"
#include "thinblock.h"
#include "timedata.h"
#include "tinyformat.h"
#include "tweak.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "version.h"

#include <atomic>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <inttypes.h>
#include <iomanip>
#include <limits>
#include <queue>
#include <stdexcept>


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << ((int) nBits) << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

CBlock *proposedGenesisBlock=NULL;

extern UniValue genesis(const UniValue& params, bool fHelp)
{
  if (fHelp || params.size() > 3)
      throw std::runtime_error(
            "genesis\n"
            "\ncreate a genesis block\n"
            "  outputAddress (string)\n"
            "  minerComment (string) miner comment\n"
            "  nBits difficulty   (compact number, optional) block difficulty\n"
            "\nExamples:\n" +
            HelpExampleCli("genesis", "") + HelpExampleRpc("genesis", ""));

  std::string genesisComment = params[1].getValStr();
  const CChainParams& chp = Params();
  const Consensus::Params& conp = chp.GetConsensus();
  int genesisDiff = UintToArith256(conp.powLimit).GetCompact();  // default to easiest block supported by this chain
  if (params.size() > 2)
  {
      std::string genesisDiffs = params[2].getValStr();
      if (genesisDiffs[1] == 'x' || genesisDiffs[1] == 'X')
      {
          genesisDiff = std::stoul(genesisDiffs, nullptr, 16);
      }
      else
      {
          genesisDiff = boost::lexical_cast<int>(genesisDiffs);
      }
  }

  CBitcoinAddress payaddress(params[0].get_str());
  if (!payaddress.IsValid())
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

  arith_uint256 bnTarget;
  bool fNegative, fOverflow;

  bnTarget.SetCompact(genesisDiff, &fNegative, &fOverflow);
  if (fNegative || bnTarget == 0 || fOverflow)
  {
      throw JSONRPCError(RPC_INVALID_PARAMETER,"block nBits difficulty is invalid");
  }

  if (bnTarget > UintToArith256(conp.powLimit))
  {
      throw JSONRPCError(RPC_INVALID_PARAMETER,"block nBits difficulty is greater than this chain allows");
  }


  CScript outputScript = GetScriptForDestination(payaddress.Get());
  CAmount genesisReward(5000000000);
  CBlock block = CreateGenesisBlock(genesisComment.c_str(), outputScript, GetTime(), 0,   genesisDiff, genesisReward );

  CBlock *pblock = &block;
  proposedGenesisBlock = pblock;
  uint256 hash = pblock->GetHash();
  while (!CheckProofOfWork(hash, pblock->nBits, conp))
  {
      ++pblock->nNonce;
      hash = pblock->GetHash();
  }
  proposedGenesisBlock = NULL;

  CValidationState state;

  std::ostringstream ret;
  std::string hexOutScript = HexStr(outputScript);

  ret << "CreateGenesisBlock() parameters: Comment: " << genesisComment.c_str() << " OutputScript: ParseHex(\"" << hexOutScript.c_str() << "\") Time: " << pblock->nTime << " Nonce: " << pblock->nNonce << " nBits: " << pblock->nBits << " Version: " << pblock->nVersion << " Reward: " << genesisReward << "\n";

  CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
  pblock->Serialize(stream, SER_NETWORK, PROTOCOL_VERSION);
  ret << "\nHEX: " << HexStr(stream.str());

  ret << "\n\n" << pblock->ToString();

  LogPrint("blk", ret.str().c_str());
  return ret.str();
}


/* clang-format off */
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "genesis",                &genesis,                true  },
};
/* clang-format on */

void RegisterGenesisRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
