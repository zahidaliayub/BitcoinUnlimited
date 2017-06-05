// Copyright (c) 2017 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stream>
#include <string>
#include <boost/lexical_cast.hpp>

#include "arith_uint256.h"
#include "base58.h"
#include "chainparams.h"
#include "pow.h"
#include "rpc/server.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "consensus/validation.h"

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
  int genesisBits = UintToArith256(conp.powLimit).GetCompact();  // default to easiest block supported by this chain
  if (params.size() > 2)
  {
      std::string genesisDiffs = params[2].getValStr();
      if (genesisDiffs[1] == 'x' || genesisDiffs[1] == 'X')
      {
          genesisBits = std::stoul(genesisDiffs, nullptr, 16);
      }
      else
      {
          genesisBits = boost::lexical_cast<int>(genesisDiffs);
      }
  }

  CBitcoinAddress payaddress(params[0].get_str());
  if (!payaddress.IsValid())
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");

  arith_uint256 bnTarget;
  bool fNegative, fOverflow;

  bnTarget.SetCompact(genesisBits, &fNegative, &fOverflow);
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
  // BIP34 height prefix
  CBlock block = CreateGenesisBlock(CScript() << 0, genesisComment, outputScript, GetTime(), 0,
                                    genesisBits, 1, genesisReward);
  CBlock *pblock = &block;
  proposedGenesisBlock = pblock;
  uint256 hash = pblock->GetHash();

  while (!CheckProofOfWork(hash, pblock->nBits, conp))
  {
      if (++pblock->nNonce == 0)
          throw JSONRPCError(RPC_MISC_ERROR, "could not solve for a block");
      if (pblock->nNonce % 10000000 == 0)
          LogPrintf("Nonce: %u\n", pblock->nNonce);
      hash = pblock->GetHash();
  }

  proposedGenesisBlock = NULL;

  CValidationState state;

  std::ostringstream ret;
  std::string hexOutScript = HexStr(outputScript);

  ret << "CreateGenesisBlock() parameters: Prefix: CScript() << 0 Comment: " << genesisComment << " OutputScript: ParseHex(\"" << hexOutScript << "\") Time: " << pblock->nTime << " Nonce: " << pblock->nNonce << " nBits: " << pblock->nBits << " Version: " << pblock->nVersion << " Reward: " << genesisReward << "\n";

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
