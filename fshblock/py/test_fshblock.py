#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# wait for py3.6: from enum import Enum,Flag
import binascii

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import create_block, create_coinbase
from test_framework.wallet import *
from test_framework.script import *
from test_framework.key import *
from test_framework.chainparams import *

from fshutils import *
from fshblock import *


class TestClass(BitcoinTestFramework):
    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0,self.options.tmpdir, ["-rpcservertimeout=0"], timewait=60*10))

    def createUtxos(self, node, addrs, amt):
        wallet = node.listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=True)
        # Create a LOT of UTXOs
        logging.info("Create lots of UTXOs...")
        n = 0
        group = min(100, amt)
        count = 0
        for w in wallet:
            count += group
            split_transaction(node, [w], addrs[n:group + n])
            n += group
            if n >= len(addrs):
                n = 0
            if count > amt:
                break
        logging.info("mine blocks")
        node.generate(1)  # mine all the created transactions
        logging.info("sync all blocks and mempools")


    def fshTest(self, coins, node):

        fshUtxos = FshBackingUtxoSet()

        change = CBitcoinAddress(node.getnewaddress())

        # to allow this script to sign FSH tx
        #fshDepositSecret = CKey("this way to the egress")
        #fshBackingSecret = CKey("stand your ground")
        #fshDepositAddr = fshDepositSecret.pub
        #fshBackingAddr = fshBackingSecret.pub

        # to allow node to sign FSH tx get addresses from the node
        fshDepositAddr = node.getnewaddress()
        fshBackingAddr = node.getnewaddress()

        blocks = []

        fshGenesisBlock = FshBlock()
        genesisTx = FshGenesisTxn("example doc", fshGenesisBlock, coins, fshDepositAddr, fshBackingAddr, change)
        print("contract hash: %s\ndeposit addr: %s\nbacking addr: %s\nfsh genesis block hash: %s\n" %
              ("", # hexlify(ser_uint256(genesisTx.docCommitment)),
               fshDepositAddr,
               fshBackingAddr,
               hexlify(ser_uint256(fshGenesisBlock.getHash()))))

        fcts = obj2Str(genesisTx)

        ret = node.signrawtransaction(fcts)
        if ret["complete"]:
            ret2 = node.sendrawtransaction(ret["hex"])
            print(ret2)
            if ret2:  # transaction was accepted
                ret3 = node.generate(1)
                print(ret3)
                blocks.append(ret3[0])
                blockInfo = node.getblock(ret3[0])
                idx = blockInfo["tx"].index(ret2)  # what's the transaction index?
                genesisTx.instantiated(blockInfo["hash"],blockInfo["height"],ret2,idx) # Tell the TX where it appeared in the blockchain
            else:
                assert(0)
        else:
            assert(0)

        alltx = [genesisTx]
        priorTx = genesisTx
        priorFshBlk = fshGenesisBlock
        # now create updates:
        for i in range(1,10):
            print("block %d" % i)
            fshBlk = FshBlock(priorFshBlk)
            nxtTx = FshUpdateTxn(fshBlk.getHash(), priorTx.getContinuityUtxo(), [], [], 0, fshUtxos, fshBackingAddr )  #, inputs, outputs, feeFromFshBlock, fshUtxos)
            nxts = obj2Str(nxtTx)
            nret1 = node.signrawtransaction(nxts)
            #print ("signing response: %s" % str(nret1))
            if nret1["complete"]:
                nret2 = node.sendrawtransaction(nret1["hex"])
                #print("Send raw response: %s" % nret2)
                if nret2:
                    nret3 = node.generate(1)
                    print(nret3)
                    blocks.append(nret3[0])
                    blockInfo = node.getblock(nret3[0])
                    idx = blockInfo["tx"].index(nret2)  # what's the transaction index?
                    nxtTx.instantiated(blockInfo["hash"],blockInfo["height"],nret2,idx)  # Tell the TX where it appeared in the blockchain
            else:
                pdb.set_trace()
            alltx.append(nxtTx)
            priorTx = nxtTx
            priorFshBlk = fshBlk
        print("FSH TEST COMPLETE")
        print(alltx)

        fbc = FshExtensionBlockChain(fshDepositAddr, fshBackingAddr)
        for b in blocks:
            blockInfo = node.getblock(b)
            txList = []
            for txhash in blockInfo['tx']:
                txdata = node.gettransaction(txhash)
                txList.append(txdata["hex"])
            fbc.acceptBitcoinBlock(blockInfo,txList)

        pdb.set_trace()



    def run_test(self):

        # first create addrs
        # self.nodes[0].keypoolrefill(100)
        # addrs = [self.nodes[0].getnewaddress() for _ in range(100)]
        # self.createUtxos(self.nodes[0], addrs, 100)

        node = self.nodes[0]

        addr1 = node.getnewaddress()

        wallet = node.listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=True)
        self.fshTest(wallet[1], node)

        txidNum = uint256_from_str(lx(wallet[0]["txid"]))
        txin = CTxIn(COutPoint(txidNum,int(wallet[0]["vout"])))
        txin.nSequence = 0
        txinSPK = wallet[0]["scriptPubKey"]

        # outAddr = CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8')
        outAddr = CBitcoinAddress(addr1)

        txoutScript = CScript([OP_HASH160, outAddr, OP_EQUAL])
        # [OP_DUP, OP_HASH160, self, OP_EQUALVERIFY, OP_CHECKSIG]
        fee = 0
        txout = CTxOut((wallet[0]["amount"]*COIN)-fee, txoutScript)

        data = "foo"
        commitScript = CScript([OP_RETURN])
        if len(data) == 0:
            pass
        elif len(data) < 75:
            commitScript += CScriptOp(len(data))
        elif len(data) < 256:
            commitScript += OP_PUSHDATA1
            commitScript += len(data)
        elif len(data) < 0x10000:
            commitScript += OP_PUSHDATA2
            commitScript += len(data)
        else:
            commitScript += OP_PUSHDATA4
            commitScript += len(data)

        commitScript += data
        txoutCommitment = CTxOut(0, commitScript)

        txn = CTransaction()
        txn.vin.append(txin)
        txn.vout.append(txout)
        txn.vout.append(txoutCommitment)
        txn.rehash()
        rawtx = binascii.hexlify(txn.serialize())
        rawtxStr = rawtx.decode()
        ret = node.signrawtransaction(rawtxStr)
        if ret["complete"]:
            ret2 = node.sendrawtransaction(ret["hex"])
            print(ret2)

        blockhash = node.generate(1)
        print("block hash is %s" % str(blockhash))

        # now create the python BU node
        pybu = BasicBUNode()
        pybu.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0])

        # set it to request all block types when an INV comes in
        pybu.cnxns[0].requestOnInv = REQ_BLOCK | REQ_THINBLOCK | REQ_XTHINBLOCK

        NetworkThread().start()  # Start up network handling in another thread

        # Now create a block with lots of tx
        node = self.nodes[0]
        wallet = node.listunspent()
        reverse = copy.copy(wallet)
        wallet.sort(key=lambda x: x["amount"], reverse=False)
        reverse.sort(key=lambda x: x["amount"], reverse=True)

        try:
            for (a, b) in zip(wallet, reverse):
                node.sendtoaddress(b["address"], a["amount"])
        except JSONRPCException as e:
            pass

        # ok this mined block should make thin & xthin blocks
        node.generate(1)

        # Wait for the blocks to come in
        while pybu.nblocks == 0 or pybu.nthin == 0 or pybu.nxthin == 0:
            time.sleep(.25)
        print("received all block types")


if __name__ == '__main__':
    Test().main()

def info(type, value, tb):
   pdb.set_trace()
   if hasattr(sys, 'ps1') or not sys.stderr.isatty():
      # we are in interactive mode or we don't have a tty-like
      # device, so we call the default hook
      sys.__excepthook__(type, value, tb)
   else:
      import traceback, pdb
      # we are NOT in interactive mode, print the exception...
      traceback.print_exception(type, value, tb)
      print
      # ...then start the debugger in post-mortem mode.
      pdb.pm()

sys.excepthook = info

def Test():
    t = TestClass()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],  # "lck"
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    t.main(["--tmpdir=/ramdisk/test", "--nocleanup", "--noshutdown"], bitcoinConf, None)  # , "--tracerpc"])
