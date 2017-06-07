#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Unlimited developers
# Copyright (c) 2014-2016 The Bitcoin Core developers
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

EXPEDITED_VERSION = 80002

# class InvResp(Flags):
REQ_TX = 1
REQ_THINBLOCK = 2
REQ_XTHINBLOCK = 4
REQ_BLOCK = 8


CONTINUITY_AMT = 1
#def        signTx(node, txn):
#    a0 = hexlify(serialize(txn))
#    for i in txn.txin:
#        a1.append(
#    a1 = {}
#    d["txid"

def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]


def dataTxo(data, txo=None):
    """Adds creates an empty output with data, or appends data onto an existing one"""
    if txo is None:
        txo = CTxOut(0, CScript([OP_RETURN]))
    elif isinstance(txo, CScript):
        txo = CTxOut(0, txo)
    elif isinstance(txo, CTxOut):
        pass
    else:
        raise IllegalArgumentTypeError("txo must be a CScript or a CTxOut")

    commitScript = txo.scriptPubKey

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
    txo.scriptPubKey = commitScript
    return txo

def createCTxIn(utxoInput):
    """Return a CTxIn given a dictionary in wallet format, a COutPoint, or a CTxIn"""
    if isinstance(utxoInput, CTxIn):
        return utxoInput

    if isinstance(utxoInput, dict):
        txidNum = uint256_from_str(lx(utxoInput["txid"]))
        txin = CTxIn(COutPoint(txidNum,int(utxoInput["vout"])))
        txin.nSequence = 0
        return txin

    if isinstance(utxoInput, COutPoint):
        txin = CTxIn(utxoInput)
        txin.nSequence = 0
        return txin

    raise  IllegalArgumentTypeError("input must be a CTxIn or a dictionary in wallet format")


def createTxoScript(btcAddress):
    """Create a CScript that forces a payer to sign with the provided address
    btcAddress: object of type CBitcoinAddress
    """
    #TODO multisig
    assert(isinstance(btcAddress, CBitcoinAddress))
    ret = CScript([OP_DUP, OP_HASH160, btcAddress, OP_EQUALVERIFY, OP_CHECKSIG])
    return ret

def getValue(tx):
    """Returns the value (amount of BTC) in a CTxIn in Satoshis"""
    return 1*COIN  # TODO

def obj2Str(txn):
    rawtx = binascii.hexlify(txn.serialize())
    rawtxStr = rawtx.decode()
    return rawtxStr

def isSha256Str(s):
    # TODO
    return False

def hashIntForm(obj):
    if type(obj) is int:
        return obj
    elif type(obj) is bytes:
        return uint256_from_str(obj)
    elif type(obj) is str:  # strings are assumed to be in hex format
        return uint256_from_str(lx(obj))
    else:
        raise  IllegalArgumentTypeError("Need an integer or binary data")

def toSatoshis(inAmt):
    """Convert arg to integer Satoshis
    inAmt: something convertable to a number. If Decimal we assume its specced in BTC

    """
    if isinstance (inAmt, decimal.Decimal):
        qty = int(inAmt * COIN)
    elif type(inAmt) == int:
        qty = inAmt
    else:
        raise  IllegalArgumentTypeError("BTC quantities must be either Decimal(BTC) or int(Satoshi)")
    return qty

def regularizeBitcoinAddress(obj):
    """Take a bitcoin address of different formats and convert into a CBitcoinAddress object"""
    # Regularize the type of obj
    if isinstance(obj, str):
        obj = CBitcoinAddress(obj)
    if isinstance(obj, CPubKey):
        # obj = CBitcoinAddress(obj.getP2PKHAddress())
        # TODO add member function of CPubKey or CBitcoinAddress to do this:
        obj = CBitcoinAddress.from_bytes(obj.getP2PKHAddress(),Params().BASE58_PREFIXES['PUBKEY_ADDR'])


    if not isinstance(obj, CBitcoinAddress):
        raise  IllegalArgumentTypeError("obj must be a CBitcoinAddress")
    return obj


class IllegalArgumentTypeError(TypeError):
    pass

class FshBlock():
    """Extension block"""
    def __init__(self,parent = None):
        self.idver=1
        self.height=0
        self.txMerkleTree=0
        self.utxoCommitment=0
        self.prevBlockHash=0
        self.time = 0
        self.bits = 0
        self.nonce0=0
        self.nonce1=0

        # RAM only
        self.hash = None

        if type(parent) is bytes:
            parent = uint256_from_str(parent)
        elif parent:
            self.prevBlockHash = parent.getHash()

    def serializeHeader(self):
        r = b""
        r += struct.pack("<i", self.idver)
        r += struct.pack("<Q", self.height)
        r += struct.pack("<I", self.time)
        r += struct.pack("<I", self.bits)
        r += ser_uint256(self.txMerkleTree)
        r += ser_uint256(self.prevBlockHash)
        return r

    def serialize(self):
        r = serializeHdr()
        r += struct.pack("<Q", self.nonce)
        return r

    def rehash(self):
        """Hashing the FSH block happens slightly differently than Bitcoin blocks.
        First the block header is hashed using SHA256.
        Then this hash + the nonce is hashed.
        (this defeats ASICboost)
        SHA256 uses rounds of 64 bytes.  the sha256 of the header uses 32 bytes.  Next use 16 bytes of nonce for a total message size of 48 bytes
        """
        hdr = self.serializeHeader()
        shaHdr = sha256(hdr)

        # miners would grind this:
        r = shaHdr + struct.pack("<Q", self.nonce0) + struct.pack("<Q", self.nonce1)
        self.hash = uint256_from_str(hash256(r))
        return self.hash

    def getHash(self):
        """return the hash of this block, calculated if needed as an integer"""
        if self.hash == None:
            self.rehash()
        return self.hash


class FshBitcoinUtxoSet():
    def __init__(self):
        self.utxos = {}

    def getSpendableUtxos(self, amountInSatoshis):
        """return a list of UXTOs on the bitcoin blockchain worth at least amountInSatoshis
        """
        # TODO
        return []

class FshBitcoinTxn(CTransaction):
    GENESIS_TXO_IDX = 2
    CONTINUITY_TXO_IDX = 1
    FSH_BLOCK_TXO_IDX = 0
    def __init__(self):
        super(FshBitcoinTxn, self).__init__()

    def instantiated(self, blockHash, height, txHash, txIdx):
        """ Indicate where this transaction was instantiated in the bitcoin blockchain
        """
        self.blockHash = hashIntForm(blockHash)
        self.height = height
        self.txHash = hashIntForm(txHash)
        self.txIdx = txIdx

    def getContinuityUtxo(self):
        """Returns the UXTO in the bitcoin blockchain that needs to be spent by the next update transaction"""
        return COutPoint(self.txHash, self.CONTINUITY_TXO_IDX)

class FshGenesisTxn(FshBitcoinTxn):
    def __init__(self, docOrCommitment, fshGenesisBlock, utxoInput, depositAddress, backingAddress, change, continuityAmt=CONTINUITY_AMT, feePerKb = 0):
        """
        docOrCommitment: a hash or string of the extension block contract
        fshGenesisBlock: block object corresponding to the first fsh block
        """
        super(FshGenesisTxn, self).__init__()


        # input parameter validation and conversion to a canonical format
        depositAddress = regularizeBitcoinAddress(depositAddress)
        backingAddress = regularizeBitcoinAddress(backingAddress)

        if type(docOrCommitment) == str:
            if not isSha256Str(docOrCommitment):
                docOrCommitment = sha256(docOrCommitment.encode())

        self.docCommitment = docOrCommitment #

        txn = self

        # Fixup the input
        txn.vin.append(createCTxIn(utxoInput));

        # block hash output.  Should this be a separate UTXO like here, or part of the continuity utxo?
        # txo 0 will ALWAYS be the block
        blkout = dataTxo(ser_uint256(fshGenesisBlock.getHash()))
        txn.vout.append(blkout)

        # txo 1 will ALWAYS be the continuity
        continuityAmt = toSatoshis(continuityAmt)
        # extension block continuity output.  The amount that is sent does not really matter
        txn.vout.append(CTxOut(continuityAmt,createTxoScript(backingAddress)))

        # txo 2 will be the chain genesis information for genesis transactions
        # Format of this 0 value data TXO is depositAddress, backingAddress, OP_RETURN, SHA256 commitment describing the extension block
        docout = CScript([OP_RETURN,depositAddress, backingAddress])
        docout = dataTxo(docOrCommitment, docout)
        txn.vout.append(docout)

        # Any number of "normal" txos can follow
        # next add change

        if isinstance(change, CTxOut):
            # don't touch it if they gave us a change CTxOut
             pass
        elif isinstance (change, CBitcoinAddress):
            txoutScript = createTxoScript(change)
            fee = feePerKb * 1 # TODO estimate fee
            change = CTxOut((utxoInput["amount"]*COIN)-continuityAmt-fee, txoutScript)
        else:
            raise  IllegalArgumentTypeError("change must be an object of type CTxOut or CBitcoinAddress")
        txn.vout.append(change)

        txn.rehash()


class FshUpdateTxn(FshBitcoinTxn):
    def __init__(self, fshBlockCommitment, fshPriorTxUtxo, inputs, outputs, feeFromFshBlock, fshUtxos, backingAddress, continuityAmt=CONTINUITY_AMT):
        """It is the caller's responsibility to ensure that the fshBlock is consistent with the inputs, outputs,
           and fee selected in this transaction.
        fshBlockCommitment: hash of the new FSH block
        fshPriorTxUxto: the continuity utxo: defined in the prior update tx, to be spent in this block
        inputs: list of CTxIn or a dictionary in wallet format
        outputs: list of CTxOut or tuple(amount, address)
        feeFromFshBlock: BTC from fees in the Fsh block that should be paid to miners for this transaction
            (so the fsh ext block is no longer tracking this balance)
        fshUtxos: an object providing access to all the backing Utxos (all the BTC funds sequestered), in case
            additional money is needed for withdrawal.
        """
        super(FshUpdateTxn, self).__init__()

        # Regularize the type of backingAddress
        backingAddress = regularizeBitcoinAddress(backingAddress)

        # add in the inputs
        inputBtc = 0
        inputs.append(fshPriorTxUtxo)
        for i in inputs:
            tx = createCTxIn(i)
            self.vin.append(tx)
            inputBtc += getValue(i)

        # TX0 will always be the FSH block commitment
        self.vout.append(dataTxo(ser_uint256(fshBlockCommitment)))

        # TX1 is always the continuity output
        continuityAmt = toSatoshis(continuityAmt)
        # extension block continuity output.  The amount that is sent does not really matter
        continuityScript = createTxoScript(backingAddress)
        self.vout.append(CTxOut(continuityAmt,continuityScript))

        # now append the money moving out of the extension block
        outputBtc = 0
        for j in outputs:
            if isinstance(j, CTxOut):
                # don't touch it if they gave us a change CTxOut
                tx = j
            elif type(j) is tuple:
                qty = toSatoshis(j[0])
                if isinstance (j[1], CBitcoinAddress):
                    txoutScript = createTxoScript(j[1])
                    tx = CTxOut(qty, txoutScript)
                else:
                    raise  IllegalArgumentTypeError("output must be an object of type CTxOut or tuple(amount,CBitcoinAddress)")
            else:
                raise  IllegalArgumentTypeError("output must be an object of type CTxOut or tuple(amount,CBitcoinAddress)")
            outputBtc += tx.nValue
            self.vout.append(tx)

        # more is going out than coming in.  We need to grab inputs from "savings"
        if inputBtc < feeFromFshBlock + outputBtc:
            addtlInputs = fshUtxos.getSpendableUtxos( (feeFromFshBlock + outputBtc) - inputBtc)

        self.rehash()


class FshBackingUtxoSet:
    """This class tracks all the UTXOs on the bitcoin blockchain that are backing funds in the extension block"""
    def __init__(self,):
        self.pendingInTx = [] # transactions that are incoming
        pass
    def acceptBitcoinBlock(self, block):
        """Parses the bitcoin block, extracting what is interesting to the FSH extension blocks"""

class FshCommitmentDb:
    """This class tracks all the FSH commitment transactions (its the SPV of FSH blocks)"""
    def __init__(self, dbfile):
        self.dbfile = dbfile
        self.db = leveldb.LevelDB(dbfile)
    def insert(self):
        pass

class FshCommitmentRamDb:
    """This class tracks all the FSH commitment transactions (its the SPV of FSH blocks)"""
    def __init__(self, dbfile):
        self.dbfile = dbfile
        self.db = {}

    def insert(self,fshblock, tx):
        self.db[fshblock] = tx


class FshExtensionBlockChain:
    def __init__(self, depositAddress, backingAddress, dbdir=None):
        self.backingAddress = regularizeBitcoinAddress(backingAddress)
        self.depositAddress = regularizeBitcoinAddress(depositAddress)
        self.pendingInflows = [] # transactions that are incoming
        self.backingUtxos = FshBackingUtxoSet()

        if dbdir:
            self.dbdir = dbdir
            commitDbFile = os.path.join(self.dbdir,"commitments.db")
            self.fshCommitmentTx = FshCommitmentDb(commitDbFile)  # all the fsh transactions that have been on the bitcoin blockchain
        else:
            self.fshCommitmentTx = FshCommitmentRamDb()

    def acceptBitcoinBlock(self, block, ptx):
        """Parses the bitcoin block, extracting what is interesting to the FSH extension blocks"""
        print(block)
        tx = []
        for t in ptx:
            if isinstance(t, CTransaction):
                tx.append(t)
            else:
                tmptx = CTransaction().deserialize(t)
                print(t)
                print(tmptx)
                tx.append(tmptx)

        for t in tx:
            fshBlockHash = None
            if t.vout[FshBitcoinTxn.FSH_BLOCK_TXO_IDX].nValue == 0:  # for any tx relevant to the FSH ext blocks, vout[0]'s value is 0
                # TODO: validate that this tx is signed by the backingAddress
                scr = CScript(t.vout[FshBitcoinTxn.FSH_BLOCK_TXO_IDX].scriptPubKey)
                fshBlockHash = hexlify(list(scr)[1])
                print ("FSH block hash: ", hexlify(list(scr)[1]))
                for op in scr:
                    print(op)
                    if not isinstance(op, CScriptOp):
                        print(hexlify(op))
                scr = CScript(t.vout[FshBitcoinTxn.CONTINUITY_TXO_IDX].scriptPubKey)
                continuityAddr = CBitcoinAddress.from_scriptPubKey(scr)
                print("Continuity Addr: " + str(continuityAddr))
            if len(t.vout) > FshBitcoinTxn.GENESIS_TXO_IDX and t.vout[FshBitcoinTxn.GENESIS_TXO_IDX].nValue == 0:  # this is the genesis transaction
                pdb.set_trace()
                scr = CScript(t.vout[FshBitcoinTxn.FSH_BLOCK_TXO_IDX].scriptPubKey)
                for op in scr:
                    print(op)
                    if not isinstance(op, CScriptOp):
                        print("as hex: " + str(hexlify(op)))
                        print("as addr: " +  str(P2PKHBitcoinAddress.from_bytes(op)))
            if fshBlockHash:
                fshCommitmentTx.insert(fshBlockHash, t)


#     CONTINUITY_TXO_IDX = 1
        pdb.set_trace()

        pass



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
            pdb.set_trace()
            blockInfo = node.getblock(b)
            txList = []
            for txhash in blockInfo['tx']:
                txdata = node.gettransaction(txhash)
                txList.append(txdata["hex"])
            fbc.acceptBitcoinBlock(blockInfo,txList)

        pdb.set_trace()



    def run_test(self):
        # Receive a block of all types

        # I need to create a nontrivial block so thin and xthin saves space.

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
