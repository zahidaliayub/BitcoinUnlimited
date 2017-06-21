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

# How many satoshis to use for the continuity transaction
CONTINUITY_AMT = 1

def compactNumber(mantissa, exp):
    return mantissa&0xffffff | (exp << 24)

class IllegalArgumentTypeError(TypeError):
    pass

class Error(Exception):
    def __init__(self, message):
        super().__init__(message)

class FshBlock():
    """Extension block"""
    def __init__(self,parent = None):
        """Pass the parent FshBlock if you know what it is"""
        self.idver=1
        self.height=0
        self.txHashTree=None
        self.utxoCommitment=0
        self.prevBlockHash=None
        self.time = 0
        self.bits = compactNumber(0xffffff, 0x20)
        self.nonce0=0
        self.nonce1=0

        # RAM only
        self.hashval = None

        self.connect(parent)

    def serializeHeader(self):
        r = b""
        r += struct.pack("<i", self.idver)
        r += struct.pack("<Q", self.height)
        r += struct.pack("<I", self.time)
        r += struct.pack("<I", self.bits)
        # r += ser_uint256(self.txHashTree)
        r += self.txHashTree
        # r += ser_uint256(self.prevBlockHash)
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
        #self.hashval = uint256_from_str(hash256(r))
        self.hashval = hash256(r)
        return self.hashval

    def solve(self, chunk=None):
        if not chunk is None:
            self.nonce1 = chunk

        hdr = self.serializeHeader()
        shaHdr = sha256(hdr)

        difficulty = uint256_from_compact(self.bits)
        # miners would grind this.  TODO make sure asics can do it
        while 1:
            r = shaHdr + struct.pack("<Q", self.nonce0) + struct.pack("<Q", self.nonce1)
            self.hashval = hash256(r)
            hashint = uint256_from_str(self.hashval)
            if hashint <= difficulty:
                break
            self.nonce0 += 1
        return self.hashval

    def connect(self,parent):
        if type(parent) is bytes:
            self.prevBlockHash = parent
        elif parent:
            self.prevBlockHash = parent.hash()
            self.height = parent.height+1


    def hash(self):
        """return the hash of this block, calculated if needed as an integer"""
        if self.hashval == None:
            self.rehash()
        return self.hashval

    def getOutflowTx(self):
        """Generate the set of bitcoin txos that correspond to outflows defined in this extension block"""
        pass

    def validate(self, fshUtxoSet, bitcoinTxi=None, bitcoinTxo=None):
        """Validate this extension block given what is not spent in the fsh blockchain, and the bitcoin inflow and outflow.  If this is an intermediary block (not part of a bitcoin transaction) then bitcoinTxi and bitcoinTxo must be None."""
        pass

class FshBackingUtxoSet:
    """This class tracks all the UTXOs on the bitcoin blockchain that are backing funds in the extension block"""
    def __init__(self,):
        self.pendingInTx = [] # transactions that are incoming
        self.utxos = {}
        pass

    def acceptBitcoinBlock(self, block):
        """Parses the bitcoin block, extracting what is interesting to the FSH extension blocks"""
        pass

    def getSpendableUtxos(self, amountInSatoshis):
        """return a list of UXTOs on the bitcoin blockchain worth at least amountInSatoshis
        """
        # TODO
        return []


class FshCommitmentDb:
    """This class tracks all the FSH commitment transactions (its the SPV of FSH blocks)"""
    def __init__(self, dbfile):
        self.dbfile = dbfile
        self.db = leveldb.LevelDB(dbfile)
    def insert(self):
        pass
    def insertGenesis(self,fshblock, tx):
        pass

class FshBitcoinTxn(CTransaction):
    GENESIS_TXO_IDX = 2
    CONTINUITY_TXO_IDX = 1
    FSH_BLOCK_TXO_IDX = 0

    EXT_BLOCK_HASH_SCRIPT_IDX = 1
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
    DEPOSIT_ADDRESS_SCRIPT_IDX = 1
    BACKING_ADDRESS_SCRIPT_IDX = 2

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



class FshCommitmentRamDb:
    """This class tracks all the FSH commitment transactions (its the SPV of FSH blocks)"""
    def __init__(self):
        self.db = {}
        self.genesisBlockHash = None
        self.genesisTx = None

    def insert(self,fshblock, tx):
        self.db[fshblock] = tx

    def insertGenesis(self,fshblock, tx):
        self.genesisBlockHash = fshblock
        self.genesisTx = tx


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
            # Is this a FSH block transaction?
            if t.vout[FshBitcoinTxn.FSH_BLOCK_TXO_IDX].nValue == 0:  # for any tx relevant to the FSH ext blocks, vout[0]'s value is 0
                # TODO: validate that this tx is signed by the backingAddress

                # extract the first extension block hash
                scr = CScript(t.vout[FshBitcoinTxn.FSH_BLOCK_TXO_IDX].scriptPubKey)
                fshBlockHash = list(scr)[FshBitcoinTxn.EXT_BLOCK_HASH_SCRIPT_IDX]
                print ("FSH block hash: ", hexlify(list(scr)[1]))
                for op in scr:
                    print(op)
                    if not isinstance(op, CScriptOp):
                        print(hexlify(op))

                # extract the continuity address
                scr = CScript(t.vout[FshBitcoinTxn.CONTINUITY_TXO_IDX].scriptPubKey)
                continuityAddr = CBitcoinAddress.from_scriptPubKey(scr)
                print("Continuity Addr: " + str(continuityAddr))

                # Is this the genesis transaction?
                if len(t.vout) > FshBitcoinTxn.GENESIS_TXO_IDX and t.vout[FshBitcoinTxn.GENESIS_TXO_IDX].nValue == 0:
                    scr = CScript(t.vout[FshBitcoinTxn.GENESIS_TXO_IDX].scriptPubKey)
                    lst = list(scr)

                    # Extract the deposit and backing addresses from this transaction, and validate them if addresses were supplied
                    # otherwise set the appropriate class attribute
                    depositAddress = P2PKHBitcoinAddress.from_bytes(lst[FshGenesisTxn.DEPOSIT_ADDRESS_SCRIPT_IDX])
                    if self.depositAddress:
                        if self.depositAddress != depositAddress:
                            raise Error("Genesis block deposit address %s does not match passed deposit address %s" % (depositAddress,self.depositAddress))
                    else:
                        self.depositAddress = depositAddress
                    backingAddress = P2PKHBitcoinAddress.from_bytes(lst[FshGenesisTxn.BACKING_ADDRESS_SCRIPT_IDX])
                    if self.backingAddress:
                        if self.backingAddress != backingAddress:
                            raise Error("Genesis block backing address %s does not match passed backing address %s" % (backingAddress,self.backingAddress))
                    else:
                        self.depositAddress = depositAddress

                    self.fshCommitmentTx.insertGenesis(fshBlockHash, t)

            if fshBlockHash:
                self.fshCommitmentTx.insert(fshBlockHash, t)


        pass


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


def Test():
    sys.excepthook = info
    pass
