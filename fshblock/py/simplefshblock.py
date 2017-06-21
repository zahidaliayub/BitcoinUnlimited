#!/usr/bin/env python3.6
# Copyright (c) 2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import time
import pdb
import hashlib

from fshutils import *
import fshblock

TX_HASH_LEN = 32  # 256 bits


def hash(x):
    return hashlib.blake2b(x,digest_size=TX_HASH_LEN).digest()


def calcMerkle(lst):
    if len(lst) == 1:
        return lst[0].hash()
    if len(lst) == 2:
        return hash(lst[0].hash() + lst[1].hash())
    half = int(len(lst)/2)
    # inefficiently create new lists
    return hash(calcMerkle(lst[0:half]) + calcMerkle(lst[half:]))

class Error(Exception):
    def __init__(self, message):
        super().__init__(message)

class SerBytes:
    def __init__(self, data=None):
        super().__init__()
        self.bytes = data
    def serialize(self):
        return ser_string(self.bytes)
    def deserialize(self,f):
        if type(f) is str:
            f = unhexlify(f)
        if type(f) is bytes:
            f = BytesIO(f)
        self.bytes = deser_string(f)
        return self

    def __eq__(self, other):
        if isinstance(other, SerBytes):
            return self.__dict__ == other.__dict__
        return False

#class PubKey:
#    def __init__(self):
#        pass

class Signature:
    def __init__(self):
        pass

class SimpleTxOut:
    """All txouts are pay-to-hash.  This saves utxo space"""
    def __init__(self, hash=None, value=None):
        if not hash is None:
            assert(type(hash) is bytes)
            assert(len(hash) == TX_HASH_LEN)
            self.hashbytes = hash
            self.value = value

#    @classmethod
#    def spendTo(cls, value, address):
#        return cls(address, value)

    def deserialize(self, f):
        if type(f) is str:
            f = unhexlify(f)
        if type(f) is bytes:
            f = BytesIO(f)
        self.hashbytes = f.read(TX_HASH_LEN)
        self.value = deser_uint(f)
        return self

    def serialize(self):
        return self.hashbytes + ser_uint(self.value)

    def serializeForSigning(self):
        return self.serialize()

    def __eq__(self, other):
        return self.hashbytes == other.hashbytes

class SimpleTxIn:
    def __init__(self, blockNum=None, txIndex=None, voutIndex=None, signatures=None, blockHash=None, value=None,    pubKey=None,nonce=0, atleast=None):
        # data that is hashed for the TXO:
        self.signatures = None
        self.atleast = atleast
        self.setPubKeys(pubKey)
        # TODO: self.nonce = nonce  # The nonce allows a payer to send to the same address, but create a different utxo hash

        # integer block count.  Genesis block is 0
        self.blockNum = blockNum
        # integer tx index in the block
        self.txIndex = txIndex
        # integer output index in the tx
        self.voutIndex = voutIndex

        # TXin data
        # TODO: to allow half-transactions: self.txSignRange =
        if signatures == None:
            self.signatures = [None] * len(self.pubKeys)
        elif not type(signatures) is list:
            self.signatures = [signatures]
        else:
            self.signatures = signatures

        # this info is not serialized, but is needed to sign the transaction
        self.blockHash = blockHash
        # by allowing value to be None, we'll get errors if the caller doesn't set it
        self.value     = int(value) if not value is None else None

    def setPubKeys(self,pubKey):
        if pubKey is None:
            pubKey = []
        if not type(pubKey) is list:
            pubKey = [pubKey]
        if self.atleast is None:
            self.atleast = len(pubKey)
        assert(self.atleast <= len(pubKey))
        self.pubKeys = pubKey
        if self.signatures == None or self.signatures == []:
            self.signatures = [None] * len(self.pubKeys)


    def setSignature(self,idx, sig):
        """Set the signature for a particular pubkey to the passed value"""
        assert(len(self.signatures) == len(self.pubKeys))
        self.signatures[idx] = sig


    def serializeP2H(self):
        assert(self.atleast != None)
        assert(self.pubKeys)
        for p in self.pubKeys:
            assert(p != None)
        r = b""
        r += struct.pack("<B", self.atleast)
        r += ser_vector([ SerBytes(x) for x in self.pubKeys])
        # TODO serialize nonce
        return r

    def getAddress(self):
        txInData = self.serializeP2H()
        return hash(txInData)

    def deserializeP2H(self,f):
        self.atleast = struct.unpack("<B", f.read(1))[0]
        self.pubKeys = deser_vector(f,SerBytes)
        # TODO deserialize nonce
        return self

    def getOutpoint(self):
        """Returns block,tx,vout triple that identifies this tx"""
        return self.blockNum, self.txIndex, self.voutIndex


    def getTxOut(self):
        """This returns a pay-to-hash txout that corresponds to this TxIn"""
        return SimpleTxOut(self.getAddress(),self.value)

    def emplace(self, block):
        """Update this txi based with where it is in this block"""
        txout = self.getTxOut()
        outpoint = block.findOutpoint(txout)
        if outpoint is None:
            raise Error("Not found in block") 
        (self.blockNum, self.txIndex, self.voutIndex) = outpoint
        self.blockHash = ser_uint256(block.hash())
        self.value     = block.tx[self.txIndex].vout[self.voutIndex].value


    def serialize(self):
        r = self.serializeP2H()
        r += ser_uint(self.blockNum)
        r += ser_uint(self.txIndex)
        r += ser_uint(self.voutIndex)
        r += ser_vector([SerBytes(x) for x in self.signatures])
        return r

    def serializeForSigning(self):
        """
        By including the vin's block hash in what is signed, we allow the transaction to include the smaller and more useful (allows fraud proofs) block.tx.vout indexing scheme in the stored data.
        By including the vin's input value, isolated wallets can sign transactions supplied by untrusted network connected devices.
        """
        r = self.serializeP2H()
        r += ser_uint(self.blockNum)
        r += ser_uint(self.txIndex)
        r += ser_uint(self.voutIndex)
        # unlike serialize(), don't serialize the signatures, since we are signing now!

        # now serialize info coming from the txo that this txi references:

        assert(self.blockHash) # make sure that the field is properly inited
        # make sure that field is properly inited and disallow use of 0 value txouts as input of another tx
        assert(self.value)
        r += self.blockHash # blockhash is already a byte array of known length
        r += ser_uint(self.value)
        return r

    def sighash(self):
        """Return the hash of this transaction serialized for signing
        """
        ser = self.serializeForSigning()
        return bhash(ser)

    def deserialize(self, f):
        if type(f) is str:
            f = unhexlify(f)
        if type(f) is bytes:
            f = BytesIO(f)
        self.deserializeP2H(f)
        self.blockNum = deser_uint(f)
        self.txIndex = deser_uint(f)
        self.voutIndex = deser_uint(f)
        self.signatures = [ x.bytes for x in deser_vector(f,SerBytes)]
        return self

    def equivalent(self, other):
        for s, s1 in zip(self.signatures, other.signatures):
            if s != s1: return False
        for s, s1 in zip(self.pubKeys, other.pubKeys):
            if s != s1: return False

        
        if self.blockNum  != other.blockNum:
            return False
        if self.txIndex  != other.txIndex:
            return False
        if self.voutIndex != other.voutIndex:
            return False
        return True
        
    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class SimpleTransaction(object):
    def __init__(self,vin=None, vout=None, validAtTime=None):
        # note no need for a version; use a new extension block: removed self.nVersion = 1.  This saves 4 bytes per tx

        if type(vin) is list:
            self.vin = vin
        else:
            self.vin = [vin]
        self.vin = list(filter(lambda x: not x is None, self.vin))

        self.vout = vout if type(vout) is list else [vout]
        self.vout = list(filter(lambda x: not x is None, self.vout))
        # validAtTime contains epoch seconds and serves 2 functions:
        # 1. similar to nLockTime, the tx cannot be commited to a block whose blockTime < validAtTime
        # 2. affects the ratio of fee that goes to the block miner vs the fee pool, to encourage rapid
        #    mining and mining the FSH block rather than only committing
        self.validAtTime = validAtTime
        if self.validAtTime is None:
            self.validAtTime = int(time.time())

        # not serialized:
        self.hashval = None

    def setBlock(self,block):
        for v in self.vin:
            pass

    def deserialize(self, f):
        if type(f) is str:
            f = unhexlify(f)
        if type(f) is bytes:
            f = BytesIO(f)
        self.vin = deser_vector(f, SimpleTxIn)
        self.vout = deser_vector(f, SimpleTxOut)
        self.validAtTime = deser_uint(f)
        self.hashbytes = None
        return self

    def serialize(self):
        assert(type(self.vin) is list)
        assert(type(self.vout) is list)
        assert(type(self.validAtTime) is int)
        r = b""
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += ser_uint(self.validAtTime)
        return r

    def serializeForSigning(self):
        """The transaction's vout is serialized with portions of the vin and every vin's block hash and input value.
        By including the vin's block hash in what is signed, we allow the transaction to include the smaller and more useful (allows fraud proofs) block.tx.vout indexing scheme in the stored data.
        By including the vin's input value, isolated wallets can sign transactions supplied by untrusted network connected devices.
        """
        assert(type(self.vin) is list)
        assert(type(self.vout) is list)
        assert(type(self.validAtTime) is int)

        r = b""
        for vin in self.vin:
            r += vin.serializeForSigning()
        for vout in self.vout:
            r += vout.serializeForSigning()
        r += ser_uint(self.validAtTime)
        return r

    def sighash(self):
        """Return the hash of this transaction serialized for signing
        """
        ser = self.serializeForSigning()
        return hash(ser)


    def rehash(self):
        """like hash but always recalculates"""
        self.hashval = None
        self.hash()
        return self.hashval

    def hash(self):
        """returns the hash, calculating only if hash not previously calculated"""
        if self.hashval is None:
            self.hashval = hashlib.blake2b(self.serialize(),digest_size=TX_HASH_LEN).digest()
        return self.hashval

    def __eq__(self, other):
        return self.vin == other.vin and self.vout == other.vout


class SimpleBlock(fshblock.FshBlock):
    MINT_TX_IDX = 0
    def __init__(self,tx = None, parent = None):
        fshblock.FshBlock.__init__(self, parent)
        if tx is None:
            self.tx = [None]
        else:
            self.tx = tx
        self.hashval = None
        if parent:
            self.finish(parent)

    def setMint(self, tx):
        self.tx[0] = tx

    def addValidatedTx(self):
        """include this transaction in the block"""
        pass

    def finish(self,prevBlock=None):
        self.txHashTree = calcMerkle(self.tx)
        self.utxoCommitment = 0  # TODO
        if prevBlock:
            self.connect(prevBlock)

    def findOutpoint(self, txout):
        txi = 0
        for tx in self.tx:
            outi = 0
            for out in tx.vout:
                if out == txout:
                    return (self.height, txi, outi)
                outi +=1
            txi+=1

    def difficulty(self):
        bits = self.bits
        diff = uint256_from_compact(self.bits)
        return diff

    def chainDifficulty(self):
        # todo calculate cumulative difficulty, for now return diff of last block
        return self.difficulty()

def testHashing():
    h = hash(b"1")
    i = hash(b"1")
    assert(h==i)

    class HashInt(int):
        def hash(self):
            r = b""
            r += struct.pack("<Q", self)
            return hash(r)

    merkleValueSet = set()
    if 1:
        lst = [ HashInt(x) for x in range(0,10)]
        m0 = calcMerkle(lst)
        lst1 = [ HashInt(x) for x in range(0,10)]
        m1 = calcMerkle(lst1)
        assert(m0==m1)
        merkleValueSet.add(m0)


def Test():
    testHashing()

    s = SimpleTransaction([],[])
    h = s.rehash()
    assert(len(h)==TX_HASH_LEN)
    s1 = SimpleTransaction([],[])
    h1 = s1.rehash()
    assert(h == h1)

    t = SimpleTxOut(hash(b"1234"),1000)
    b = t.serialize()
    t1 = SimpleTxOut().deserialize(b)
    assert(t1 == t)

    pk=SerBytes(b"1")
    t = SimpleTxIn(blockNum=0, txIndex=1, voutIndex=2, pubKey=SerBytes(b"1"),signatures=SerBytes(b"1"))
    b = t.serialize()
    t1 = SimpleTxIn().deserialize(b)
    assert(t1.equivalent(t))

    inp = [t]
    nextInp = SimpleTxIn(pubKey=SerBytes(b"2"),value=1000)
    out = [nextInp.getTxOut()]
    t = SimpleTransaction(inp,out)
    b = t.serialize()
    t1 = SimpleTransaction().deserialize(b)
    assert(t1 == t)
    pdb.set_trace()
