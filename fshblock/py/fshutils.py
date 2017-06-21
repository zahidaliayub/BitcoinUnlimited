#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Unlimited developers
# Portions Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import binascii
import decimal

from test_framework.wallet import *
from test_framework.script import *
from test_framework.key import *
from test_framework.chainparams import *

# "Compact" integer in the Satoshi C++
def ser_uint(i):
    assert(i >= 0)
    r = b""
    if i < 253:
        r = struct.pack("B", i)
    elif i < 0x10000:
        r = struct.pack("<BH", 253, i)
    elif i < 0x100000000:
        r = struct.pack("<BI", 254, i)
    else:
        r = struct.pack("<BQ", 255, i)
    return r


# "Compact" integer in the Satoshi C++
def deser_uint(f):
    if type(f) is str:
        f = unhexlify(f)
    if type(f) is bytes:
        f = BytesIO(f)

    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]

    return nit

def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]


def dataTxo(data, txo=None):
    """Adds creates an empty output with data, or appends data onto an existing one"""

    assert(type(data) == bytes)

    if txo is None:
        txo = CTxOut(0, CScript([OP_RETURN]))
    elif isinstance(txo, CScript):
        txo = CTxOut(0, txo)
    elif isinstance(txo, CTxOut):
        pass
    else:
        raise IllegalArgumentTypeError("txo must be a CScript or a CTxOut")

    commitScript = txo.scriptPubKey

    if 0:  # already done by commitScript += data
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
        raise  TypeError("obj must be a CBitcoinAddress")
    return obj
