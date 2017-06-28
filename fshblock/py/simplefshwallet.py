import hashlib
import secrets

from simplefshblock import *

from test_framework.base58 import *
from test_framework.nodemessages import uint256_from_str

COIN = 100000000
mCOIN = COIN/1000

def bhash(x):
    if type(x) is int:
        assert(0)
        x = ser_uint256(x)
    if type(x) is str:
        x = x.encode("ascii")
    return hashlib.blake2b(x,digest_size=32).digest()

def makeAddress(pubKeys, atLeast=None):
    if not type(pubKeys) is list:
        pubKeys=[pubKeys]
    if atLeast is None:
        atLeast = len(pubKeys)

    r = b""
    r += struct.pack("<B", atLeast)
    r += ser_vector([ SerBytes(x) for x in pubKeys])
    return addrhash(r)

class CKey(object):
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key

    is_compressed - True if compressed

    """
    def __init__(self, secret, compressed=True):
        if type(secret) == str:
            secret = secret.encode()
        self._cec_key = CECKey()
        self._cec_key.set_secretbytes(secret)
        self._cec_key.set_compressed(compressed)

        self.pub = CPubKey(self._cec_key.get_pubkey(), self._cec_key)

    @property
    def is_compressed(self):
        return self.pub.is_compressed

    def sign_long(self, hash):
        return self._cec_key.sign(hash)

    def sign_compact(self, hash):
        return self._cec_key.sign_compact(hash)

    def sign(self, msg):
        sigc = self.sign_compact(msg)
        meta = 27 + sigc[1]
        if self.is_compressed:
          meta += 4
        sigcBytes = bytes(bytearray((meta,))) + sigc[0]
        return sigcBytes

    def validate(self, msg, sig):
        pub = CPubKey.recover_compact(msg,sig)
        if pub is False: return False
        return pub == self.pub

class CBitcoinSecretError(Base58Error):
    pass

class CSecret(CBase58Data, CKey):
    """A base58-encoded secret key"""

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        self = cls.from_bytes(secret + (b'\x01' if compressed else b''),
                              params.BASE58_PREFIXES['SECRET_KEY'])
        self.__init__(None)
        return self

    def __init__(self, s):
        if self.nVersion != params.BASE58_PREFIXES['SECRET_KEY']:
            raise CBitcoinSecretError('Not a base58-encoded secret key: got nVersion=%d; expected nVersion=%d' % \
                                      (self.nVersion, params.BASE58_PREFIXES['SECRET_KEY']))

        CKey.__init__(self, self[0:32], len(self) > 32 and self[32] == 1)


class SimpleRamWallet:
    DEFAULT_FEE = 1
    def __init__(self, seed = None):
        if seed is None:
            self.seed = secrets.randbits(256)
        else:
            self.seed = bhash(seed)
        self.count = 0
        self.key2Addr = {}
        self.addr2Key = {}
        self.pub2Key = {}


    def getNewPubKey(self):
        self.count += 1
        newkey = bhash(ser_uint256(self.seed + self.count))
        newSecret = CSecret.from_secret_bytes(newkey)
        self.key2Addr[newkey] = newSecret
        self.pub2Key[newSecret.pub] = newSecret
        self.addr2Key[makeAddress(newSecret.pub)] = newSecret
        return newSecret.pub

    def getNewAddress(self):
        key = self.getNewPubKey()
        addr = SimpleTxIn(pubKey=key).getAddress()
        return addr

    def signTx(self, tx):
        assert(isinstance(tx, SimpleTransaction))
        sighash = tx.sighash()
        for vin in tx.vin:
            kidx = 0
            for pubKey in vin.pubKeys:
                secret = self.pub2Key.get(pubKey,None)
                if secret:
                    vin.setSignature(kidx, secret.sign(sighash))
                kidx += 1

    def spend(self, destAddr, amount, utxo, minfee=None):
        if minfee == None:
            minfee = self.DEFAULT_FEE
        maxfee = minfee*2

        spendable = utxo.getByAddrs(self.addr2Key.keys())
        # Coin selection: select a group of utxos from "spendable" that sum to >= amount
        selection = []
        total = 0
        for utxo in spendable:
            selection.append(utxo)
            total += utxo.vout.value
            if total >= amount+minfee: break
        txin = []

        # now that the input coins are selected, create the transaction
        for s in selection:
            txi = s.getTxIn()
            txi.setPubKeys([self.addr2Key[s.vout.hashbytes].pub])
            txin.append(txi)

        payment = SimpleTxOut(destAddr, amount)
        change = None
        if total-amount > maxfee:  # there is change
            changeAddr = self.getNewAddress()
            change = SimpleTxOut(changeAddr, total-amount-minfee)
        tx = SimpleTransaction(txi,[payment,change])
        self.signTx(tx)
        return tx


def Test():
    GENESIS_PARENT = b"0"*32
    NO_MINT = SimpleTransaction([],[])
    secret = CSecret.from_secret_bytes(bhash("shh"))
    print("pub key %s" % str(secret.pub))
    sig = secret.sign(bhash(""))
    print("signature: len: %d  %s" % (len(sig),hexlify(sig)))

    msg1 = bhash("1")
    msg2 = bhash("2")
    k = CKey("shh")
    if 1:
        sig1 = k.sign(msg1)
        sig2 = k.sign(msg2)
        assert( k.validate(msg1, sig1))
        assert(k.validate(msg2, sig2))
        assert(not k.validate(msg1, sig2))
        assert(not k.validate(msg2, sig1))

    w = SimpleRamWallet()
    k = w.getNewAddress()
    k1 = w.getNewAddress()

    # create the tx that can spend what will be the mint tx
    spendMint = SimpleTxIn(value=1*COIN, pubKey=k)
    b0 = SimpleBlock()
    b0.prevBlockHash=GENESIS_PARENT
    # add the mint tx, extracting the txout from the spending txin
    b0.setMint(SimpleTransaction([],[spendMint.getTxOut()]))
    b0.finish(None)
    spendMint.emplace(b0)

    spend2 = SimpleTxIn(value=1*COIN/2, pubKey=k1)
    spend3 = SimpleTxIn(value=1*COIN/2, pubKey=k1)
    spend = SimpleTransaction(spendMint,[spend2.getTxOut(),spend3.getTxOut()])
    w.signTx(spend)
    b1 = SimpleBlock([NO_MINT, spend])
    b1.finish(b0)
    # b1.validate()
    spend2.emplace(b1)
    spend3.emplace(b1)

    spend4 = SimpleTxIn(value=spend2.value, pubKey=w.getNewAddress())
    spend5 = SimpleTxIn(value=spend3.value, pubKey=w.getNewAddress())

    tx2 = SimpleTransaction(spend2,spend4.getTxOut())
    tx3 = SimpleTransaction(spend3,spend5.getTxOut())
    w.signTx(tx2)
    w.signTx(tx3)
    b2 = SimpleBlock([NO_MINT,tx2,tx3],b1)
    spend4.emplace(b2)
    spend5.emplace(b2)

