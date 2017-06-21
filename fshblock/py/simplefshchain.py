import fshblock
import copy
from simplefshblock import *

class Error(Exception):
    def __init__(self, message):
        super().__init__(message)

class Placeholder:
    pass

class UtxoRecord:
    def __init__(self,outpoint, vout, blockHash):
        self.vout = vout
        self.outpoint = outpoint
        self.spent = False
        self.blockHash = blockHash # this could be looked up from the outpoint but it is easier to store it

    def getTxIn(self):
        return SimpleTxIn(blockNum=self.outpoint[0], txIndex=self.outpoint[1], voutIndex=self.outpoint[2], value=self.vout.value,blockHash=self.blockHash)



class UtxoDiff:
    SPENT = Placeholder()
    def __init__(self, parent):
        self.outpoints = {}
        self.addr = {}
        self.parent = parent

    def merge(self):
        if not self.parent:
            raise Error("Cannot merge lowest snapshot")
        self.parent.outpoints.update(self.outpoints)
        self.parent.addr.update(self.addr)
        self.outpoints = {}
        self.addr = {}
        return self.parent

    def copyflatten(self):
        """Returns a UtxoDiff object that is a flattened copy of this entire stack"""
        stack = [self]
        tmp = self
        while tmp.parent:
            tmp = tmp.parent
            stack.append(tmp)
        ret = UtxoDiff(None)
        while stack:
            s = stack.pop()
            ret.outpoints.update(s.outpoints)
            ret.addr.update(s.addr)
        return ret

    def spent(self,outp):
        self.outpoints[outp] = SPENT
        addr = val.hashbytes
        dlist = self.getByAddr(addr)
        


    def getByAddr(self, key, default=None, promote=True):
        """If promote is true, you may modify the returned object... it will be copied to the first diff"""
        val = self.addr.get(key, None)
        if val is not None:
            return val
        if not self.parent:
            return default
        val = self.parent.getByAddr(key,default,False)
        if promote:
            val = copy.deepcopy(val)
            self.addr[key] = val
        return val

    def getByOutpoint(self, key, default):
        """Note do not modify the returned object"""
        val = self.outpoints.get(key, None)
        if val == SPENT:
            return default
        if val is not None:
            return val
        if not self.parent:
            return default
        val = self.parent.getByOutpoint(key)
        return val

    def set(self,outpoint,val):
        rec = UtxoRecord(outpoint, val)
        # note that both dictionaries at this level point to the same record
        self.outpoints[outpoint] = rec
        addr = val.hashbytes
        dlist = self.addr.setdefault(addr,[])
        dlist.append(rec)


class SimpleUtxoOld:
    def __init__(self):
        self.utxo = UtxoDiff(None)

    def fork(self):
        self.utxo = UtxoDiff(self.utxo)

    def submitTx(self,tx,blockidx,txidx):
        assert(isinstance(tx, SimpleTransaction))

        dbfork = self.fork()

        # Remove the spent
        totalSpent = 0
        for vin in tx.vin:
            outp = vin.getOutpoint()
            rec = dbfork.get(outp, None)
            if not rec:
                raise Error("transaction cannot be applied to the UTXO")

            totalSpent += rec.vout.value
            dbfork.spent(outp)

        # insert the new
        voutidx=0
        totalPaid = 0
        for vout in tx.vout:
            dbfork.set((blockidx,txidx, voutidx), UtxoDiff(tx.vout))
            voutidx+=1

        if totalSpent < totalPaid:
            raise Error("transaction pays more than it spends")

        # tx is OK: merge the changes
        dbfork.merge()

    def getAddrs(addrList):
        flat = self.utxo.copyflatten()  # TODO inefficient
        result = []
        for addr in addrList:
            result.append(flat.get(addr, []))
        return result

class SimpleUtxo:
    def __init__(self):
        self.outpoints = {}
        self.addr = {}
        self.parent = None

    def fork(self):
        temp = copy.deepcopy(self)
        temp.parent = self
        return temp

    def merge():
        if not self.parent:
            raise Error("no parent")
        self.parent.outpoints = self.outpoints
        self.parent.addr = self.addr

    def spent(self,outpoint, rec=None):
        if rec is None:
            rec = self.getByOutpoint(outp)
            if not rec or rec.spent:
                raise Error("transaction cannot be applied to the UTXO")
        rec.spent = True

    def clean(self):
        """Removes all spent records"""
        for (k,v) in self.outpoints:
            if v.spent:
                del self.outpoints[k]
                lst = self.addr[v.vout.hashbytes]
                lst.remove(v)

    def insert(self, rec):
        tmp = self.outpoints.get(rec.outpoint, None)
        if not tmp is None:
            raise Error("Repeat outpoint")
        self.outpoints[rec.outpoint] = rec
        lst = self.addr.setdefault(rec.vout.hashbytes,[])
        lst.append(rec)

    def getByOutpoint(self, key, default=None):
        return self.outpoints.get(key,default)

    def getByAddr(self, key, default=None):
        return self.addr.get(key,default)

    def getByAddrs(self, addrList):
        flat = self.addr
        result = []
        for addr in addrList:
            result += flat.get(addr, [])
        return result

    def submitTx(self,tx,blockidx,txidx, blockHash):
        assert(isinstance(tx, SimpleTransaction))

        # mark the spent
        totalSpent = 0
        for vin in tx.vin:
            outp = vin.getOutpoint()
            rec = self.getByOutpoint(outp)
            if not rec or rec.spent:
                raise Error("transaction cannot be applied to the UTXO")

            totalSpent += rec.vout.value
            self.spent(outp,rec)

        # insert the new
        voutidx=0
        totalPaid = 0
        for vout in tx.vout:
            outpt = (blockidx, txidx, voutidx)
            self.insert(UtxoRecord(outpt, vout, blockHash))
            voutidx+=1

        if totalSpent < totalPaid:
            raise Error("transaction pays more than it spends")


class ChainTip:
    def __init__(self):
        self.block = None
        self.utxo = None

class SimpleBlockChain(fshblock.FshExtensionBlockChain):
    def __init__(self, depositAddress, backingAddress, genesisParentHash):
        fshblock.FshExtensionBlockChain.__init__(self, depositAddress, backingAddress)
        self.blockTips = []
        self.oldTips = []
        self.blocks = {}
        self.genesisParentHash = genesisParentHash

    def submitHeader(self, fshblk):
        assert(isinstance(fshblk, fshblock.FshBlock))
        pass

    def submitBlock(self, block):
        blk = self.blocks.get(block.hash(), None)
        if blk:  # already have this block
            return True

        newtip = ChainTip()
        newtip.block = block

        tip = None
        if block.prevBlockHash == self.genesisParentHash:
            newtip.utxo = SimpleUtxo()
        else:
            tip = self.blocks.get(block.prevBlockHash)
            if not tip:
                raise Error("unordered block")

            newtip.utxo = tip.utxo.fork()

        txidx = 0
        for tx in block.tx:
            newtip.utxo.submitTx(tx,block.height, txidx, block.hash())
            txidx += 1

        self.blocks[block.hash()] = newtip

        if tip: self.blockTips.remove(tip)  # Remove the now-buried block out of the tip list
        self.blockTips.append(newtip)

    def tip(self):
        """returns the most difficulty (lowest number) blockchain tip"""
        ret = None
        diff = 0xFfffffffFfffffffFfffffffffffffffffffffffffffffffffffffffffffffff
        for b in self.blockTips:
            bdiff = b.block.chainDifficulty()
            if diff > bdiff:
                diff = bdiff
                ret = b
        return ret


def Test():

    u = SimpleUtxo()
    t = SimpleTransaction([],[])
    u.submitTx(t,0,0)

    ti = SimpleTxIn(value=10, blockNum=0, txIndex=1, voutIndex=0, pubKey=SerBytes(b"1"),signatures=SerBytes(b"1"))
    to = ti.getTxOut()
    t = SimpleTransaction([],to)
    u.submitTx(t,0,1)

    ti2 = SimpleTxIn(value=10, blockNum=1, txIndex=1, voutIndex=0, pubKey=SerBytes(b"1"),signatures=SerBytes(b"1"))
    to2 = ti.getTxOut()

    try: # ti2 hasn't been committed to the utxo yet so it can't be an input
        t = SimpleTransaction(ti2,to2)
        u.submitTx(t,1,1)
        assert(0)
    except Error as e:
        pass

    t = SimpleTransaction(ti,to2)
    u.submitTx(t,1,1)

