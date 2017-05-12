from test_framework.mininode import *
import test_framework.bumessages as bumessages
import sys
import logging
import pdb
import types
import code
import pickle
import os.path
import cProfile


def loadMessages(filename):
    with open(filename,"rb") as f:
        m = pickle.load(f)
    return m

class Messages:
    def __init__(self):
        self.lst = []
        self.byType = {}
        self.byHash = {}
        self.byHashstr = {}
        self.msgBuffer = None

    def save(self,filename):
        with open(filename,"wb") as f:
            pickle.dump(self,f)
            
    def summary(self):
        s = []
        s.append("%16d messages\n" % len(self.lst))
        keys = list(self.byType.keys())
        keys.sort()
        for k in keys:
            s.append("  %16d %s\n" % (len(self.byType[k]), k.decode('ascii')))
        return "".join(s)
            
    def add(self, msglst):
        if type(msglst) != list:
            msglst = [msglst]
        self.lst += msglst
        for m in msglst:
            self.byType.setdefault(m.command,[]).append(m)
            if hasattr(m,"block") and isinstance(m.block, CBlockHeader):
                hash = m.block.gethash()
                self.byHash.setdefault(hash,[]).append(m)
                self.byHashstr.setdefault("%064x" % hash,[]).append(m)

    def getByOffset(self, offset):
        """Return the message that contains this byte offset"""
        ret = self.lst[0]
        for l in self.lst:  # awful linear search, bisect doesn't seem to offer lambda comparator
            if l.offset > offset:
                break
            ret = l
        return ret

    def findByteOffset(self, data):
        """pass some binary data, a class object or a int hash and get a list of offsets of the original buffer where this data is found."""
        if isinstance(data, object) and hasattr(data,"serialize"):
            data = data.serialize()
        if type(data) is str:
            data = data.encode("ascii")
        if type(data) is int:
            if data <= 0xffffffffffffffff:  # it could be a quarter hash
                data = struct.pack("<Q",data)
            else:
                data = ser_uint256(data)
        idx = self.msgBuffer.find(data)
        ret = []
        while idx != -1:
            ret.append(idx)
            idx = self.msgBuffer.find(data,idx+1)
        return ret

    def find(self, data):
        """find some data and return all the messages that contain it"""
        idxes = self.findByteOffset(data)
        ret = []
        for idx in idxes:
            ret.append(self.getByOffset(idx))
        return ret

    def __getitem__(self, key):
        """reference a message by type, index or hash.  Will return a list if there can be multiple matches"""
        if type(key) is str:
            key = key.encode("ascii")
        if type(key) is int:
            if key < 1000000000000:    # less than this, assume it is an index, bigger than this and we are looking for a hash
                return self.lst[key]
            return self.byHash(key)
        return self.byType[key]


# this will hold the results of all the commands executed for easy access
result=[]

def p(obj):
    if type(obj) == list:
        print("[")
        for o in obj:
            print(str(o),",")
        print("]")
    else:
        print(str(obj))

def load(fname):
    if not fname:
        return

    extension = os.path.splitext(fname)[1]
    if extension == ".pkl":
        msgs = loadMessages(fname)
    else:
        parser = NodeConn("127.0.0.1",0,0,None, net="mainnet")
        parser.log.setLevel(logging.WARNING)
        f = open(fname,"rb")
        msgsbuf = f.read()
        f.close()
        msgs=Messages()
        msgs.msgBuffer = msgsbuf
        locals = {"parser":parser,"msgsbuf":msgsbuf}
        print("go")
        cProfile.runctx("ret = parser.parse_messages(msgsbuf)",globals(),locals)
        ret = locals["ret"]
        msgs.add(ret)

    result.append(msgs)
    return msgs


def main(argv):
    global result

    if len(argv) > 1:
        fname = argv[1]
        msgs = load(fname)
    else:
        msgs = Messages() 

    locals={"Messages":Messages, "msgs":msgs,"p":p,"load":load,"r":result}    
    locals.update(bumessages.__dict__)
    # pdb.set_trace()
    c = code.InteractiveConsole(locals)
    c.interact()

    pdb.set_trace()


def Test():
    # main(["","msg4mb"])
    # main(["","node40.87.158.209:34009.4427"])
    # main(["","node13.94.41.82:8333.4497"])
    #main(["","node178.63.60.137:43198.2319"])
    #main(["","node13.68.218.246:8333.67"])
    #main(["","msgs.pkl"])
    main([""])
if __name__ == '__main__':
    main(sys.argv)
