from simplefshchain import *
from simplefshwallet import *

from test_framework.test_framework import BitcoinTestFramework

class TestClass(BitcoinTestFramework):
    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0,self.options.tmpdir, ["-rpcservertimeout=0"], timewait=60*10))

    def run_test(self):

        node = self.nodes[0]
        addr1 = node.getnewaddress()
        wallet = node.listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=True)

        pass

if __name__ == '__main__':
    Test().main()

def info(type, value, tb):
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
    UnitTest()
    t = TestClass()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],  # "lck"
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    t.main(["--tmpdir=/ramdisk/test", "--nocleanup", "--noshutdown"], bitcoinConf, None)  # , "--tracerpc"])


def UnitTest():
    # any valid address for the purpose of this test
    fshDepositAddr = "mrDDZJ637G3M5hiKz9ehdgBRM6y1fo5gMw"
    fshBackingAddr = "mnPf6UGVgLEahHDXyrsZE5kMnVAK8RzVjB"

    GENESIS_PARENT = b"0"*32
    NO_MINT = SimpleTransaction([],[])

    wallet = SimpleRamWallet()
    chain =  SimpleBlockChain(fshDepositAddr,fshBackingAddr,GENESIS_PARENT)

    pdb.set_trace()
    k = wallet.getNewAddress()
    spendMint = SimpleTxOut(k, 1000)
    t = SimpleTransaction([],[spendMint])

    b0 = SimpleBlock([t],GENESIS_PARENT)
    b0.solve()
    chain.submitBlock(b0)

    tip = chain.tip()
    newaddr = wallet.getNewAddress()
    t2 = wallet.spend(newaddr, 10, tip.utxo)

    pdb.set_trace()
    b1 = SimpleBlock([t2],b0)
    b1.solve()
    chain.submitBlock(b1)

    pdb.set_trace()
