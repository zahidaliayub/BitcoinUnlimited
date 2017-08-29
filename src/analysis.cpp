// Copyright (c) 2017 The Bitcoin Unlimimted developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "init.h"

#include "addrman.h"
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "compat/sanity.h"
#include "connmgr.h"
#include "consensus/validation.h"
#include "dosman.h"
#include "httpserver.h"
#include "httprpc.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "parallel.h"
#include "policy/policy.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "script/standard.h"
#include "script/sigcache.h"
#include "scheduler.h"
#include "txdb.h"
#include "txmempool.h"
#include "torcontrol.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "unlimited.h"
#ifdef ENABLE_WALLET
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include <stdint.h>
#include <stdio.h>

#ifndef WIN32
#include <signal.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>

extern void (*AnalyzeBlock) (const CBlock &block, CBlockIndex *pindex, CCoinsViewCache &view, std::vector<int>& prevheights);

uint64_t txSize = 0;
uint64_t txOutpointSize = 0;
std::map<uint32_t,uint32_t> relativeBlock;

void PriorTxAnalysis(const CBlock &block, CBlockIndex *pindex, CCoinsViewCache &view, std::vector<int> &prevheights)
{
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = block.vtx[i];

        if (!tx.IsCoinBase())
        {
            int txsz = ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

            txSize += txsz;
            txOutpointSize += tx.vin.size() * sizeof(COutPoint);
            for (size_t j = 1; j < tx.vin.size(); j++)
            {
                int diff = pindex->nHeight - prevheights[j];
                auto it = relativeBlock.find(diff);
                if (it == relativeBlock.end())
                {
                    relativeBlock[diff] = 1;
                }
                else
                    it->second = it->second + 1;
            }
        }
    }

    LogPrintf("Height: %d TX total size: %d, Outpoint size: %d\n", pindex->nHeight, txSize, txOutpointSize);

    if ((pindex->nHeight & 511) == 0)
    {
        std::string fname = "/fast/bitcoin/txdist1/" + boost::lexical_cast<std::string>(pindex->nHeight) + ".csv";
        FILE *fp = std::fopen(fname.c_str(), "w");
        // LogPrintf("Relative block map\n");
        std::map<uint32_t, uint32_t> iter;
        for (auto &kv : relativeBlock)
        {
            // LogPrintf("distance: %d, count: %d\n", kv.first, kv.second);
            fprintf(fp, "%d, %d\n", kv.first, kv.second);
        }
        std::fclose(fp);
    }
}

// BU add lockstack stuff here because I need to carefully
// order it in globals.cpp for bitcoind and bitcoin-qt
//boost::mutex dd_mutex;
//std::map<std::pair<void*, void*>, LockStack> lockorders;
//boost::thread_specific_ptr<LockStack> lockstack;

//volatile bool fRequestShutdown = false;

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR);
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_WARNING);
    return true;
}


class CCoinsViewErrorCatcher : public CCoinsViewBacked
{
public:
    CCoinsViewErrorCatcher(CCoinsView* view) : CCoinsViewBacked(view) {}
    bool GetCoins(const uint256 &txid, CCoins &coins) const {
        try {
            return CCoinsViewBacked::GetCoins(txid, coins);
        } catch(const std::runtime_error& e) {
            uiInterface.ThreadSafeMessageBox(_("Error reading from database, shutting down."), "", CClientUIInterface::MSG_ERROR);
            LogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller.
};

static CCoinsViewDB *pcoinsdbview = NULL;
static CCoinsViewErrorCatcher *pcoinscatcher = NULL;
static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle;

struct CImportingNow
{
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};

void AnalysisThreadImport(std::vector<boost::filesystem::path> vImportFiles)
{
    const CChainParams& chainparams = Params();
    RenameThread("bitcoin-loadblk");
    // -reindex
    if (fReindex) {
        CImportingNow imp;
        int nFile = 0;
        while (true) {
            CDiskBlockPos pos(nFile, 0);
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in OpenBlockFile
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(chainparams, file, &pos);
            nFile++;
        }
        pblocktree->WriteReindexing(false);
        fReindex = false;
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        InitBlockIndex(chainparams);
    }

    // hardcoded $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (boost::filesystem::exists(pathBootstrap)) {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            CImportingNow imp;
            boost::filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock=
    BOOST_FOREACH(const boost::filesystem::path& path, vImportFiles) {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file) {
            CImportingNow imp;
            LogPrintf("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file);
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    if (GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT)) {
        LogPrintf("Stopping after block import\n");
        StartShutdown();
    }
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AnalysisInit2(boost::thread_group &threadGroup, CScheduler &scheduler)
{
    int64_t nStart=0;
    std::ostringstream strErrors;
    bool fRequestShutdown=false;

// ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
// Enable Data Execution Prevention (DEP)
// Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
// A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL(WINAPI * PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol =
        (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL)
        setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    const CChainParams &chainparams = Params();

#ifdef BITCOIN_CASH
    nLocalServices |= NODE_BITCOIN_CASH;
#endif

    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    // if (!InitSanityCheck())
    //   return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    std::string strDataDir = GetDataDir().string();
    OpenDebugLog();

    // -par=0 means autodetect, but passing 0 to the CParallelValidation constructor means no concurrency
    int nPVThreads = GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (nPVThreads <= 0)
        nPVThreads += GetNumCores();

    // BU: create the parallel block validator
    PV.reset(new CParallelValidation(nPVThreads, &threadGroup));

    // Start the lightweight task scheduler thread
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    boost::filesystem::path blocksDir = GetDataDir() / "blocks";
    int64_t nTotalCache = (GetArg("-dbcache", nDefaultDbCache) << 20);
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greated than nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", DEFAULT_TXINDEX))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache =
        std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    std::string chainstateDb = GetArg("-utxoDb", "analyzechain");

    bool fLoaded = false;
    while (!fLoaded)
    {
        bool fReset = fReindex;
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do
        {
            try
            {
                UnloadBlockIndex();
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;

                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex);
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex, chainstateDb);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);

                if (fReindex)
                {
                    pblocktree->WriteReindexing(true);
                }

                if (!LoadBlockIndex())
                {
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex(chainparams))
                {
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -txindex state
                if (fTxIndex != GetBoolArg("-txindex", DEFAULT_TXINDEX))
                {
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (fHavePruned && !fPruneMode)
                {
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  "
                                     "This will redownload the entire blockchain");
                    break;
                }

                uiInterface.InitMessage(_("Verifying blocks..."));
                if (fHavePruned && GetArg("-checkblocks", DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP)
                {
                    LogPrintf("Prune: pruned datadir may not have more than %d blocks; only checking available blocks",
                        MIN_BLOCKS_TO_KEEP);
                }

                {
                    LOCK(cs_main);
                    CBlockIndex *tip = chainActive.Tip();
                    if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60)
                    {
                        strLoadError = _("The block database contains a block which appears to be from the future. "
                                         "This may be due to your computer's date and time being set incorrectly. "
                                         "Only rebuild the block database if you are sure that your computer's date "
                                         "and time are correct");
                        break;
                    }
                }

                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                        GetArg("-checkblocks", DEFAULT_CHECKBLOCKS)))
                {
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            }
            catch (const std::exception &e)
            {
                if (fDebug)
                    LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while (false);

        if (!fLoaded)
        {
            // first suggest a reindex
            if (!fReset)
            {
                bool fRet = uiInterface.ThreadSafeMessageBox(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"), "",
                    CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet)
                {
                    fReindex = true;
                    fRequestShutdown = false;
                }
                else
                {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            }
            else
            {
                return InitError(strLoadError);
            }
        }

    }
        CValidationState state;
        if (!ActivateBestChain(state, chainparams))
        {
            if (fRequestShutdown)
                return false;
            else
                strErrors << "Failed to connect best block";
        }
        IsChainNearlySyncdInit(); // BUIP010 XTHIN: initialize fIsChainNearlySyncd
        IsInitialBlockDownloadInit();

        std::vector<boost::filesystem::path> vImportFiles;
        if (mapArgs.count("-loadblock"))
        {
            BOOST_FOREACH (const std::string &strFile, mapMultiArgs["-loadblock"])
                vImportFiles.push_back(strFile);
        }
        threadGroup.create_thread(boost::bind(&AnalysisThreadImport, vImportFiles));
        if (chainActive.Tip() == NULL)
        {
            LogPrintf("Waiting for genesis block to be imported...\n");
            while (!fRequestShutdown && chainActive.Tip() == NULL)
                MilliSleep(10);
        }
    

        StartNode(threadGroup, scheduler);
        return 0;
    }

    //
    // This function returns either one of EXIT_ codes when it's expected to stop the process or
    // CONTINUE_EXECUTION when it's expected to continue further.
    //
    static int AnalysisInit(int argc, char *argv[])
    {
        boost::thread_group threadGroup;
        CScheduler scheduler;
        AllowedArgs::Bitcoind allowedArgs(&tweaks);
        try
        {
            ParseParameters(argc, argv, allowedArgs);
        }
        catch (const std::exception &e)
        {
            fprintf(stderr, "Error parsing program options: %s\n", e.what());
            // TEMP return false;
        }

        if (mapArgs.count("-?") || mapArgs.count("-h") || mapArgs.count("-help") || mapArgs.count("-version"))
        {
            std::string strUsage =
                strprintf(_("%s Daemon"), _(PACKAGE_NAME)) + " " + _("version") + " " + FormatFullVersion() + "\n";

            if (mapArgs.count("-version"))
            {
                strUsage += FormatParagraph(LicenseInfo());
            }
            else
            {
                strUsage += "\n" + _("Usage:") + "\n" + "  bitcoind [options]                     " +
                            strprintf(_("Start %s Daemon"), _(PACKAGE_NAME)) + "\n";

                strUsage += "\n" + allowedArgs.helpMessage();
            }

            fprintf(stdout, "%s", strUsage.c_str());
            return true;
        }

        try
        {
            if (!boost::filesystem::is_directory(GetDataDir(false)))
            {
                fprintf(
                    stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
                return false;
            }
            try
            {
                ReadConfigFile(mapArgs, mapMultiArgs, allowedArgs);
            }
            catch (const std::exception &e)
            {
                fprintf(stderr, "Error reading configuration file: %s\n", e.what());
                return false;
            }
            // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
            try
            {
                SelectParams(ChainNameFromCommandLine());
            }
            catch (const std::exception &e)
            {
                fprintf(stderr, "Error: %s\n", e.what());
                return false;
            }

            // Command-line RPC
            bool fCommandLine = false;
            for (int i = 1; i < argc; i++)
                if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:"))
                    fCommandLine = true;

            if (fCommandLine)
            {
                fprintf(stderr, "Error: There is no RPC client functionality in bitcoind anymore. Use the bitcoin-cli "
                                "utility instead.\n");
                return false;
            }
            SoftSetBoolArg("-server", true);

            // Set this early so that parameter interactions go to console
            InitLogging();
            InitParameterInteraction();
            AnalysisInit2(threadGroup, scheduler);
        }
        catch (const std::exception &e)
        {
            PrintExceptionContinue(&e, "AppInit()");
        }
        catch (...)
        {
            PrintExceptionContinue(NULL, "AppInit()");
        }

        UnlimitedSetup();
        return true;
    }


    int main(int argc, char *argv[])
    {
        int ret = 0;
        SetupEnvironment();
        AnalyzeBlock = PriorTxAnalysis;
        try
        {
            ret = AnalysisInit(argc, argv);
        }
        catch (const std::exception &e)
        {
            PrintExceptionContinue(&e, "AppInitRPC()");
            return EXIT_FAILURE;
        }
        catch (...)
        {
            PrintExceptionContinue(NULL, "AppInitRPC()");
            return EXIT_FAILURE;
        }

        return ret;
    }
