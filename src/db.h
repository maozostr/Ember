// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DB_H
#define BITCOIN_DB_H

#include "serialize.h"
#include "sync.h"
#include "version.h"

#include <map>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <db.h>

class CAddrMan;
class CBlockLocator;
class CDiskBlockIndex;
class CDiskTxPos;
class COutPoint;
class CTxIndex;

extern unsigned int nWalletDBUpdated;

void ThreadFlushWalletDB(const std::string& strWalletFile);


class CDBEnv
{
private:
    bool fDbEnvInit;
    bool fMockDb;
    boost::filesystem::path pathEnv;
    std::string strPath;

    void EnvShutdown();

public:
    mutable CCriticalSection cs_db;
    DB_ENV *dbenv;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, DB*> mapDb;

    CDBEnv();
    ~CDBEnv();
    void MakeMock();
    bool IsMock() { return fMockDb; };

    /*
     * Verify that database file strFile is OK. If it is not,
     * call the callback to try to recover.
     * This must be called BEFORE strFile is opened.
     * Returns true if strFile is OK.
     */
    enum VerifyResult { VERIFY_OK, RECOVER_OK, RECOVER_FAIL };
    VerifyResult Verify(std::string strFile, bool (*recoverFunc)(CDBEnv& dbenv, std::string strFile));
    /*
     * Salvage data from a file that Verify says is bad.
     * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
     * Appends binary key/value pairs to vResult, returns true if successful.
     * NOTE: reads the entire database into memory, so cannot be used
     * for huge databases.
     */
    typedef std::pair<std::vector<unsigned char>, std::vector<unsigned char> > KeyValPair;
    bool Salvage(std::string strFile, bool fAggressive, std::vector<KeyValPair>& vResult);

    bool Open(boost::filesystem::path pathEnv_);
    void Close();
    void Flush(bool fShutdown);
    void CheckpointLSN(const std::string& strFile);

    void CloseDb(const std::string& strFile);
    bool RemoveDb(const std::string& strFile);

	DB_TXN *TxnBegin(int flags=DB_TXN_WRITE_NOSYNC)
    {
		DB_TXN* ptxn = NULL;
        int ret = dbenv->txn_begin(dbenv, NULL, &ptxn, flags);
        if (!ptxn || ret != 0)
            return NULL;
        return ptxn;
    }
};

extern CDBEnv bitdb;


/** RAII class that provides access to a Berkeley database */
class CDB
{
protected:
    DB* pdb;
    std::string strFile;
    DB_TXN *activeTxn;
    bool fReadOnly;

    explicit CDB(const std::string& strFilename, const char* pszMode="r+");
    ~CDB() { Close(); }

public:
    void Close();

private:
    CDB(const CDB&);
    void operator=(const CDB&);

protected:
    template<typename K, typename T>
    bool Read(const K& key, T& value) {
		DBT datKey = { 0 };
		DBT datValue = { 0 };
        
		if (!pdb)
            return false;
        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
		datKey.data = &ssKey[0];
		datKey.size = ssKey.size();

        // Read
		datValue.flags |= DB_DBT_MALLOC;
        int ret = pdb->get(pdb, activeTxn, &datKey, &datValue, 0);
        memset(datKey.data, 0, datKey.size);
		if (datValue.data == NULL) {
			return false;
		}

        // Unserialize value
        try {
            CDataStream ssValue((char*)datValue.data, (char*)datValue.data + datValue.size, SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        }
        catch (std::exception &e) {
			(void)e; // Compiler tricks: trick it to "use e" at 0 cost
            return false;
        }

        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true) {
		DBT datKey = { 0 };
		DBT datValue = { 0 };

        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Write called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
		datKey.data = &ssKey[0];
		datKey.size = ssKey.size();

        // Value
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;
		datValue.data = &ssValue[0];
		datValue.size = ssValue.size();

        // Write
        int ret = pdb->put(pdb, activeTxn, &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K& key) {
		DBT datKey = { 0 };
        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Erase called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
		datKey.data = &ssKey[0];
		datKey.size = ssKey.size();

        // Erase
        int ret = pdb->del(pdb, activeTxn, &datKey, 0);

        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
	bool Exists(const K& key) {
		DBT datKey = { 0 };
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
		datKey.data = &ssKey[0];
		datKey.size = ssKey.size();

        // Exists
        int ret = pdb->exists(pdb, activeTxn, &datKey, 0);

        return (ret == 0);
    }

    int ReadAtCursor(DBC *pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT) {
		DBT datKey = {0};
		DBT datValue = { 0 };

        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
			datKey.data = &ssKey[0];
            datKey.size = ssKey.size();
        }
		
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE) {
            datValue.data = &ssValue[0];
            datValue.size = ssValue.size();
        }
        datKey.flags |= DB_DBT_MALLOC;
        datValue.flags |= DB_DBT_MALLOC;
        int ret = pcursor->get(pcursor, &datKey, &datValue, fFlags);
		if (ret != 0) {
			return ret;
		} else if (datKey.data == NULL || datValue.data == NULL) {
			return 99999;
		}

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.data, datKey.size);
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.data, datValue.size);

        return 0;
    }

public:
    bool TxnBegin()
    {
        if (!pdb || activeTxn)
            return false;
        DB_TXN* ptxn = bitdb.TxnBegin();
        if (!ptxn)
            return false;
        activeTxn = ptxn;
        return true;
    }

    bool TxnCommit()
    {
        if (!pdb || !activeTxn)
            return false;
        int ret = activeTxn->commit(activeTxn, 0);
        activeTxn = NULL;
        return (ret == 0);
    }

    bool TxnAbort()
    {
        if (!pdb || !activeTxn)
            return false;
        int ret = activeTxn->abort(activeTxn);
        activeTxn = NULL;
        return (ret == 0);
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    bool static Rewrite(const std::string& strFile, const char* pszSkip = NULL);
};

#endif // BITCOIN_DB_H
