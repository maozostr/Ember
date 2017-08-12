// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"

#include "addrman.h"
#include "hash.h"
#include "util.h"

#ifndef _WIN32
#include <sys/stat.h>
#endif

#ifdef _WIN32
#include <io.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/version.hpp>
#include <openssl/rand.h>
#include <string.h>

#define IO_BUF_LEN 4096

using namespace std;
using namespace boost;


unsigned int nWalletDBUpdated;

//
// CDB
//

CDBEnv bitdb;

void CDBEnv::EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv->close(dbenv, 0);
    if (ret != 0)
        LogPrintf("EnvShutdown exception: %s (%d)\n", db_strerror(ret), ret);
    if (!fMockDb)
		dbenv->close(dbenv, 0);
}

CDBEnv::CDBEnv() {
	int ret;
	if (0 != (ret = db_env_create(&dbenv, 0))) {
		cerr << "db_env_create error:" << db_strerror(ret) << endl;
		exit(1);
	}
    fDbEnvInit = false;
    fMockDb = false;
}

CDBEnv::~CDBEnv()
{
    EnvShutdown();
}

void CDBEnv::Close()
{
    EnvShutdown();
}

bool CDBEnv::Open(boost::filesystem::path pathEnv_) {
	int ret;
	FILE *err_file_h;

	if (fDbEnvInit) {
		return true;
	}

    boost::this_thread::interruption_point();

    pathEnv = pathEnv_;
    filesystem::path pathDataDir = pathEnv;
    strPath = pathDataDir.generic_string();
    filesystem::path pathLogDir = pathDataDir / "database";
    filesystem::create_directory(pathLogDir);
    filesystem::path pathErrorFile = pathDataDir / "db.log";
    LogPrintf("dbenv.open LogDir=%s ErrorFile=%s\n", pathLogDir.generic_string(), pathErrorFile.generic_string());
	const std::string& string_thing = pathDataDir.generic_string();
	const char *str_p = string_thing.c_str();

	uint32_t flags = DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD | DB_AUTO_COMMIT | DB_TXN_WRITE_NOSYNC;
#ifdef DB_LOG_AUTO_REMOVE
	flags |= DB_LOG_AUTO_REMOVE;
#endif
	if (GetBoolArg("-privdb", true)) {
		flags |= DB_PRIVATE;
	}

	int nDbCache = GetArg("-dbcache", 25);
	dbenv->set_cachesize(dbenv, nDbCache / 1024, (nDbCache % 1024) * 1048576, 1);
	/*
	if (0 != (ret = dbenv->set_memory_max(dbenv, 4, 0))) {
		return error("CDB() : error %s (%d) setting max memory", db_strerror(ret), ret);
	}

	if (0 != (ret = dbenv->set_memory_init(dbenv, DB_MEM_CONFIG type, 0))) {
		return error("CDB() : error %s (%d) setting initial memory", db_strerror(ret), ret);
	}
	*/
	const std::string& err_file_path = pathErrorFile.generic_string();
	err_file_h = fopen(err_file_path.c_str(), "a");
	if (NULL == err_file_h) {
		return error("CDB() : error opening file: %s\n", err_file_path);
	}
	dbenv->set_errfile(dbenv, err_file_h);


	if (0 != (ret = dbenv->open(dbenv, str_p, flags, S_IRUSR | S_IWUSR))) {
		return error("CDB() : %s (%d) Opening database environment", db_strerror(ret), ret);
	}


    fDbEnvInit = true;
    fMockDb = false;

    return true;
}

void CDBEnv::MakeMock()
{
    if (fDbEnvInit)
        throw runtime_error("CDBEnv::MakeMock(): already initialized");

    boost::this_thread::interruption_point();

    LogPrint("db", "CDBEnv::MakeMock()\n");

    dbenv->set_cachesize(dbenv, 1, 0, 1);
#ifdef DB_LOG_IN_MEMORY
    dbenv->log_set_config(dbenv, DB_LOG_IN_MEMORY, 1);
#endif
    int ret = dbenv->open(dbenv, NULL,
                     DB_CREATE      |
                     DB_INIT_LOCK   |
                     DB_INIT_LOG    |
                     DB_INIT_MPOOL  |
                     DB_INIT_TXN    |
                     DB_THREAD      |
					 DB_AUTO_COMMIT |
                     DB_PRIVATE,
                     S_IRUSR | S_IWUSR);
    if (ret > 0)
        throw runtime_error(strprintf("CDBEnv::MakeMock(): error %d opening database environment", ret));

    fDbEnvInit = true;
    fMockDb = true;
}

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool (*recoverFunc)(CDBEnv& dbenv, std::string strFile))
{
    LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

	DB *db = NULL;
	int ret = db_create(&db, dbenv, 0);
	if (ret != 0) {
		LogPrintf("Verify Failed for: %s\n", strFile.c_str());
		return RECOVER_FAIL;
	}
    int result = db->verify(db, strFile.c_str(), NULL, NULL, 0);
	if (result == 0) {
		return VERIFY_OK;
	} else if (recoverFunc == NULL) {
		return RECOVER_FAIL;
	}

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

#ifdef _WIN32
bool directory_exists(wchar_t *p_path) {
	unsigned long attributes = GetFileAttributesW(p_path);
	return (attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

bool file_exists(wchar_t *p_path) {
	unsigned long attributes = GetFileAttributesW(p_path);
	return (attributes != INVALID_FILE_ATTRIBUTES &&
		!(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

#else
bool directory_exists(const char &path) {
	struct stat sb;

	if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		return true;
	}
	return false;
}

bool file_exists(const char &path) {
	struct stat sb;

	if (stat(path, &sb) == 0 && S_ISREG(sb.st_mode)) {
		return true;
	}
	return false;
}
#endif

#ifdef _WIN32
int get_tmp_filename(wchar_t *p_filename, wchar_t *p_basepath, wchar_t *p_tmp_filename, uint64_t tmp_filename_size) {
	wchar_t tmp_path[_MAX_PATH] = { 0 };
	LPWSTR tmp_path_p = &tmp_path[0];
	wchar_t tmp_name[_MAX_PATH] = { 0 };
	LPWSTR tmp_name_p = &tmp_name[0];

	// Parameter Validation
	if (p_tmp_filename == NULL) {
		return -1; // FAILURE_NULL_ARGUMENT
	}

	// Get a basepath
	if (p_basepath != NULL) {
		wcscpy_s(&tmp_path[0], _MAX_PATH, p_basepath);
	} else { // Use the CWD if a basepath wasn't supplied
		wcscpy_s(&tmp_path[0], _MAX_PATH, L".\\");
	}
	if (!directory_exists(tmp_path)) {
		return -4; // FAILURE_INVALID_PATH
	}

	// Form the full filename
	if (p_filename != NULL)	{
		wcscpy_s(&tmp_name[0], MAX_PATH, &tmp_path[0]);
		wcscat_s(&tmp_name[0], MAX_PATH, L"\\");
		wcscat_s(tmp_name, MAX_PATH, p_filename);
	} else { // Get a temporary filename if one wasn't supplied
		if (GetTempFileName(tmp_path_p, NULL, 0, tmp_name_p) == 0) {
			LogPrintf("Error getting temporary filename.\n");
			return -3; // FAILURE_API_CALL
		}
	}

	// Copy over the result
	switch (wcscpy_s(p_tmp_filename, tmp_filename_size, tmp_name)) {
	case 0:
		// Make sure that the file doesn't already exist before we suggest it as a tempfile.
		// They will still get the name in-case they intend to use it, but they have been warned.
		if (file_exists(tmp_name)) {
			return -5; // FAILURE_FILE_ALREADY_EXISTS
		}
		return 0;
		break;
	case ERANGE:
		return -2; // FAILURE_INSUFFICIENT_BUFFER
		break;
	default:
		return -3; // FAILURE_API_CALL
		break;
	}
}
#else
//TODO: Posix version
#endif

int get_line(char s[], int lim, FILE *f) {
	int c, i;
	for (i = 0; i < lim - 1 && (c = fgetc(f)) != EOF && c != '\n'; ++i) {
		s[i] = c;
	}
	if (c == '\n') {
		s[i] = c;
		++i;
	}
	s[i] = '\0';
	return i;
}

bool CDBEnv::Salvage(std::string strFile, bool fAggressive, std::vector<CDBEnv::KeyValPair >& vResult) {
	HANDLE whandle;
	int chandle;
	FILE *cfile;
	DB *db = NULL;
	char io_buf[IO_BUF_LEN];
	char search_buf[11] = { 0 };
	size_t len_read;
	int err;
	std::vector<unsigned char> k, v;
	char *end;

	LOCK(cs_db);
    assert(mapFileUseCount.count(strFile) == 0);

    u_int32_t flags = DB_SALVAGE;
    if (fAggressive) flags |= DB_AGGRESSIVE;

	int ret;
	wchar_t tmpfilename[_MAX_PATH] = { 0 };
	ret = 0;
	ret = get_tmp_filename(NULL, NULL, &tmpfilename[0], _MAX_PATH);
	if (ret != 0)	{
		LogPrintf("Error retrieveng tmp name for salvage operation: %i", ret);
		return false;
	}

	// Extract the DLL to disk
	whandle = CreateFileW(tmpfilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (whandle == INVALID_HANDLE_VALUE) {
		LogPrintf("Error creating temporary file\n");
		return false;
	}
	chandle = _get_osfhandle((long)whandle);
	if (chandle < 0) {
		LogPrintf("Error converting handle.\n");
		return false;
	}

	if ((cfile = _fdopen(chandle, "r+")) == NULL) {
		LogPrintf("Error opening temporary file\n");
		return false;
	}

	ret = 0;
	ret = db_create(&db, dbenv, 0);
	if (ret != 0) {
		LogPrintf("Error: Cannot open %s\n", strFile.c_str());
		return false;
	}
    int result = db->verify(db, strFile.c_str(), NULL, cfile, flags);
    if (result == DB_VERIFY_BAD) {
        LogPrintf("Error: Salvage found errors, all data may not be recoverable.\n");
        if (!fAggressive)
        {
            LogPrintf("Error: Rerun with aggressive mode to ignore errors and continue.\n");
            return false;
        }
    }
    if (result != 0 && result != DB_VERIFY_BAD)
    {
        LogPrintf("ERROR: db salvage failed: %d\n",result);
        return false;
    }

    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    // hexadecimal key
    // hexadecimal value
    // ... repeated
    // DATA=END
	uint8_t mode = 0;

	if (cfile) {
		while (get_line(io_buf, sizeof(io_buf), cfile) > 0) {
			for (int i = 0; i < 10; ++i) {
				search_buf[i] = io_buf[i];
			}
			switch (mode) {
				case 0:
					if (strcmp("HEADER=END", search_buf) == 0) {
						mode = 1;
					}
					break;
				case 1:
					if (strcmp("DATA=END", search_buf) == 0) {
						fclose(cfile);
						return (result == 0);
					}
					for (int i = 0; i < (io_buf - strchr(io_buf, '\n')); i++) {
						k.push_back((unsigned char)io_buf[i]);
					}
					mode = 2;
					break;
				case 2:
					mode = 1;
					for (int i = 0; i < (io_buf - strchr(io_buf, '\n')); i++) {
						v.push_back((unsigned char)io_buf[i]);
					}
					vResult.push_back(make_pair(k, v));

					break;
				}
			}
		}

		if ((err = ferror(cfile)) != 0) {
			LogPrintf("Error reading from temporary file: %s\n", strerror(ferror(cfile)));
			return false;
		}
}


void CDBEnv::CheckpointLSN(const std::string& strFile)
{
    dbenv->txn_checkpoint(dbenv, 0, 0, 0);
    if (fMockDb)
        return;
    dbenv->lsn_reset(dbenv, strFile.c_str(), 0);
}


CDB::CDB(const std::string& strFilename, const char* pszMode) :
    pdb(NULL), activeTxn(NULL)
{
    int ret;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    if (strFilename.empty())
        return;

    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(bitdb.cs_db);
        if (!bitdb.Open(GetDataDir()))
            throw runtime_error("env open failed");

        strFile = strFilename;
        ++bitdb.mapFileUseCount[strFile];
        pdb = bitdb.mapDb[strFile];
		if (pdb == NULL)
		{
			ret = db_create(&pdb, bitdb.dbenv, 0);
			if (ret != 0) {
				throw runtime_error(strprintf("Error: Cannot open %s\n", strFile.c_str()));
			}
            bool fMockDb = bitdb.IsMock();
            if (fMockDb)
            {
				DB_MPOOLFILE *mpf = pdb->get_mpf(pdb);
                ret = mpf->set_flags(mpf, DB_MPOOL_NOFILE, 1);
                if (ret != 0)
                    throw runtime_error(strprintf("CDB : Failed to configure for no temp file backing for database %s", strFile));
            }

            ret = pdb->open(pdb,
							NULL, // Txn pointer
                            fMockDb ? NULL : strFile.c_str(), // Filename
                            fMockDb ? strFile.c_str() : "main", // Logical db name
                            DB_BTREE, // Database type
                            nFlags, // Flags
                            0);

            if (ret != 0) {
                pdb = NULL;
                --bitdb.mapFileUseCount[strFile];
                strFile = "";
                throw runtime_error(strprintf("CDB : Error %d, can't open database %s", ret, strFile));
            }

            if (fCreate && !Exists(string("version"))) {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            bitdb.mapDb[strFile] = pdb;
        }
    }
}

void CDB::Close() {
	if (!pdb) {
		return;
	}
	if (activeTxn) {
		activeTxn->abort(activeTxn);
	}
    activeTxn = NULL;
    pdb = NULL;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;

    bitdb.dbenv->txn_checkpoint(bitdb.dbenv, nMinutes ? GetArg("-dblogsize", 100)*1024 : 0, nMinutes, 0);

    {
        LOCK(bitdb.cs_db);
        --bitdb.mapFileUseCount[strFile];
    }
	return;
}

void CDBEnv::CloseDb(const string& strFile) {
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL) {
            // Close the database handle
            DB *pdb = mapDb[strFile];
            pdb->close(pdb, 0);
            mapDb[strFile] = NULL;
        }
    }
}

bool CDBEnv::RemoveDb(const string& strFile) {
    this->CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv->dbremove(dbenv, NULL, strFile.c_str(), NULL, DB_AUTO_COMMIT);
    return (rc == 0);
}

bool CDB::Rewrite(const string& strFile, const char* pszSkip) {
	int ret;

    while (true)
    {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(strFile) || bitdb.mapFileUseCount[strFile] == 0)
            {
                // Flush log data to the dat file
                bitdb.CloseDb(strFile);
                bitdb.CheckpointLSN(strFile);
                bitdb.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                LogPrintf("Rewriting %s...\n", strFile);
                string strFileRes = strFile + ".rewrite";
                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
					DB *pdbCopy;
					if (0 != (ret = db_create(&pdbCopy, bitdb.dbenv, 0))) {
						LogPrintf("Verify Failed for: %s\n", strFile.c_str());
						fSuccess = false;
						goto start_loop;
					}

                    ret = pdbCopy->open(pdbCopy,
											NULL,                 // Txn pointer
                                            strFileRes.c_str(),   // Filename
                                            "main",    // Logical db name
                                            DB_BTREE,  // Database type
                                            DB_CREATE,    // Flags
                                            0);
                    if (ret > 0) {
                        LogPrintf("Cannot create database file %s\n", strFileRes);
                        fSuccess = false;
						goto start_loop;
                    }
start_loop:

					DBC *pcursor = NULL;
					if (0 != (ret = db.pdb->cursor(db.pdb, NULL, &pcursor, 0))) {
						while (fSuccess) {
							CDataStream ssKey(SER_DISK, CLIENT_VERSION);
							CDataStream ssValue(SER_DISK, CLIENT_VERSION);
							int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
							if (ret == DB_NOTFOUND) {
								pcursor->close(pcursor);
								break;
							}
							else if (ret != 0) {
								pcursor->close(pcursor);
								fSuccess = false;
								break;
							}
							if (pszSkip &&
								strncmp(&ssKey[0], pszSkip, std::min(ssKey.size(), strlen(pszSkip))) == 0)
								continue;
							if (strncmp(&ssKey[0], "\x07version", 8) == 0)
							{
								// Update version:
								ssValue.clear();
								ssValue << CLIENT_VERSION;
							}
							DBT datKey = DBT{ &ssKey[0], (uint32_t)ssKey.size() };
							DBT datValue = DBT{ &ssValue[0], (uint32_t)ssValue.size() };
							int ret2 = pdbCopy->put(pdbCopy, NULL, &datKey, &datValue, DB_NOOVERWRITE);
							if (ret2 > 0)
								fSuccess = false;
						}
					}
                    if (fSuccess) {
                        db.Close();
                        bitdb.CloseDb(strFile);
						if (pdbCopy->close(pdbCopy, 0)) {
							fSuccess = false;
						}
						pdbCopy = NULL;
                    }
                }
                if (fSuccess) {
					DB *dbA, *dbB;
					ret = db_create(&dbA, bitdb.dbenv, 0);
					if (ret != 0 && dbA->remove(dbA, strFile.c_str(), NULL, 0)) {
						fSuccess = false;
					}
                    ret = db_create(&dbB, bitdb.dbenv, 0);
					if (ret != 0 && dbB->rename(dbB, strFileRes.c_str(), NULL, strFile.c_str(), 0)) {
						fSuccess = false;
					}
                }
                if (!fSuccess)
                    LogPrintf("Rewriting of %s FAILED!\n", strFileRes);
                return fSuccess;
            }
        }
        MilliSleep(100);
    }
    return false;
}


void CDBEnv::Flush(bool fShutdown)
{
    int64_t nStart = GetTimeMillis();
    // Flush log data to the actual data file
    //  on all files that are not in use
    LogPrint("db", "Flush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
	if (!fDbEnvInit) {
		return;
	}

    {
        LOCK(cs_db);
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end()) {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            LogPrint("db", "%s refcount=%d\n", strFile, nRefCount);
            if (nRefCount == 0) {
                // Move log data to the dat file
                CloseDb(strFile);
                LogPrint("db", "%s checkpoint\n", strFile);
                dbenv->txn_checkpoint(dbenv, 0, 0, 0);
                LogPrint("db", "%s detach\n", strFile);
				if (!fMockDb) {
					dbenv->lsn_reset(dbenv, strFile.c_str(), 0);
				}
                LogPrint("db", "%s closed\n", strFile);
                mapFileUseCount.erase(mi++);
            } else {
				mi++;
			}
        }
        LogPrint("db", "DBFlush(%s)%s ended %15dms\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started", GetTimeMillis() - nStart);
        if (fShutdown) {
            char** listp;
            if (mapFileUseCount.empty()) {
                dbenv->log_archive(dbenv, &listp, DB_ARCH_REMOVE);
                Close();
            }
        }
    }
}
