﻿#include "smb_cs.h"
#include "smb_cs_inner.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <map>

#include "sqlite3.h"
#include "smcert.h"
#include "o_all_func_def.h"
#include "certificate_items_parse.h"
#include "openssl_func_def.h"
#include <math.h>
#include <FILE_LOG.h>

#if defined(WIN32) || defined(WINDOWS)
#include <Windows.h>
#include <WinCrypt.h>
#else
strcpy(smb_db_path, "/home/");
#endif

std::map<void*, int> g_mapPtr2IDs;

/*
defines
*/

#define LOCK_SQLITE()  
#define UNLOCK_SQLITE()  

#define SDB_SQLITE_BUSY_TIMEOUT 1000 /* milliseconds */
#define SDB_BUSY_RETRY_TIME        5 /* seconds */
#define SDB_MAX_BUSY_RETRIES      10


typedef struct SDB {
	sqlite3 *sdb_p;
	char * sdb_path;
}SDB;

/*
vars
*/

char smb_db_path[BUFFER_LEN_1K] = { 0 };

static const char BEGIN_CMD[] = "BEGIN IMMEDIATE TRANSACTION;";
static const char COMMIT_CMD[] = "COMMIT TRANSACTION;";
static const char ROLLBACK_CMD[] = "ROLLBACK TRANSACTION;";
static const char CHECK_TABLE_CMD[] = "SELECT ALL * FROM %s LIMIT 0;";
static const char *CREATE_TABLE_CMD[] =
{ "CREATE TABLE if not exists table_certificate (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, content UNIQUE ON CONFLICT REPLACE, store_type, id_attr);"
, "CREATE TABLE if not exists table_certificate_attr (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after);"
, "CREATE TABLE if not exists table_skf (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name, path UNIQUE ON CONFLICT REPLACE, signtype, pin_verify);"
, "CREATE TABLE if not exists table_pid_vid (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, pid UNIQUE ON CONFLICT REPLACE, vid, type);"
, "CREATE TABLE if not exists table_product (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name UNIQUE ON CONFLICT REPLACE, id_skf, id_pid_vid);"
, "CREATE TABLE if not exists table_check_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type UNIQUE ON CONFLICT REPLACE, description);"
, "CREATE TABLE if not exists table_check_keyid_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, keyid UNIQUE ON CONFLICT REPLACE, type);"
, "CREATE TABLE if not exists table_fix_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type UNIQUE ON CONFLICT REPLACE);"
, "CREATE TABLE if not exists table_data (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, data);"
, "CREATE TABLE if not exists table_element (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, data, description);"
, "CREATE TABLE if not exists table_tlv (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, value);"
, "CREATE TABLE if not exists table_fileinfo (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name UNIQUE ON CONFLICT REPLACE, path, digest_md5, digest_sha1, filetype, category);"
, "CREATE TABLE if not exists table_csp (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name UNIQUE ON CONFLICT REPLACE, value);"
};


/*
functions declar
*/

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

/*
function implement
*/

static int sdb_openDB(const char *name, sqlite3 **sqlDB)
{
	int sqlerr = SQLITE_OK;

	int bFlagExist = 0;
	int bFlagUpdate = 0;

	*sqlDB = NULL;
	sqlerr = sqlite3_open(name, sqlDB);
	if (sqlerr != SQLITE_OK) {
		goto err;
	}

#if defined(SQLITE_HAS_CODEC)
	sqlerr = sqlite3_key(*sqlDB, "abcdef",6);
#endif

	sqlerr = sqlite3_busy_timeout(*sqlDB, SDB_SQLITE_BUSY_TIMEOUT);
	if (sqlerr != SQLITE_OK) {
		sqlite3_close(*sqlDB);
		*sqlDB = NULL;
		return sqlerr;
	}

err:

	return sqlerr;
}

static int sdb_done(int err, int *count)
{
	/* allow as many rows as the database wants to give */
	if (err == SQLITE_ROW) {
		*count = 0;
		return 0;
	}
	if (err != SQLITE_BUSY) {
		return 1;
	}
	/* err == SQLITE_BUSY, Dont' retry forever in this case */
	if (++(*count) >= SDB_MAX_BUSY_RETRIES) {
		return 1;
	}
	return 0;
}

static int sdb_complete(sqlite3 *sdb, const char *cmd)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;

	sqlerr = sqlite3_prepare_v2(sdb, cmd, -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);
		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}
err:

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sqlite3_close(sdb);

	return sqlerr;
}

int sdb_Begin(SDB *sdb, int bTransaction)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;

	LOCK_SQLITE();

	/* get a new version that we will use for the entire transaction */
	sqlerr = sdb_openDB(sdb->sdb_path, &sdb->sdb_p);
	if (sqlerr != SQLITE_OK) {
		goto err;
	}

	if ( 1 == bTransaction)
	{
		sqlerr = sqlite3_prepare_v2(sdb->sdb_p, BEGIN_CMD, -1, &stmt, NULL);
	
		if (sqlerr != SQLITE_OK)
		{
			goto err;
		}

		do {
			sqlerr = sqlite3_step(stmt);

			if (sqlerr == SQLITE_BUSY) {
				sqlite3_sleep(SDB_BUSY_RETRY_TIME);
			}

			if (sqlerr == SQLITE_DONE)
			{
				sqlerr = SQLITE_OK;
			}

		} while (!sdb_done(sqlerr, &retry));

		if (sqlerr == SQLITE_ROW)
		{
			sqlerr = SQLITE_OK;
		}

    }

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	if (sqlerr == SQLITE_OK) {

	}
	else {
		/* we failed to start our transaction,
		* free any databases we opened. */
		if (sdb->sdb_p) {
			sqlite3_close(sdb->sdb_p);
		}
	}

	UNLOCK_SQLITE();
	return sqlerr;
}

int sdb_Commit(SDB *sdb, int bTransaction)
{
	if (1 == bTransaction)
	{
		int crv;
		LOCK_SQLITE();
		crv = sdb_complete(sdb->sdb_p, COMMIT_CMD);
		UNLOCK_SQLITE();
		return crv;
	}
	else
	{
		return sqlite3_close(sdb->sdb_p);
	}
}

int sdb_Abort(SDB *sdb, int bTransaction)
{
	if (1 == bTransaction)
	{
		int crv;
		LOCK_SQLITE();
		crv = sdb_complete(sdb->sdb_p, ROLLBACK_CMD);
		UNLOCK_SQLITE();
		return crv;
	}
	else
	{
		return sqlite3_close(sdb->sdb_p);
	}
}

/* return 1 if sqlDB contains table 'tableName */
static int tableExists(sqlite3 *sqlDB, const char *tableName)
{
	char * cmd = sqlite3_mprintf(CHECK_TABLE_CMD, tableName);
	int sqlerr = SQLITE_OK;

	if (cmd == NULL) {
		return 0;
	}

	sqlerr = sqlite3_exec(sqlDB, cmd, NULL, 0, 0);
	sqlite3_free(cmd);

	return (sqlerr == SQLITE_OK) ? 1 : 0;
}

int sdb_Init(SDB *sdb)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;

	int i = 0;
	LOCK_SQLITE();

	for (i = 0; i < sizeof(CREATE_TABLE_CMD) / sizeof(char *); i++)
	{
		const char *cmd = CREATE_TABLE_CMD[i];
		sqlerr = sqlite3_exec(sdb->sdb_p, cmd, NULL, 0, NULL);
		if (sqlerr != SQLITE_OK)
		{
			goto err;
		}
	}
err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();
	return sqlerr;
}



COMMON_API unsigned int CALL_CONVENTION SMB_CS_Init()
{
	int crv = 0;
	SDB sdb = { 0 };

	SMB_CS_SetPath(NULL);

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 1);
	if (crv)
	{
		goto err;
	}

	crv = sdb_Init(&sdb);
	if (crv)
	{
		goto err;
	}
err:

	if (crv)
	{
		sdb_Abort(&sdb, 1);
	}
	else
	{
		sdb_Commit(&sdb, 1);
	}


	return crv;
}

int sdb_EnumSKF(SDB *sdb, char * pszSKFNames, unsigned int * puiSKFNamesLen)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;
	char data_value[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len_real = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_skf;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			memcpy(data_value + data_len_real, (char *)sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));

			data_len_real += sqlite3_column_bytes(stmt, 1);

			data_value[data_len_real] = '\0';
			data_len_real += 1;
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{
		if (NULL == pszSKFNames)
		{
			*puiSKFNamesLen = data_len_real;
			sqlerr = 0;
		}
		else if (*puiSKFNamesLen < data_len_real)
		{
			*puiSKFNamesLen = data_len_real;
			sqlerr = EErr_SMB_MEM_LES;
		}
		else
		{
			*puiSKFNamesLen = data_len_real;
			memcpy(pszSKFNames, data_value, data_len_real);
			sqlerr = 0;
		}
	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_CreateCertCtx(SMB_CS_CertificateContext **ppCertCtx, unsigned char *pCertificate, unsigned int uiCertificateLen)
{
	SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));
	unsigned int uiRet = -1;

	if (!pCertCtx)
	{
		uiRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));

	pCertCtx->stContent.length = uiCertificateLen;
	pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
	memcpy(pCertCtx->stContent.data, pCertificate, pCertCtx->stContent.length);

	uiRet = SMB_CS_FillCertAttr(pCertCtx);
	if (0 != uiRet)
	{
		goto err;
	}
	*ppCertCtx = pCertCtx;
err:

	return uiRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FillCertAttr(SMB_CS_CertificateContext * pCertCtx)
{
	unsigned int ulRet = 0;
	if (NULL == pCertCtx)
	{
		goto err;
	}
	else
	{
		{
			CertificateItemParse certParse;

			if (0 != certParse.setCertificate(pCertCtx->stContent.data, pCertCtx->stContent.length))
			{
				ulRet = EErr_SMB_INVALID_ARG;
				goto err;
			}

			certParse.parse();

			pCertCtx->stAttr.ucCertAlgType = certParse.m_iKeyAlg;

			if (pCertCtx->stAttr.stSubjectKeyID.data)
			{
				free(pCertCtx->stAttr.stSubjectKeyID.data);
				pCertCtx->stAttr.stSubjectKeyID.data = NULL;
			}
			pCertCtx->stAttr.stSubjectKeyID.length = certParse.m_strSubjectKeyID.size();
			pCertCtx->stAttr.stSubjectKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubjectKeyID.length);
			memcpy(pCertCtx->stAttr.stSubjectKeyID.data, certParse.m_strSubjectKeyID.c_str(), pCertCtx->stAttr.stSubjectKeyID.length);

			if (pCertCtx->stAttr.stIssueKeyID.data)
			{
				free(pCertCtx->stAttr.stIssueKeyID.data);
				pCertCtx->stAttr.stIssueKeyID.data = NULL;
			}
			pCertCtx->stAttr.stIssueKeyID.length = certParse.m_strIssueKeyID.size();
			pCertCtx->stAttr.stIssueKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssueKeyID.length);
			memcpy(pCertCtx->stAttr.stIssueKeyID.data, certParse.m_strIssueKeyID.c_str(), pCertCtx->stAttr.stIssueKeyID.length);

			if (pCertCtx->stAttr.stIssue.data)
			{
				free(pCertCtx->stAttr.stIssue.data);
				pCertCtx->stAttr.stIssue.data = NULL;
			}
			pCertCtx->stAttr.stIssue.length = certParse.m_strIssue.size();
			pCertCtx->stAttr.stIssue.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssue.length);
			memcpy(pCertCtx->stAttr.stIssue.data, (unsigned char *)&certParse.m_strIssue.front(), pCertCtx->stAttr.stIssue.length);

			if (pCertCtx->stAttr.stSubject.data)
			{
				free(pCertCtx->stAttr.stSubject.data);
				pCertCtx->stAttr.stSubject.data = NULL;
			}
			pCertCtx->stAttr.stSubject.length = certParse.m_strSubject.size();
			pCertCtx->stAttr.stSubject.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubject.length);
			memcpy(pCertCtx->stAttr.stSubject.data, (unsigned char *)&certParse.m_strSubject.front(), pCertCtx->stAttr.stSubject.length);
		}

		// 证书的属性
		char data_info_value[1024] = { 0 };
		int data_info_len = 0;

		WT_SetMyCert(pCertCtx->stContent.data, pCertCtx->stContent.length);

		memset(data_info_value, 0, 1024);
		WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
		if (pCertCtx->stAttr.stSerialNumber.data)
		{
			free(pCertCtx->stAttr.stSerialNumber.data);
			pCertCtx->stAttr.stSerialNumber.data = NULL;
		}
		pCertCtx->stAttr.stSerialNumber.length = strlen(data_info_value) + 1;
		pCertCtx->stAttr.stSerialNumber.data = (unsigned char *)malloc(pCertCtx->stAttr.stSerialNumber.length);
		memcpy(pCertCtx->stAttr.stSerialNumber.data, data_info_value, pCertCtx->stAttr.stSerialNumber.length);

		memset(data_info_value, 0, 1024);
		WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
		if (pCertCtx->stAttr.stCommonName.data)
		{
			free(pCertCtx->stAttr.stCommonName.data);
			pCertCtx->stAttr.stCommonName.data = NULL;
		}
		pCertCtx->stAttr.stCommonName.length = strlen(data_info_value) + 1;
		pCertCtx->stAttr.stCommonName.data = (unsigned char *)malloc(pCertCtx->stAttr.stCommonName.length);
		memcpy(pCertCtx->stAttr.stCommonName.data, data_info_value, pCertCtx->stAttr.stCommonName.length);

		WT_ClearCert();


	}

err:

	return ulRet;

}

int sdb_FillCertCtx(SMB_CS_CertificateContext **ppCertCtx, SMB_CS_CertificateFindAttr *pCertificateFindAttr, sqlite3_stmt *stmt)
{
	SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));

	memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));


	//id content, store_type, id_attr,
	//cert_alg_type, cert_usage_type, skf_name, device_name, application_name, 
	//container_name, common_name, subject, isuue, public_key, serial_number, 
	//subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after

	int pos = -1;

	pos += 1;

	g_mapPtr2IDs[&pCertCtx->stContent] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stContent.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
	memcpy(pCertCtx->stContent.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stContent.length);

	pos += 1;
	pCertCtx->ucStoreType = sqlite3_column_int(stmt, pos);

	pos += 1;
	g_mapPtr2IDs[&pCertCtx->stAttr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stAttr.ucCertAlgType = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stAttr.ucCertUsageType = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stAttr.stSKFName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSKFName.data = (unsigned char *)malloc(pCertCtx->stAttr.stSKFName.length);
	memcpy(pCertCtx->stAttr.stSKFName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSKFName.length);

	pos += 1;
	pCertCtx->stAttr.stDeviceName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stDeviceName.data = (unsigned char *)malloc(pCertCtx->stAttr.stDeviceName.length);
	memcpy(pCertCtx->stAttr.stDeviceName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stDeviceName.length);

	pos += 1;
	pCertCtx->stAttr.stApplicationName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stApplicationName.data = (unsigned char *)malloc(pCertCtx->stAttr.stApplicationName.length);
	memcpy(pCertCtx->stAttr.stApplicationName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stApplicationName.length);

	pos += 1;
	pCertCtx->stAttr.stContainerName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stContainerName.data = (unsigned char *)malloc(pCertCtx->stAttr.stContainerName.length);
	memcpy(pCertCtx->stAttr.stContainerName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stContainerName.length);

	pos += 1;
	pCertCtx->stAttr.stCommonName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stCommonName.data = (unsigned char *)malloc(pCertCtx->stAttr.stCommonName.length);
	memcpy(pCertCtx->stAttr.stCommonName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stCommonName.length);

	pos += 1;
	pCertCtx->stAttr.stSubject.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSubject.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubject.length);
	memcpy(pCertCtx->stAttr.stSubject.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSubject.length);

	pos += 1;
	pCertCtx->stAttr.stIssue.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stIssue.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssue.length);
	memcpy(pCertCtx->stAttr.stIssue.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stIssue.length);

	pos += 1;
	pCertCtx->stAttr.stPublicKey.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stPublicKey.data = (unsigned char *)malloc(pCertCtx->stAttr.stPublicKey.length);
	memcpy(pCertCtx->stAttr.stPublicKey.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stPublicKey.length);

	pos += 1;
	pCertCtx->stAttr.stSerialNumber.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSerialNumber.data = (unsigned char *)malloc(pCertCtx->stAttr.stSerialNumber.length);
	memcpy(pCertCtx->stAttr.stSerialNumber.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSerialNumber.length);

	pos += 1;
	pCertCtx->stAttr.stSubjectKeyID.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSubjectKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubjectKeyID.length);
	memcpy(pCertCtx->stAttr.stSubjectKeyID.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSubjectKeyID.length);

	pos += 1;
	pCertCtx->stAttr.stIssueKeyID.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stIssueKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssueKeyID.length);
	memcpy(pCertCtx->stAttr.stIssueKeyID.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stIssueKeyID.length);

	pos += 1;
	pCertCtx->stAttr.stVendorData.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stVendorData.data = (unsigned char *)malloc(pCertCtx->stAttr.stVendorData.length);
	memcpy(pCertCtx->stAttr.stVendorData.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stVendorData.length);


	pos += 1;
	pCertCtx->stAttr.ulVerify = sqlite3_column_int(stmt, pos);


	pos += 1;
	pCertCtx->stAttr.ulNotBefore = sqlite3_column_int64(stmt, pos);


	pos += 1;
	pCertCtx->stAttr.ulNotAfter = sqlite3_column_int64(stmt, pos);

	//if (pCertificateFindAttr && (pCertificateFindAttr->uiFindFlag & 0x10))
	//{
	//	FILE_WRITE_FMT(file_log_name, "%x", pCertificateFindAttr->uiFindFlag);
	//	if (pCertificateFindAttr->stIssue.data)
	//	{
	//		FILE_WRITE_FMT(file_log_name, "%d %s pCertificateFindAttr length=%d", __LINE__, __FUNCTION__, pCertificateFindAttr->stIssue.length);
	//		//FILE_WRITE_FMT(file_log_name, "%d %s pCertificateFindAttr %s", __LINE__, __FUNCTION__, pCertificateFindAttr->stIssue.data);
	//		FILE_WRITE_HEX(file_log_name, pCertificateFindAttr->stIssue.data, pCertificateFindAttr->stIssue.length);
	//	}

	//	if (pCertCtx->stAttr.stIssue.data)
	//	{
	//		FILE_WRITE_FMT(file_log_name, "%d %s pCertCtx length=%d", __LINE__, __FUNCTION__, pCertCtx->stAttr.stIssue.length);
	//		//FILE_WRITE_FMT(file_log_name, "%d %s pCertificateFindAttr %s", __LINE__, __FUNCTION__, pCertCtx->stAttr.stIssue.data);
	//		FILE_WRITE_HEX(file_log_name, pCertCtx->stAttr.stIssue.data, pCertCtx->stAttr.stIssue.length);
	//	}
	//	FILE_WRITE_FMT(file_log_name, "\n\n");
	//}


	if (NULL == pCertificateFindAttr)
	{
		*ppCertCtx = pCertCtx;
	}
	else
	{
		bool bExist = true;

		if ((pCertificateFindAttr->uiFindFlag & 1) && pCertCtx->stAttr.ucCertAlgType != pCertificateFindAttr->ucCertAlgType)
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 2) && pCertCtx->stAttr.ucCertUsageType != pCertificateFindAttr->ucCertUsageType)
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 4) && pCertCtx->ucStoreType != pCertificateFindAttr->ucStoreType)
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 8) && 0 != memcmp(pCertCtx->stAttr.stSubject.data, pCertificateFindAttr->stSubject.data, pCertificateFindAttr->stSubject.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 16) && 0 != memcmp(pCertCtx->stAttr.stIssue.data, pCertificateFindAttr->stIssue.data, pCertificateFindAttr->stIssue.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 32) && 0 != memcmp(pCertCtx->stAttr.stPublicKey.data, pCertificateFindAttr->stPublicKey.data, pCertificateFindAttr->stPublicKey.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 64) && 0 != memcmp(pCertCtx->stAttr.stSerialNumber.data, pCertificateFindAttr->stSerialNumber.data, pCertificateFindAttr->stSerialNumber.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 128) && 0 != memcmp(pCertCtx->stAttr.stSubjectKeyID.data, pCertificateFindAttr->stSubjectKeyID.data, pCertificateFindAttr->stSubjectKeyID.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 256) && 0 != memcmp(pCertCtx->stAttr.stIssueKeyID.data, pCertificateFindAttr->stIssueKeyID.data, pCertificateFindAttr->stIssueKeyID.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 512) && 0 != memcmp(pCertCtx->stAttr.stVendorData.data, pCertificateFindAttr->stVendorData.data, pCertificateFindAttr->stVendorData.length))
		{
			bExist = false;
		}

		if (bExist)
		{
			*ppCertCtx = pCertCtx;
		}
		else
		{
			SMB_CS_FreeCertCtx(pCertCtx);
			*ppCertCtx = NULL;
		}
	}

	return 0;
}

int sdb_FindCertCtx(SDB *sdb, SMB_CS_CertificateFindAttr *pCertificateFindAttr, SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select a.id as id, content, store_type, id_attr, "
		"cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after "
		"from table_certificate as a,table_certificate_attr as b where a.id_attr=b.id; ", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_CertificateContext *pCertCtx = NULL;
			sdb_FillCertCtx(&pCertCtx, pCertificateFindAttr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppCertCtxNodeHeader, (void *)pCertCtx);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FindCertCtx(SMB_CS_CertificateFindAttr *pCertificateFindAttr, SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;



	crv = sdb_Begin(&sdb, 0);
	if (crv)
	{
		goto err;
	}

	crv = sdb_FindCertCtx(&sdb, pCertificateFindAttr, ppCertCtxNodeHeader);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 0);
	}
	else
	{
		sdb_Commit(&sdb, 0);
	}

	return crv;
}



COMMON_API unsigned int CALL_CONVENTION SMB_CS_SetCertCtxVendor(SMB_CS_CertificateContext *pCertCtx, unsigned char *pVendor, unsigned int uiVendorLen)
{
	unsigned int ulRet = 0;
	if (NULL == pCertCtx)
	{
		goto err;
	}
	else
	{
		if (pCertCtx->stAttr.stVendorData.data)
		{
			free(pCertCtx->stAttr.stVendorData.data);
			pCertCtx->stAttr.stVendorData.data = NULL;
		}

		pCertCtx->stAttr.stVendorData.length = uiVendorLen;
		pCertCtx->stAttr.stVendorData.data = (unsigned char *)malloc(pCertCtx->stAttr.stVendorData.length);
		memcpy(pCertCtx->stAttr.stVendorData.data, pVendor, pCertCtx->stAttr.stVendorData.length);
	}
err:
	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeCertCtx(SMB_CS_CertificateContext *pCertCtx)
{
	if (pCertCtx)
	{
		if (pCertCtx->stContent.data)
		{
			free(pCertCtx->stContent.data);
			pCertCtx->stContent.data = NULL;
		}

		if (pCertCtx->stAttr.stSKFName.data)
		{
			free(pCertCtx->stAttr.stSKFName.data);
			pCertCtx->stAttr.stSKFName.data = NULL;
		}

		if (pCertCtx->stAttr.stDeviceName.data)
		{
			free(pCertCtx->stAttr.stDeviceName.data);
			pCertCtx->stAttr.stDeviceName.data = NULL;
		}

		if (pCertCtx->stAttr.stApplicationName.data)
		{
			free(pCertCtx->stAttr.stApplicationName.data);
			pCertCtx->stAttr.stApplicationName.data = NULL;
		}

		if (pCertCtx->stAttr.stContainerName.data)
		{
			free(pCertCtx->stAttr.stContainerName.data);
			pCertCtx->stAttr.stContainerName.data = NULL;
		}

		if (pCertCtx->stAttr.stCommonName.data)
		{
			free(pCertCtx->stAttr.stCommonName.data);
			pCertCtx->stAttr.stCommonName.data = NULL;
		}

		if (pCertCtx->stAttr.stSubject.data)
		{
			free(pCertCtx->stAttr.stSubject.data);
			pCertCtx->stAttr.stSubject.data = NULL;
		}

		if (pCertCtx->stAttr.stIssue.data)
		{
			free(pCertCtx->stAttr.stIssue.data);
			pCertCtx->stAttr.stIssue.data = NULL;
		}

		if (pCertCtx->stAttr.stPublicKey.data)
		{
			free(pCertCtx->stAttr.stPublicKey.data);
			pCertCtx->stAttr.stPublicKey.data = NULL;
		}

		if (pCertCtx->stAttr.stSerialNumber.data)
		{
			free(pCertCtx->stAttr.stSerialNumber.data);
			pCertCtx->stAttr.stSerialNumber.data = NULL;
		}

		if (pCertCtx->stAttr.stSubjectKeyID.data)
		{
			free(pCertCtx->stAttr.stSubjectKeyID.data);
			pCertCtx->stAttr.stSubjectKeyID.data = NULL;
		}

		if (pCertCtx->stAttr.stIssueKeyID.data)
		{
			free(pCertCtx->stAttr.stIssueKeyID.data);
			pCertCtx->stAttr.stIssueKeyID.data = NULL;
		}

		if (pCertCtx->stAttr.stVendorData.data)
		{
			free(pCertCtx->stAttr.stVendorData.data);
			pCertCtx->stAttr.stVendorData.data = NULL;
		}

		free(pCertCtx);
		pCertCtx = NULL;
	}

	return 0;
}


COMMON_API unsigned int CALL_CONVENTION SMB_CS_DuplicateCertAttr(IN SMB_CS_CertificateContext *pCertCtx, IN OUT SMB_CS_CertificateAttr **ppCertAttr)
{
	if (pCertCtx && ppCertAttr)
	{
		SMB_CS_CertificateAttr * pCertAttr = (SMB_CS_CertificateAttr *)malloc(sizeof(SMB_CS_CertificateAttr));

		memcpy(pCertAttr, &pCertCtx->stAttr, sizeof(SMB_CS_CertificateAttr));

		if (pCertCtx->stAttr.stSKFName.data)
		{
			pCertAttr->stSKFName.length = pCertCtx->stAttr.stSKFName.length;
			pCertAttr->stSKFName.data = (unsigned char *)malloc(pCertAttr->stSKFName.length);
			memcpy(pCertAttr->stSKFName.data, pCertCtx->stAttr.stSKFName.data, pCertCtx->stAttr.stSKFName.length);
		}

		if (pCertCtx->stAttr.stDeviceName.data)
		{
			pCertAttr->stDeviceName.length = pCertCtx->stAttr.stDeviceName.length;
			pCertAttr->stDeviceName.data = (unsigned char *)malloc(pCertAttr->stDeviceName.length);
			memcpy(pCertAttr->stDeviceName.data, pCertCtx->stAttr.stDeviceName.data, pCertCtx->stAttr.stDeviceName.length);
		}

		if (pCertCtx->stAttr.stApplicationName.data)
		{
			pCertAttr->stApplicationName.length = pCertCtx->stAttr.stApplicationName.length;
			pCertAttr->stApplicationName.data = (unsigned char *)malloc(pCertAttr->stApplicationName.length);
			memcpy(pCertAttr->stApplicationName.data, pCertCtx->stAttr.stApplicationName.data, pCertCtx->stAttr.stApplicationName.length);
		}

		if (pCertCtx->stAttr.stContainerName.data)
		{
			pCertAttr->stContainerName.length = pCertCtx->stAttr.stContainerName.length;
			pCertAttr->stContainerName.data = (unsigned char *)malloc(pCertAttr->stContainerName.length);
			memcpy(pCertAttr->stContainerName.data, pCertCtx->stAttr.stContainerName.data, pCertCtx->stAttr.stContainerName.length);
		}

		if (pCertCtx->stAttr.stCommonName.data)
		{
			pCertAttr->stCommonName.length = pCertCtx->stAttr.stCommonName.length;
			pCertAttr->stCommonName.data = (unsigned char *)malloc(pCertAttr->stCommonName.length);
			memcpy(pCertAttr->stCommonName.data, pCertCtx->stAttr.stCommonName.data, pCertCtx->stAttr.stCommonName.length);
		}

		if (pCertCtx->stAttr.stSubject.data)
		{
			pCertAttr->stSubject.length = pCertCtx->stAttr.stSubject.length;
			pCertAttr->stSubject.data = (unsigned char *)malloc(pCertAttr->stSubject.length);
			memcpy(pCertAttr->stSubject.data, pCertCtx->stAttr.stSubject.data, pCertCtx->stAttr.stSubject.length);
		}

		if (pCertCtx->stAttr.stIssue.data)
		{
			pCertAttr->stIssue.length = pCertCtx->stAttr.stIssue.length;
			pCertAttr->stIssue.data = (unsigned char *)malloc(pCertAttr->stIssue.length);
			memcpy(pCertAttr->stIssue.data, pCertCtx->stAttr.stIssue.data, pCertCtx->stAttr.stIssue.length);
		}

		if (pCertCtx->stAttr.stPublicKey.data)
		{
			pCertAttr->stPublicKey.length = pCertCtx->stAttr.stPublicKey.length;
			pCertAttr->stPublicKey.data = (unsigned char *)malloc(pCertAttr->stPublicKey.length);
			memcpy(pCertAttr->stPublicKey.data, pCertCtx->stAttr.stPublicKey.data, pCertCtx->stAttr.stPublicKey.length);
		}

		if (pCertCtx->stAttr.stSerialNumber.data)
		{
			pCertAttr->stSerialNumber.length = pCertCtx->stAttr.stSerialNumber.length;
			pCertAttr->stSerialNumber.data = (unsigned char *)malloc(pCertAttr->stSerialNumber.length);
			memcpy(pCertAttr->stSerialNumber.data, pCertCtx->stAttr.stSerialNumber.data, pCertCtx->stAttr.stSerialNumber.length);
		}

		if (pCertCtx->stAttr.stSubjectKeyID.data)
		{
			pCertAttr->stSubjectKeyID.length = pCertCtx->stAttr.stSubjectKeyID.length;
			pCertAttr->stSubjectKeyID.data = (unsigned char *)malloc(pCertAttr->stSubjectKeyID.length);
			memcpy(pCertAttr->stSubjectKeyID.data, pCertCtx->stAttr.stSubjectKeyID.data, pCertCtx->stAttr.stSubjectKeyID.length);
		}

		if (pCertCtx->stAttr.stIssueKeyID.data)
		{
			pCertAttr->stIssueKeyID.length = pCertCtx->stAttr.stIssueKeyID.length;
			pCertAttr->stIssueKeyID.data = (unsigned char *)malloc(pCertAttr->stIssueKeyID.length);
			memcpy(pCertAttr->stIssueKeyID.data, pCertCtx->stAttr.stIssueKeyID.data, pCertCtx->stAttr.stIssueKeyID.length);
		}

		if (pCertCtx->stAttr.stVendorData.data)
		{
			pCertAttr->stVendorData.length = pCertCtx->stAttr.stVendorData.length;
			pCertAttr->stVendorData.data = (unsigned char *)malloc(pCertAttr->stVendorData.length);
			memcpy(pCertAttr->stVendorData.data, pCertCtx->stAttr.stVendorData.data, pCertCtx->stAttr.stVendorData.length);
		}

		*ppCertAttr = pCertAttr;
	}

	return 0;
}


COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeCertAttr(IN SMB_CS_CertificateAttr *pCertAttr)
{
	if (pCertAttr)
	{
		if (pCertAttr->stSKFName.data)
		{
			free(pCertAttr->stSKFName.data);
			pCertAttr->stSKFName.data = NULL;
		}

		if (pCertAttr->stDeviceName.data)
		{
			free(pCertAttr->stDeviceName.data);
			pCertAttr->stDeviceName.data = NULL;
		}

		if (pCertAttr->stApplicationName.data)
		{
			free(pCertAttr->stApplicationName.data);
			pCertAttr->stApplicationName.data = NULL;
		}

		if (pCertAttr->stContainerName.data)
		{
			free(pCertAttr->stContainerName.data);
			pCertAttr->stContainerName.data = NULL;
		}

		if (pCertAttr->stCommonName.data)
		{
			free(pCertAttr->stCommonName.data);
			pCertAttr->stCommonName.data = NULL;
		}

		if (pCertAttr->stSubject.data)
		{
			free(pCertAttr->stSubject.data);
			pCertAttr->stSubject.data = NULL;
		}

		if (pCertAttr->stIssue.data)
		{
			free(pCertAttr->stIssue.data);
			pCertAttr->stIssue.data = NULL;
		}

		if (pCertAttr->stPublicKey.data)
		{
			free(pCertAttr->stPublicKey.data);
			pCertAttr->stPublicKey.data = NULL;
		}

		if (pCertAttr->stSerialNumber.data)
		{
			free(pCertAttr->stSerialNumber.data);
			pCertAttr->stSerialNumber.data = NULL;
		}

		if (pCertAttr->stSubjectKeyID.data)
		{
			free(pCertAttr->stSubjectKeyID.data);
			pCertAttr->stSubjectKeyID.data = NULL;
		}

		if (pCertAttr->stIssueKeyID.data)
		{
			free(pCertAttr->stIssueKeyID.data);
			pCertAttr->stIssueKeyID.data = NULL;
		}

		if (pCertAttr->stVendorData.data)
		{
			free(pCertAttr->stVendorData.data);
			pCertAttr->stVendorData.data = NULL;
		}

		free(pCertAttr);
		pCertAttr = NULL;
	}

	return 0;
}


COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeCertCtxLink(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader)
{
	while (*ppCertCtxNodeHeader)
	{
		SMB_CS_FreeCertCtx((*ppCertCtxNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppCertCtxNodeHeader, (*ppCertCtxNodeHeader)->ptr_data);
	}

	return 0;
}

unsigned int sdb_GetCertCtxByCert(SDB *sdb, SMB_CS_CertificateContext **ppCertCtx, unsigned char *pCertificate, unsigned int uiCertificateLen)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select a.id as id, content, store_type, id_attr, "
		"cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after "
		"from table_certificate as a,table_certificate_attr as b where a.id_attr=b.id and content=$content limit 0,1;", -1, &stmt, NULL);

	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	sqlerr = sqlite3_bind_blob(stmt, 1, pCertificate, uiCertificateLen, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_CertificateContext *pCertCtx = NULL;
			sdb_FillCertCtx(&pCertCtx, NULL, stmt);
			*ppCertCtx = pCertCtx;
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_GetCertCtxByCert(SMB_CS_CertificateContext **ppCertCtx, unsigned char *pCertificate, unsigned int uiCertificateLen)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 0);
	if (crv)
	{
		goto err;
	}

	crv = sdb_GetCertCtxByCert(&sdb, ppCertCtx, pCertificate, uiCertificateLen);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 0);
	}
	else
	{
		sdb_Commit(&sdb, 0);
	}

	return crv;
}


int GetExtAuthorityIdentifier(PCCERT_CONTEXT pCertContext, unsigned char *lpscProperty, unsigned int* pulLen)
{
	int ulRes = 0;
	DWORD ulDataLen = 512;
	int ulPropertyLen = 512;
	BYTE btData[512] = { 0 };
	CHAR csProperty[512] = { 0 };
	PCERT_AUTHORITY_KEY_ID2_INFO pAuthorityKeyID2 = NULL;
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return -1;
	}
	if (!pulLen)
	{
		return -1;
	}

	pCertExt = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);
	if (!pCertExt)
	{
		return -1;
	}

	pAuthorityKeyID2 = (PCERT_AUTHORITY_KEY_ID2_INFO)btData;
	if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING, szOID_AUTHORITY_KEY_IDENTIFIER2,
		pCertExt->Value.pbData, pCertExt->Value.cbData,
		CRYPT_DECODE_NOCOPY_FLAG, pAuthorityKeyID2, &ulDataLen))
	{

	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = pAuthorityKeyID2->KeyId.cbData;
	}
	else if (*pulLen < pAuthorityKeyID2->KeyId.cbData)
	{
		return -1;
	}
	else
	{
		*pulLen = pAuthorityKeyID2->KeyId.cbData;
		memcpy(lpscProperty, pAuthorityKeyID2->KeyId.pbData, *pulLen);
	}

	return 0;
}

#if defined(WIN32) || defined(WINDOWS)

int GetExtSubjectIdentifier(PCCERT_CONTEXT pCertContext,
	unsigned char * lpscProperty,
	unsigned int* pulLen)
{
	int ulRes = 0;
	DWORD ulDataLen = 512;
	int ulPropertyLen = 512;
	BYTE btData[512] = { 0 };
	CHAR csProperty[512] = { 0 };
	PCERT_EXTENSION pCertExt = NULL;
	PCRYPT_DATA_BLOB pDataBlob = NULL;

	if (!pCertContext)
	{
		return -1;
	}
	if (!pulLen)
	{
		return -1;
	}

	pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);
	if (!pCertExt)
	{
		return -1;
	}

	pDataBlob = (PCRYPT_DATA_BLOB)btData;
	if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING, szOID_SUBJECT_KEY_IDENTIFIER,
		pCertExt->Value.pbData, pCertExt->Value.cbData,
		CRYPT_DECODE_NOCOPY_FLAG, pDataBlob, &ulDataLen))
	{

	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = pDataBlob->cbData;
	}
	else if (*pulLen < pDataBlob->cbData)
	{
		return -1;
	}
	else
	{
		*pulLen = pDataBlob->cbData;
		memcpy(lpscProperty, pDataBlob->pbData, *pulLen);
	}

	return 0;
}
#endif

COMMON_API unsigned int CALL_CONVENTION SMB_CS_VerifyCert(unsigned int uiFlag, unsigned char* pbCert, unsigned int uiCertLen)
{
	unsigned int ulRet = 0;

	unsigned int ulAlgType = 0;

	CertificateItemParse certParse;

	SMB_CS_CertificateContext *ctx = NULL;

	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;

#if defined(WIN32) || defined(WINDOWS)
	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = { 0 };
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;
#endif

	if (0 != certParse.setCertificate(pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	certParse.parse();

	ulAlgType = certParse.m_iKeyAlg;

	if (SMB_CERT_ALG_FLAG_RSA == ulAlgType || SMB_CERT_ALG_FLAG_SM2 == ulAlgType)
	{
#if defined(WIN32) || defined(WINDOWS)
		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}

		// TIME
		if (SMB_CERT_VERIFY_FLAG_TIME & uiFlag)
		{
			ulRet = CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
			if (ulRet)
			{
				ulRet = EErr_SMB_VERIFY_TIME;
				goto err;
			}
		}

		// SIGN CERT
		if (SMB_CERT_VERIFY_FLAG_CHAIN & uiFlag)
		{
			// 打开存储区		
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
												 // not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
												 // registry location
				L"Ca"                            // The store name as a Unicode 
												 // string
			);

			if (NULL == hCertStore)
			{
				ulRet = EErr_SMB_OPEN_STORE;
				goto err;
			}

			// 查找颁发者证书
			// certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
			{
				CERT_ID id;

				unsigned char data_value_keyid[1024] = { 0 };
				unsigned int data_len_keyid = 1024;

				id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;

				GetExtAuthorityIdentifier(certContext_IN, data_value_keyid, &data_len_keyid);
				FILE_LOG_FMT(file_log_name, "%s", "data_value_keyid");
				FILE_LOG_HEX(file_log_name, data_value_keyid, data_len_keyid);

				id.KeyId.pbData = data_value_keyid;
				id.KeyId.cbData = data_len_keyid;

				certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL);
			}

			if (NULL == certContext_OUT)
			{
				// 查找颁发者证书
				certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
			}

			if (NULL == certContext_OUT)
			{
				if (hCertStore)
				{
					// 关闭存储区
					CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
				}

				// 打开存储区		
				hCertStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM,          // The store provider type
					0,                               // The encoding type is
													 // not needed
					NULL,                            // Use the default HCRYPTPROV
					CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													 // registry location
					L"Root"                            // The store name as a Unicode 
													   // string
				);

				if (NULL == hCertStore)
				{
					ulRet = EErr_SMB_OPEN_STORE;
					goto err;
				}

				
				{
					CERT_ID id;

					unsigned char data_value_keyid[1024] = { 0 };
					unsigned int data_len_keyid = 1024;

					id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;

					GetExtAuthorityIdentifier(certContext_IN, data_value_keyid, &data_len_keyid);
					//FILE_LOG_FMT(file_log_name, "%s", "data_value_keyid");
					//FILE_LOG_HEX(file_log_name, data_value_keyid, data_len_keyid);

					id.KeyId.pbData = data_value_keyid;
					id.KeyId.cbData = data_len_keyid;

					certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL);
				}
			}

			if (NULL == certContext_OUT)
			{
				// 查找颁发者证书
				certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
			}

			if (NULL != certContext_OUT)
			{
				DWORD  dwFlags = CERT_STORE_SIGNATURE_FLAG;

				FILE_LOG_FMT(file_log_name, "%s", "certContext_OUT");
				FILE_LOG_HEX(file_log_name, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);
				// 验证颁发者证书
				if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, uiCertLen))
				{
					ulRet=0;
				}
				else
				{
					// 验证上级证书
					ulRet = SMB_CS_VerifyCert(uiFlag, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);
					if (ulRet)
					{
						goto err;
					}
				}

				FILE_LOG_FMT(file_log_name, "%s", "certContext_IN");
				FILE_LOG_HEX(file_log_name, certContext_IN->pbCertEncoded, certContext_IN->cbCertEncoded);
				FILE_LOG_FMT(file_log_name, "%s", "certContext_OUT");
				FILE_LOG_HEX(file_log_name, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);

				if(SMB_CERT_ALG_FLAG_RSA == ulAlgType)
				{
					if (!CertVerifySubjectCertificateContext(certContext_IN, certContext_OUT, &dwFlags))
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}

					if (dwFlags)
					{
						FILE_LOG_FMT(file_log_name, "%s", "EErr_SMB_VERIFY_CERT");
						ulRet = EErr_SMB_VERIFY_CERT;
					}
				}
				else
				{
					ulRet = OpenSSL_VerifyCert(certContext_IN->pbCertEncoded, certContext_IN->cbCertEncoded, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);
					if (ulRet)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}
				}
			}
			else
			{
// 				ulRet = EErr_SMB_NO_CERT_CHAIN; // ???
// 				goto err;
				DWORD dwFlags = CERT_STORE_SIGNATURE_FLAG;
				if(SMB_CERT_ALG_FLAG_RSA == ulAlgType)
				{
					if (!CertVerifySubjectCertificateContext(certContext_IN, certContext_IN, &dwFlags))
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}

					if (dwFlags)
					{
						FILE_LOG_FMT(file_log_name, "%s", "EErr_SMB_VERIFY_CERT");
						ulRet = EErr_SMB_VERIFY_CERT;
					}
				}
				else
				{
					ulRet = OpenSSL_VerifyCert(certContext_IN->pbCertEncoded, certContext_IN->cbCertEncoded, certContext_IN->pbCertEncoded, certContext_IN->cbCertEncoded);
					if (ulRet)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}
				}
			}
		}
		//CRL
		if (SMB_CERT_VERIFY_FLAG_CRL & uiFlag)
		{
			; //
		}
#else
		ulRet = OpenSSL_VerifyCertChain(pbCert, uiCertLen);
#endif

		FILE_LOG_FMT(file_log_name, "ulRet = %d", ulRet);
		goto err;
	}




	// 创建上下文
	SMB_CS_CreateCertCtx(&ctx, pbCert, uiCertLen);

	if (!ctx)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	// TIME
	if (SMB_CERT_VERIFY_FLAG_TIME & uiFlag)
	{
		time_t time_now;
		time(&time_now);

		if (time_now > certParse.m_tNotAfter || time_now < certParse.m_tNotBefore)
		{
			ulRet = EErr_SMB_VERIFY_TIME;
			goto err;
		}
	}

	// SIGN CERT
	if (SMB_CERT_VERIFY_FLAG_CHAIN & uiFlag)
	{
		// 查找颁发者证书
		SMB_CS_CertificateFindAttr findAttr = { 0 };

		findAttr.uiFindFlag = 128;

		findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
		findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

		SMB_CS_FindCertCtx(&findAttr, &ctxHeader);

		if (NULL != ctxHeader)
		{
			// 验证颁发者证书
			if (0 == memcmp(ctxHeader->ptr_data->stContent.data, pbCert, uiCertLen))
			{
				;
			}
			else
			{
				// 验证上级证书
				ulRet = SMB_CS_VerifyCert(uiFlag, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					goto err;
				}
			}

			switch (ulAlgType)
			{
			case SMB_CERT_ALG_FLAG_RSA:
			{
				ulRet = OpenSSL_VerifyCert(pbCert, uiCertLen, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}
				break;
			}
			case SMB_CERT_ALG_FLAG_SM2:
			{
				OpenSSL_Initialize();
				ulRet = OpenSSL_VerifyCert(pbCert, uiCertLen, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}
				break;
			}
			default:
				break;
			}
		}
		else
		{
			ulRet = EErr_SMB_NO_CERT_CHAIN;
			goto err;
		}
	}
	//CRL
	if (SMB_CERT_VERIFY_FLAG_CRL & uiFlag)
	{

	}

err:

	if (NULL != ctx)
	{
		SMB_CS_FreeCertCtx(ctx);
	}

	if (NULL != ctxHeader)
	{
		SMB_CS_FreeCertCtxLink(&ctxHeader);
	}
#if defined(WIN32) || defined(WINDOWS)
	// 释放上下文
	if (certContext_OUT)
	{
		CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if (certContext_IN)
	{
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}


#if 0
COMMON_API unsigned int CALL_CONVENTION SMB_CS_VerifyCert(unsigned int uiFlag, unsigned char* pbCert, unsigned int uiCertLen)
{
	unsigned int ulRet = 0;

	unsigned int ulAlgType = 0;

	CertificateItemParse certParse;

	SMB_CS_CertificateContext *ctx = NULL;

	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;

#if defined(WIN32) || defined(WINDOWS)
	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = { 0 };
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;
#endif

	if (0 != certParse.setCertificate(pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	certParse.parse();

	ulAlgType = certParse.m_iKeyAlg;

	if (SMB_CERT_ALG_FLAG_RSA == ulAlgType)
	{
#if defined(WIN32) || defined(WINDOWS)
		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}
		// TIME
		if (SMB_CERT_VERIFY_FLAG_TIME & uiFlag)
		{
			ulRet = CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
			if (ulRet)
			{
				ulRet = EErr_SMB_VERIFY_TIME;
				goto err;
			}
		}
		// SIGN CERT
		if (SMB_CERT_VERIFY_FLAG_CHAIN & uiFlag)
		{
			// 打开存储区		
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
				// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
				// registry location
				L"Ca"                            // The store name as a Unicode 
				// string
				);

			if (NULL == hCertStore)
			{
				ulRet = EErr_SMB_OPEN_STORE;
				goto err;
			}

			// 查找颁发者证书
			// certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
			{
				CERT_ID id;

				unsigned char data_value_keyid[1024] = { 0 };
				unsigned int data_len_keyid = 1024;

				id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;

				GetExtAuthorityIdentifier(certContext_IN, data_value_keyid, &data_len_keyid);

				id.KeyId.pbData = data_value_keyid;
				id.KeyId.cbData = data_len_keyid;

				certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL);
			}

			if (NULL == certContext_OUT)
			{
				if (hCertStore)
				{
					// 关闭存储区
					CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
				}

				// 打开存储区		
				hCertStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM,          // The store provider type
					0,                               // The encoding type is
					// not needed
					NULL,                            // Use the default HCRYPTPROV
					CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
					// registry location
					L"Root"                            // The store name as a Unicode 
					// string
					);

				if (NULL == hCertStore)
				{
					ulRet = EErr_SMB_OPEN_STORE;
					goto err;
				}

				// 查找颁发者证书
				// certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
				{
					CERT_ID id;

					unsigned char data_value_keyid[1024] = { 0 };
					unsigned int data_len_keyid = 1024;

					id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;

					GetExtAuthorityIdentifier(certContext_IN, data_value_keyid, &data_len_keyid);

					id.KeyId.pbData = data_value_keyid;
					id.KeyId.cbData = data_len_keyid;

					certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL);
				}
			}

			if (NULL != certContext_OUT)
			{
				DWORD  dwFlags = CERT_STORE_SIGNATURE_FLAG;

				// 验证颁发者证书
				if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, uiCertLen))
				{

				}
				else
				{
					// 验证上级证书
					ulRet = SMB_CS_VerifyCert(uiFlag, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);
					if (ulRet)
					{
						goto err;
					}
				}

				if (!CertVerifySubjectCertificateContext(certContext_IN, certContext_OUT, &dwFlags))
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}

				if (dwFlags)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
				}
			}
			else
			{
				ulRet = EErr_SMB_NO_CERT_CHAIN;
				goto err;
			}
		}
		//CRL
		if (SMB_CERT_VERIFY_FLAG_CRL & uiFlag)
		{

		}
#else
		ulRet = OpenSSL_VerifyCertChain(pbCert, uiCertLen);
#endif
		goto err;
	}


	// 创建上下文 
	SMB_CS_CreateCertCtx(&ctx, pbCert, uiCertLen);

	if (!ctx)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}
	// TIME
	if (SMB_CERT_VERIFY_FLAG_TIME & uiFlag)
	{
		time_t time_now;
		time(&time_now);

		if (time_now > certParse.m_tNotAfter || time_now < certParse.m_tNotBefore)
		{
			ulRet = EErr_SMB_VERIFY_TIME;
			goto err;
		}
	}
	// SIGN CERT
	if (SMB_CERT_VERIFY_FLAG_CHAIN & uiFlag)
	{
		// 查找颁发者证书
		SMB_CS_CertificateFindAttr findAttr = { 0 };

		findAttr.uiFindFlag = 128;

		findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
		findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

		SMB_CS_FindCertCtx(&findAttr, &ctxHeader);

		if (NULL != ctxHeader)
		{
			// 验证颁发者证书
			if (0 == memcmp(ctxHeader->ptr_data->stContent.data, pbCert, uiCertLen))
			{

			}
			else
			{
				// 验证上级证书
				ulRet = SMB_CS_VerifyCert(uiFlag, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					goto err;
				}
			}
			switch (ulAlgType)
			{
			case SMB_CERT_ALG_FLAG_RSA:
				{
					ulRet = OpenSSL_VerifyCert(pbCert, uiCertLen, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
					if (ulRet)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}
					break;
				}
			case SMB_CERT_ALG_FLAG_SM2:
				{
					OpenSSL_Initialize();

					ulRet = OpenSSL_VerifyCert(pbCert, uiCertLen, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
					if (ulRet)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}
					break;
				}
			default:
				break;
			}
		}
		else
		{
			ulRet = EErr_SMB_NO_CERT_CHAIN;
			goto err;
		}
	}
	//CRL
	if (SMB_CERT_VERIFY_FLAG_CRL & uiFlag)
	{

	}
err:

	if (NULL != ctx)
	{
		SMB_CS_FreeCertCtx(ctx);
	}

	if (NULL != ctxHeader)
	{
		SMB_CS_FreeCertCtxLink(&ctxHeader);
	}
#if defined(WIN32) || defined(WINDOWS)
	// 释放上下文
	if (certContext_OUT)
	{
		CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if (certContext_IN)
	{
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}

#endif


COMMON_API unsigned int CALL_CONVENTION SMB_CS_EnumCertCtx(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned char ucStoreType)
{
	SMB_CS_CertificateFindAttr findAttr;
	if (0 == ucStoreType)
	{
		findAttr.ucStoreType = 0;
		findAttr.uiFindFlag = 0;
	}
	else
	{
		findAttr.ucStoreType = ucStoreType;

		findAttr.uiFindFlag = 4;
	}


	return SMB_CS_FindCertCtx(&findAttr, ppCertCtxNodeHeader);
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_DelCertCtxLink(SMB_CS_CertificateContext_NODE *pCertCtxNodeHeader)
{
	while (pCertCtxNodeHeader)
	{
		SMB_CS_DelCertCtx(pCertCtxNodeHeader->ptr_data);
		pCertCtxNodeHeader = pCertCtxNodeHeader->ptr_next;
	}

	return 0;
}

int sdb_AddCertCtx(SDB *sdb, SMB_CS_CertificateContext *pCertCtx, unsigned char ucStoreType)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;
	int id_attr = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "INSERT INTO "
		"table_certificate_attr(cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after) "
		"VALUES($cert_alg_type, $cert_usage_type, $skf_name, $device_name, $application_name, $container_name, $common_name, $subject, $isuue, $public_key, $serial_number, $subject_keyid, $isuue_keyid, $vendor_data, $verify, $not_before, $not_after);", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	// $cert_alg_type, 
	sqlerr = sqlite3_bind_int(stmt, 1, pCertCtx->stAttr.ucCertAlgType);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$cert_usage_type, 
	sqlerr = sqlite3_bind_int(stmt, 2, pCertCtx->stAttr.ucCertUsageType);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$skf_name, 
	sqlerr = sqlite3_bind_blob(stmt, 3, pCertCtx->stAttr.stSKFName.data,
		pCertCtx->stAttr.stSKFName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$device_name, 
	sqlerr = sqlite3_bind_blob(stmt, 4, pCertCtx->stAttr.stDeviceName.data,
		pCertCtx->stAttr.stDeviceName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$application_name, 
	sqlerr = sqlite3_bind_blob(stmt, 5, pCertCtx->stAttr.stApplicationName.data,
		pCertCtx->stAttr.stApplicationName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$container_name, 
	sqlerr = sqlite3_bind_blob(stmt, 6, pCertCtx->stAttr.stContainerName.data,
		pCertCtx->stAttr.stContainerName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$common_name, 
	sqlerr = sqlite3_bind_blob(stmt, 7, pCertCtx->stAttr.stCommonName.data,
		pCertCtx->stAttr.stCommonName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$subject, 
	sqlerr = sqlite3_bind_blob(stmt, 8, pCertCtx->stAttr.stSubject.data,
		pCertCtx->stAttr.stSubject.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$isuue, 
	sqlerr = sqlite3_bind_blob(stmt, 9, pCertCtx->stAttr.stIssue.data,
		pCertCtx->stAttr.stIssue.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$public_key, 
	sqlerr = sqlite3_bind_blob(stmt, 10, pCertCtx->stAttr.stPublicKey.data,
		pCertCtx->stAttr.stPublicKey.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$serial_number, 
	sqlerr = sqlite3_bind_blob(stmt, 11, pCertCtx->stAttr.stSerialNumber.data,
		pCertCtx->stAttr.stSerialNumber.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$subject_keyid, 
	sqlerr = sqlite3_bind_blob(stmt, 12, pCertCtx->stAttr.stSubjectKeyID.data,
		pCertCtx->stAttr.stSubjectKeyID.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$isuue_keyid, 
	sqlerr = sqlite3_bind_blob(stmt, 13, pCertCtx->stAttr.stIssueKeyID.data,
		pCertCtx->stAttr.stIssueKeyID.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$vendor_data,
	sqlerr = sqlite3_bind_blob(stmt, 14, pCertCtx->stAttr.stVendorData.data,
		pCertCtx->stAttr.stVendorData.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$verify, 
	sqlerr = sqlite3_bind_int64(stmt, 15, pCertCtx->stAttr.ulVerify);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$not_before, 
	sqlerr = sqlite3_bind_int64(stmt, 16, pCertCtx->stAttr.ulNotBefore);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$not_after
	sqlerr = sqlite3_bind_int64(stmt, 17, pCertCtx->stAttr.ulNotAfter);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select max(id) from table_certificate_attr;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			id_attr = sqlite3_column_int(stmt, 0);
		}

	} while (!sdb_done(sqlerr, &retry));
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "INSERT INTO "
		"table_certificate (content, store_type, id_attr) "
		"values ($content, $store_type, $id_attr);", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$content
	sqlerr = sqlite3_bind_blob(stmt, 1, pCertCtx->stContent.data, pCertCtx->stContent.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$store_type
	sqlerr = sqlite3_bind_int(stmt, 2, ucStoreType);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$id_attr
	sqlerr = sqlite3_bind_int(stmt, 3, id_attr);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_AddCertCtx(SMB_CS_CertificateContext *pCertCtx, unsigned char ucStoreType)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	SMB_CS_CertificateContext *pCertCtxTmp = NULL;

	SMB_CS_GetCertCtxByCert(&pCertCtxTmp, pCertCtx->stContent.data, pCertCtx->stContent.length);

	if (pCertCtxTmp)
	{
		SMB_CS_FreeCertCtx(pCertCtxTmp);
		pCertCtxTmp = NULL;

		return 0;
	}


	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 1);
	if (crv)
	{
		goto err;
	}

	crv = sdb_AddCertCtx(&sdb, pCertCtx, ucStoreType);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 1);
	}
	else
	{
		sdb_Commit(&sdb, 1);
	}

	return crv;
}

int sdb_DelCertCtx(SDB *sdb, SMB_CS_CertificateContext *pCertCtx)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;
	char data_value[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len = BUFFER_LEN_1K;

	LOCK_SQLITE();

	sprintf(data_value, "delete from table_certificate_attr where id=%d", g_mapPtr2IDs[&pCertCtx->stAttr]);
	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, data_value, -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sprintf(data_value, "delete from table_certificate where id=%d", g_mapPtr2IDs[&pCertCtx->stContent]);
	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, data_value, -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_DelCertCtx(SMB_CS_CertificateContext *pCertCtx)
{
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 1);
	if (crv)
	{
		goto err;
	}

	crv = sdb_DelCertCtx(&sdb, pCertCtx);
	if (crv)
	{
		goto err;
	}
err:

	if (crv)
	{
		sdb_Abort(&sdb, 1);
	}
	else
	{
		sdb_Commit(&sdb, 1);
	}

	return crv;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_ClrAllCertCtx(unsigned char ucStoreType)
{
	SMB_CS_CertificateContext_NODE *header = NULL;

	if (ucStoreType > 0)
	{
		SMB_CS_EnumCertCtx(&header, ucStoreType);

		SMB_CS_DelCertCtxLink(header);

		SMB_CS_FreeCertCtxLink(&header);
	}
	else
	{
		for (int i = 0; i < 4; i++)
		{
			SMB_CS_EnumCertCtx(&header, i + 1);

			SMB_CS_DelCertCtxLink(header);

			SMB_CS_FreeCertCtxLink(&header);
		}
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_SetPath(char *pDbPath)
{
	if (NULL == pDbPath)
	{
		char data_value_zero[BUFFER_LEN_1K] = { 0 };
		char smb_db_path_prefix[BUFFER_LEN_1K] = { 0 };

		int i = 0;

		if (0 == memcmp(data_value_zero, smb_db_path, sizeof(data_value_zero)))
		{
#if defined(WIN32) || defined(WINDOWS)
			//无权限
			GetModuleFileNameA(NULL, smb_db_path_prefix, 1024);
			for (i = strlen(smb_db_path_prefix); i > 0; i--)
			{
				if ('\\' == smb_db_path_prefix[i])
				{
					break;
				}
			}

			GetEnvironmentVariableA("APPDATA", smb_db_path, MAX_PATH);
			strcat(smb_db_path, &smb_db_path_prefix[i]);

			for (i = strlen(smb_db_path); i > 0; i--)
			{
				if ('.' == smb_db_path[i])
				{
					smb_db_path[i] = 0;
					break;
				}
			}

			strcat(smb_db_path, ".smb_cs.db");

			//strcpy(smb_db_path + strlen(smb_db_path), "smb_cs.db");
#else
			strcpy(smb_db_path, "/home/smb_cs.db");
#endif
		}
	}
	else
	{
		strcpy(smb_db_path, pDbPath);
	}

	return 0;
}



COMMON_API unsigned int CALL_CONVENTION SMB_CS_ImportCaCert(unsigned char *pbCert, unsigned int uiCertLen, unsigned int *pulAlgType)
{
	unsigned int ulRet = 0;

	SMB_CS_CertificateContext * ctx = NULL;

#if defined(WIN32) || defined(WINDOWS)
	PCCERT_CONTEXT certContext_IN = NULL;
	HCERTSTORE hCertStore = NULL;
#endif

	SMB_CS_Init();

	if (0 != SMB_CS_CreateCertCtx(&ctx, pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}
#if defined(WIN32) || defined(WINDOWS)
	if (SMB_CERT_ALG_FLAG_RSA == ctx->stAttr.ucCertAlgType)
	{
		if (0 == memcmp(ctx->stAttr.stIssueKeyID.data, ctx->stAttr.stSubjectKeyID.data, ctx->stAttr.stSubjectKeyID.length > ctx->stAttr.stIssueKeyID.length ? ctx->stAttr.stSubjectKeyID.length : ctx->stAttr.stIssueKeyID.length))
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
													// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													// registry location
				L"Root"                            // The store name as a Unicode 
													// string
			);
		}
		else
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
													// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													// registry location
				L"Ca"                            // The store name as a Unicode 
													// string
			);
		}

		if (NULL == hCertStore)
		{
			ulRet = EErr_SMB_OPEN_STORE;
			goto err;
		}

		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE *)pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}

		if (!CertAddCertificateContextToStore(hCertStore, certContext_IN, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
		{
			if (0x80070005 == GetLastError())
			{
				ulRet = EErr_SMB_NO_RIGHT;
			}
			else
			{
				ulRet = EErr_SMB_ADD_CERT_TO_STORE;
			}

			goto err;
		}
		else
		{
			ulRet = EErr_SMB_OK; // success
		}
	}
	else
	{
		if (0 != SMB_CS_AddCertCtx(ctx, 1))
		{
			ulRet = EErr_SMB_ADD_CERT_TO_STORE;
			goto err;
		}
	}
#else
	if (0 != SMB_CS_AddCertCtx(ctx, 1))
	{
		ulRet = EErr_SMB_ADD_CERT_TO_STORE;
		goto err;
	}
#endif

	ulRet = EErr_SMB_OK; // success

err:
	if (ctx)
	{
		SMB_CS_FreeCertCtx(ctx);
	}
#if defined(WIN32) || defined(WINDOWS)
	if (certContext_IN)
	{
		// 释放上下文
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}


int sdb_ExecSQL(SDB *sdb, char *pSqlData, unsigned int uiSqlDataLen)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int pos = 0;
	char data_value[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len_real = 0;
	char * ptr_n = NULL;
	char * ptr_r = NULL;
	char * ptr_semicolon = NULL;

	LOCK_SQLITE();

	for (pos = 0; pos < uiSqlDataLen;)
	{
		while (pSqlData[pos] == '#' || pSqlData[pos] == '\r' || pSqlData[pos] == '\n')
		{
			ptr_n = strstr(&pSqlData[pos], "\n");
			ptr_r = strstr(&pSqlData[pos], "\r");
			if (NULL == ptr_n && NULL == ptr_r)
			{
				pos = uiSqlDataLen;
				break;
			}
			else if (NULL == ptr_n)
			{
				pos = ptr_r - pSqlData + 1;
			}
			else if (NULL == ptr_r)
			{
				pos = ptr_n - pSqlData + 1;
			}
			else
			{
				if (ptr_n > ptr_r)
				{
					pos = ptr_r - pSqlData + 1;
				}
				else
				{
					pos = ptr_n - pSqlData + 1;
				}
			}

			while (pSqlData[pos] == '\r' || pSqlData[pos] == '\n')
			{
				pos += 1;
			}
		}

		if (pos > uiSqlDataLen || pos == uiSqlDataLen)
		{
			break;
		}
		char * pp = &pSqlData[pos];
		sqlerr = sqlite3_prepare_v2(sdb->sdb_p, &pSqlData[pos], -1, &stmt, NULL);
		if (sqlerr != SQLITE_OK)
		{
			goto err;
		}

		do {
			sqlerr = sqlite3_step(stmt);

			if (sqlerr == SQLITE_BUSY) {
				sqlite3_sleep(SDB_BUSY_RETRY_TIME);
			}

			if (sqlerr == SQLITE_DONE)
			{
				sqlerr = SQLITE_OK;
			}

			if (sqlerr == SQLITE_ROW)
			{
				// null;
			}

		} while (!sdb_done(sqlerr, &retry));

		if (sqlerr == SQLITE_ROW)
		{
			sqlerr = SQLITE_OK;
		}

		if (stmt) {
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			stmt = NULL;
		}

		if (sqlerr)
		{
			goto err;
		}

		// next line
		ptr_semicolon = strstr(&pSqlData[pos], ";");

		if (NULL == ptr_semicolon)
		{
			pos = uiSqlDataLen;
			break;
		}
		else
		{
			pos = ptr_semicolon - pSqlData + 1;
		}
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_ExecSQL(char *pSqlData, unsigned int uiSqlDataLen)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 1);
	if (crv)
	{
		goto err;
	}

	crv = sdb_ExecSQL(&sdb, pSqlData, uiSqlDataLen);
	if (crv)
	{
		goto err;
	}

err:
	if (crv)
	{
		sdb_Abort(&sdb, 1);
	}
	else
	{
		sdb_Commit(&sdb, 1);
	}

	return crv;
}


COMMON_API unsigned int CALL_CONVENTION SMB_CS_FindCertChain(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned char *pbCert, unsigned int uiCertLen)
{
	unsigned int ulRet = 0;

	SMB_CS_CertificateContext *ctx = NULL;
	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;
	SMB_CS_CertificateContext_NODE * lastHeader = NULL;
	CertificateItemParse certParse;
	SMB_CS_CertificateFindAttr findAttr = { 0 };

	if (0 != SMB_CS_CreateCertCtx(&ctx, pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	if (!ctx)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	if (0 != certParse.setCertificate(pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	certParse.parse();

	findAttr.uiFindFlag = 128;
	findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
	findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

	SMB_CS_FindCertCtx(&findAttr, &ctxHeader);

	for (lastHeader = ctxHeader; ctxHeader != NULL; lastHeader = ctxHeader)
	{
		if (0 != certParse.setCertificate(ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length))
		{
			ulRet = EErr_SMB_INVALID_ARG;
			goto err;
		}

		certParse.parse();

		if (0 == strcmp(certParse.m_strIssueKeyID.c_str(), certParse.m_strSubjectKeyID.c_str()))
		{
			ulRet = EErr_SMB_OK; // success
			break;
		}

		findAttr.uiFindFlag = 128;
		findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
		findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

		SMB_CS_FindCertCtx(&findAttr, &ctxHeader);

		if (lastHeader == ctxHeader)
		{
			break;
		}
	}

err:
	if (ctx)
	{
		SMB_CS_FreeCertCtx(ctx);
	}

	*ppCertCtxNodeHeader = ctxHeader;

	return ulRet;
}


int sdb_FillCSP(SMB_CS_CSP **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_CSP *pPtr = (SMB_CS_CSP *)malloc(sizeof(SMB_CS_CSP));

	memset(pPtr, 0, sizeof(SMB_CS_CSP));


	//id , name , value

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stName.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stName.data = (unsigned char *)malloc(pPtr->stName.length);
	memcpy(pPtr->stName.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stName.length);

	pos += 1;
	pPtr->stValue.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stValue.data = (unsigned char *)malloc(pPtr->stValue.length);
	memcpy(pPtr->stValue.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stValue.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumCSP(SDB *sdb, SMB_CS_CSP_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_csp;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_CSP *pPtr = NULL;

			sdb_FillCSP(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_EnumCSP(SMB_CS_CSP_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 0);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumCSP(&sdb, ppNodeHeader);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 0);
	}
	else
	{
		sdb_Commit(&sdb, 0);
	}

	return crv;
}


int sdb_FillPIDVID(SMB_CS_PIDVID **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_PIDVID *pPtr = (SMB_CS_PIDVID *)malloc(sizeof(SMB_CS_PIDVID));

	memset(pPtr, 0, sizeof(SMB_CS_PIDVID));


	//id , pid, vid, type

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stPID.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPID.data = (unsigned char *)malloc(pPtr->stPID.length);
	memcpy(pPtr->stPID.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPID.length);

	pos += 1;
	pPtr->stVID.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stVID.data = (unsigned char *)malloc(pPtr->stVID.length);
	memcpy(pPtr->stVID.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stVID.length);

	pos += 1;
	pPtr->stType.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stType.data = (unsigned char *)malloc(pPtr->stType.length);
	memcpy(pPtr->stType.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stType.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumPIDVID(SDB *sdb, SMB_CS_PIDVID_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_pid_vid;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_PIDVID *pPtr = NULL;

			sdb_FillPIDVID(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_EnumPIDVID(SMB_CS_PIDVID_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 0);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumPIDVID(&sdb, ppNodeHeader);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 0);
	}
	else
	{
		sdb_Commit(&sdb, 0);
	}

	return crv;
}


int sdb_FillFileInfo(SMB_CS_FileInfo **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_FileInfo *pPtr = (SMB_CS_FileInfo *)malloc(sizeof(SMB_CS_FileInfo));

	memset(pPtr, 0, sizeof(SMB_CS_FileInfo));


	//id , name, value, digest_md5, digest_sha1

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stName.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stName.data = (unsigned char *)malloc(pPtr->stName.length);
	memcpy(pPtr->stName.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stName.length);

	pos += 1;
	pPtr->stPath.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPath.data = (unsigned char *)malloc(pPtr->stPath.length);
	memcpy(pPtr->stPath.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPath.length);

	pos += 1;
	pPtr->stDigestMD5.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stDigestMD5.data = (unsigned char *)malloc(pPtr->stDigestMD5.length);
	memcpy(pPtr->stDigestMD5.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stDigestMD5.length);

	pos += 1;
	pPtr->stDigestSHA1.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stDigestSHA1.data = (unsigned char *)malloc(pPtr->stDigestSHA1.length);
	memcpy(pPtr->stDigestSHA1.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stDigestSHA1.length);

	pos += 1;
	pPtr->stFileType.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stFileType.data = (unsigned char *)malloc(pPtr->stFileType.length);
	memcpy(pPtr->stFileType.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stFileType.length);

	pos += 1;
	pPtr->stCategory.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stCategory.data = (unsigned char *)malloc(pPtr->stCategory.length);
	memcpy(pPtr->stCategory.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stCategory.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumFileInfo(SDB *sdb, SMB_CS_FileInfo_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_fileinfo;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_FileInfo *pPtr = NULL;

			sdb_FillFileInfo(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_EnumFileInfo(SMB_CS_FileInfo_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 0);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumFileInfo(&sdb, ppNodeHeader);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 0);
	}
	else
	{
		sdb_Commit(&sdb, 0);
	}

	return crv;
}


int sdb_FillSKF(SMB_CS_SKF **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_SKF *pPtr = (SMB_CS_SKF *)malloc(sizeof(SMB_CS_SKF));

	memset(pPtr, 0, sizeof(SMB_CS_SKF));

	//id , name, path, signtype

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stName.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stName.data = (unsigned char *)malloc(pPtr->stName.length);
	memcpy(pPtr->stName.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stName.length);

	pos += 1;
	pPtr->stPath.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPath.data = (unsigned char *)malloc(pPtr->stPath.length);
	memcpy(pPtr->stPath.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPath.length);

	pos += 1;
	pPtr->stSignType.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stSignType.data = (unsigned char *)malloc(pPtr->stSignType.length);
	memcpy(pPtr->stSignType.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stSignType.length);

	pos += 1;
	pPtr->stPinVerify.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPinVerify.data = (unsigned char *)malloc(pPtr->stPinVerify.length);
	memcpy(pPtr->stPinVerify.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPinVerify.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumSKF(SDB *sdb, SMB_CS_SKF_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_skf;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_SKF *pPtr = NULL;

			sdb_FillSKF(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_EnumSKF(SMB_CS_SKF_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb, 0);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumSKF(&sdb, ppNodeHeader);
	if (crv)
	{
		goto err;
	}

err:

	if (crv)
	{
		sdb_Abort(&sdb, 0);
	}
	else
	{
		sdb_Commit(&sdb, 0);
	}

	return crv;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeCSPLink(SMB_CS_CSP_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreeCSP((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeSKFLink(SMB_CS_SKF_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreeSKF((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreePIDVIDLink(SMB_CS_PIDVID_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreePIDVID((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeFileInfoLink(SMB_CS_FileInfo_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreeFileInfo((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeFileInfo(SMB_CS_FileInfo *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stDigestMD5.data)
		{
			free(pPtr->stDigestMD5.data);
			pPtr->stDigestMD5.data = NULL;
		}

		if (pPtr->stDigestSHA1.data)
		{
			free(pPtr->stDigestSHA1.data);
			pPtr->stDigestSHA1.data = NULL;
		}

		if (pPtr->stName.data)
		{
			free(pPtr->stName.data);
			pPtr->stName.data = NULL;
		}

		if (pPtr->stPath.data)
		{
			free(pPtr->stPath.data);
			pPtr->stPath.data = NULL;
		}

		if (pPtr->stFileType.data)
		{
			free(pPtr->stFileType.data);
			pPtr->stFileType.data = NULL;
		}

		if (pPtr->stCategory.data)
		{
			free(pPtr->stCategory.data);
			pPtr->stCategory.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeCSP(SMB_CS_CSP *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stName.data)
		{
			free(pPtr->stName.data);
			pPtr->stName.data = NULL;
		}

		if (pPtr->stValue.data)
		{
			free(pPtr->stValue.data);
			pPtr->stValue.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreeSKF(SMB_CS_SKF *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stName.data)
		{
			free(pPtr->stName.data);
			pPtr->stName.data = NULL;
		}

		if (pPtr->stPath.data)
		{
			free(pPtr->stPath.data);
			pPtr->stPath.data = NULL;
		}

		if (pPtr->stSignType.data)
		{
			free(pPtr->stSignType.data);
			pPtr->stSignType.data = NULL;
		}

		if (pPtr->stPinVerify.data)
		{
			free(pPtr->stPinVerify.data);
			pPtr->stPinVerify.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_FreePIDVID(SMB_CS_PIDVID *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stPID.data)
		{
			free(pPtr->stPID.data);
			pPtr->stPID.data = NULL;
		}

		if (pPtr->stVID.data)
		{
			free(pPtr->stVID.data);
			pPtr->stVID.data = NULL;
		}

		if (pPtr->stType.data)
		{
			free(pPtr->stType.data);
			pPtr->stType.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

#include "encode_switch.h"

COMMON_API unsigned int CALL_CONVENTION SMB_CS_CheckRootCertExist(wchar_t * pKeyIDHex, unsigned int ulAlgType)
{
	unsigned int ulRet = 0;
	unsigned int ulOutLen = 0;
#if defined(WIN32) || defined(WINDOWS)
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_CA = NULL;
#endif
	
	unsigned char data_value_keyid[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len_keyid = BUFFER_LEN_1K;

	CERT_ID id;

	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;

	switch (ulAlgType)
	{
	case SMB_CERT_ALG_FLAG_RSA:
#if defined(WIN32) || defined(WINDOWS)
	{

		id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
		OPF_Str2Bin(utf8_encode(pKeyIDHex).c_str(), utf8_encode(pKeyIDHex).size(), data_value_keyid, &data_len_keyid);
		id.KeyId.pbData = data_value_keyid;
		id.KeyId.cbData = data_len_keyid;
	
		hCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,          // The store provider type
			0,                               // The encoding type is
												// not needed
			NULL,                            // Use the default HCRYPTPROV
			CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
												// registry location
			L"Root"                            // The store name as a Unicode 
												// string
		);

		if (NULL == hCertStore)
		{
			ulRet = EErr_SMB_OPEN_STORE;
			goto err;
		}

		certContext_CA = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL);

		if (NULL == certContext_CA)
		{
			ulRet = EErr_SMB_NO_CERT_CHAIN;
			goto err;
		}
	}
	break;
#endif
	case SMB_CERT_ALG_FLAG_SM2:
	{
		// 查找颁发者证书
		SMB_CS_CertificateFindAttr findAttr = { 0 };

		findAttr.uiFindFlag = 128;

		findAttr.stSubjectKeyID.data = (unsigned char *)utf8_encode(pKeyIDHex).c_str();
		findAttr.stSubjectKeyID.length = utf8_encode(pKeyIDHex).size();

		SMB_CS_FindCertCtx(&findAttr, &ctxHeader);

		if (NULL == ctxHeader)
		{
			ulRet = EErr_SMB_NO_CERT_CHAIN;
			goto err;
		}
	}
	break;
	default:
		break;
	}

err:
#if defined(WIN32) || defined(WINDOWS)
	// 释放上下文
	if (certContext_CA)
	{
		CertFreeCertificateContext(certContext_CA);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	if (NULL != ctxHeader)
	{
		SMB_CS_FreeCertCtxLink(&ctxHeader);
	}

	return ulRet;
}

#include <iostream>
#include <fstream>
#include <string>
#include <io.h>

COMMON_API unsigned int CALL_CONVENTION SMB_CS_ImportCaCertRSA(unsigned char *pbCert, unsigned int uiCertLen, unsigned int *pulAlgType)
{
	unsigned int ulRet = 0;

	SMB_CS_CertificateContext * ctx = NULL;

#if defined(WIN32) || defined(WINDOWS)
	PCCERT_CONTEXT certContext_IN = NULL;
	HCERTSTORE hCertStore = NULL;
#endif

	if (0 != SMB_CS_CreateCertCtx(&ctx, pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	if (SMB_CERT_ALG_FLAG_RSA == ctx->stAttr.ucCertAlgType)
	{
		if (0 == memcmp(ctx->stAttr.stIssueKeyID.data, ctx->stAttr.stSubjectKeyID.data, ctx->stAttr.stSubjectKeyID.length > ctx->stAttr.stIssueKeyID.length ? ctx->stAttr.stSubjectKeyID.length : ctx->stAttr.stIssueKeyID.length))
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
												 // not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
												 // registry location
				L"Root"                            // The store name as a Unicode 
												   // string
			);
		}
		else
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
												 // not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
												 // registry location
				L"Ca"                            // The store name as a Unicode 
												 // string
			);
		}

		if (NULL == hCertStore)
		{
			ulRet = EErr_SMB_OPEN_STORE;
			goto err;
		}

		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE *)pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}

		if (!CertAddCertificateContextToStore(hCertStore, certContext_IN, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
		{
			if (0x80070005 == GetLastError())
			{
				ulRet = EErr_SMB_NO_RIGHT;
			}
			else
			{
				ulRet = EErr_SMB_ADD_CERT_TO_STORE;
			}

			goto err;
		}
		else
		{
			ulRet = EErr_SMB_OK; // success
		}
	}
	else
	{

	}

	ulRet = EErr_SMB_OK; // success

err:
	if (ctx)
	{
		SMB_CS_FreeCertCtx(ctx);
	}
#if defined(WIN32) || defined(WINDOWS)
	if (certContext_IN)
	{
		// 释放上下文
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_CS_ImportCaCertFile(wchar_t * pCertFile, OUT unsigned int *pulAlgType)
{
	std::fstream _file;

	_file.open(pCertFile, std::ios::binary | std::ios::in);

	if (_file)
	{
		std::ios::pos_type length;
		unsigned int ulAlgType = 0;
		unsigned char pbCaCert[1024 * 4] = { 0 };

		// get length of file:
		_file.seekg(0, std::ios::end);
		length = _file.tellg();
		_file.seekg(0, std::ios::beg);

		// read data as a block:
		_file.read((char *)pbCaCert, length>sizeof(pbCaCert) ? sizeof(pbCaCert) : length);
		_file.close();

		SMB_CS_ImportCaCertRSA(pbCaCert, length>sizeof(pbCaCert) ? sizeof(pbCaCert) : length, &ulAlgType);
	}
	else
	{

	}

	return 0;
}
