#include "logger.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

static char m_log_path[QSC_SYSTEM_MAX_PATH] = { 0 };
static qsc_mutex m_log_mutex = NULL;

static void logger_default_path(char* path, size_t pathlen)
{
	bool res;

	if (path != NULL && pathlen != 0U)
	{
		qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
		qsc_folderutils_append_delimiter(path);
		qsc_stringutils_concat_strings(path, pathlen, DKTP_LOGGER_PATH);
		res = qsc_folderutils_directory_exists(path);

		if (res == false)
		{
			res = qsc_folderutils_create_directory(path);
		}

		if (res == true)
		{
			qsc_folderutils_append_delimiter(path);
			qsc_stringutils_concat_strings(path, pathlen, DKTP_LOGGER_FILE);
		}
	}
}

void dktp_logger_dispose(void)
{
	if (m_log_mutex != NULL)
	{
		qsc_async_mutex_destroy(m_log_mutex);
		m_log_mutex = NULL;
	}

	qsc_memutils_clear(m_log_path, sizeof(m_log_path));
}

void dktp_logger_initialize(const char* path)
{
	qsc_memutils_clear(m_log_path, QSC_SYSTEM_MAX_PATH);
	m_log_mutex = qsc_async_mutex_create();

	if (path != NULL && qsc_fileutils_valid_path(path) == true)
	{
		size_t plen = qsc_stringutils_string_size(path);

		if ((plen + 1U) <= QSC_SYSTEM_MAX_PATH)
		{
			qsc_memutils_copy(m_log_path, path, plen);
		}
	}

	if (qsc_stringutils_string_size(m_log_path) == 0U)
	{
		logger_default_path(m_log_path, QSC_SYSTEM_MAX_PATH);
	}

	if (dktp_logger_exists() == false)
	{
		dktp_logger_reset();
	}
}

bool dktp_logger_exists(void)
{
	bool res;

	res = qsc_fileutils_valid_path(m_log_path);

	if (res == true)
	{
		res = qsc_fileutils_exists(m_log_path);
	}

	return res;
}

void dktp_logger_print(void)
{
	char buf[DKTP_LOGGING_MESSAGE_MAX + 1U] = { 0 };
	size_t lctr;
	size_t mlen;

	lctr = 0U;

	if (dktp_logger_exists() == true)
	{
		do
		{
			mlen = qsc_fileutils_read_line(m_log_path, buf, sizeof(buf) - 1U, lctr);
			++lctr;

			if (mlen > 0U)
			{
				qsc_consoleutils_print_line(buf);
				qsc_memutils_clear(buf, mlen);
			}
		} 
		while (mlen > 0U);
	}
}

void dktp_logger_read(char* output, size_t otplen)
{
	DKTP_ASSERT(output != NULL);

	if (output != NULL)
	{
		if (dktp_logger_exists() == true)
		{
			qsc_async_mutex_lock(m_log_mutex);
			qsc_fileutils_safe_read(m_log_path, 0U, output, otplen);
			qsc_async_mutex_unlock(m_log_mutex);
		}
	}
}

void dktp_logger_reset(void)
{
	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char msg[DKTP_LOGGING_MESSAGE_MAX] = "Created: ";
	size_t mlen;

	qsc_async_mutex_lock(m_log_mutex);

	if (dktp_logger_exists() == true)
	{
		qsc_fileutils_erase(m_log_path);
	}
	else
	{
		qsc_fileutils_create(m_log_path);
	}

	qsc_fileutils_write_line(m_log_path, DKTP_LOGGER_HEAD, sizeof(DKTP_LOGGER_HEAD) - 1U);
	qsc_timestamp_current_datetime(dtm);
	mlen = qsc_stringutils_concat_strings(msg, sizeof(msg), dtm);
	qsc_fileutils_write_line(m_log_path, msg, mlen);

	qsc_async_mutex_unlock(m_log_mutex);
}

size_t dktp_logger_size(void)
{
	size_t res;

	res = 0U;

	if (dktp_logger_exists() == true)
	{
		res = qsc_fileutils_get_size(m_log_path);
	}

	return res;
}

bool dktp_logger_write(const char* message)
{
	DKTP_ASSERT(message != NULL);

	char buf[DKTP_LOGGING_MESSAGE_MAX + QSC_TIMESTAMP_STRING_SIZE + 4U] = { 0 };
	char dlm[4U] = " : ";
	size_t blen;
	size_t mlen;
	bool res;

	res = false;

	if (message != NULL)
	{
		res = dktp_logger_exists();
		mlen = qsc_stringutils_string_size(message);

		if (res == true && mlen <= DKTP_LOGGING_MESSAGE_MAX && mlen > 0U)
		{
			qsc_timestamp_current_datetime(buf);
			qsc_stringutils_concat_strings(buf, sizeof(buf), dlm);
			blen = qsc_stringutils_concat_strings(buf, sizeof(buf), message);

			qsc_async_mutex_lock(m_log_mutex);
			res = qsc_fileutils_write_line(m_log_path, buf, blen);
			qsc_async_mutex_unlock(m_log_mutex);
		}
	}

	return res;
}
