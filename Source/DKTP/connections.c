#include "connections.h"
#include "async.h"
#include "memutils.h"

static qsc_mutex m_pool_mutex;

/** \cond */
typedef struct dktp_connection_set
{
	dktp_connection_state* conset;
	bool* active;
	size_t count;
} dktp_connection_set;

static dktp_connection_set m_connection_set;
/** \endcond */

bool dktp_connections_active(size_t index)
{
	bool res;

	res = false;

	qsc_async_mutex_lock(m_pool_mutex);

	if (index < m_connection_set.count)
	{
		res = m_connection_set.active[index];
	}

	qsc_async_mutex_unlock(m_pool_mutex);

	return res;
}

size_t dktp_connections_available(void)
{
	size_t count;

	count = 0U;

	qsc_async_mutex_lock(m_pool_mutex);

	for (size_t i = 0U; i < m_connection_set.count; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			++count;
		}
	}

	qsc_async_mutex_unlock(m_pool_mutex);
	
	return count;
}

void dktp_connections_clear(void)
{
	qsc_async_mutex_lock(m_pool_mutex);

	qsc_memutils_clear(m_connection_set.conset, sizeof(dktp_connection_state) * m_connection_set.count);

	for (size_t i = 0U; i < m_connection_set.count; ++i)
	{
		m_connection_set.active[i] = false;
		m_connection_set.conset[i].cid = (uint32_t)i;
	}

	qsc_async_mutex_unlock(m_pool_mutex);
}

void dktp_connections_dispose(void)
{

	if (m_connection_set.conset != NULL)
	{
#if defined(DKTP_ASYMMETRIC_RATCHET)
		for (size_t i = 0U; i < m_connection_set.count; ++i)
		{
			if (m_connection_set.conset[i].txlock)
			{
				qsc_async_mutex_destroy(m_connection_set.conset[i].txlock);
			}
		}
#endif

		dktp_connections_clear();

		if (m_connection_set.conset != NULL)
		{
			qsc_memutils_alloc_free(m_connection_set.conset);
			m_connection_set.conset = NULL;
		}
	}

	if (m_connection_set.active != NULL)
	{
		qsc_memutils_alloc_free(m_connection_set.active);
		m_connection_set.active = NULL;
	}

	m_connection_set.count = 0U;

	if (m_pool_mutex)
	{
		(void)qsc_async_mutex_destroy(m_pool_mutex);
	}
}

dktp_connection_state* dktp_connections_index(size_t index)
{
	dktp_connection_state* res;

	res = NULL;

	qsc_async_mutex_lock(m_pool_mutex);

	if (index < m_connection_set.count)
	{
		res = &m_connection_set.conset[index];
	}

	qsc_async_mutex_unlock(m_pool_mutex);

	return res;
}

bool dktp_connections_full(void)
{
	bool res;

	res = true;

	qsc_async_mutex_lock(m_pool_mutex);

	for (size_t i = 0U; i < m_connection_set.count; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = false;
			break;
		}
	}

	qsc_async_mutex_unlock(m_pool_mutex);

	return res;
}

dktp_connection_state* dktp_connections_get(uint32_t cid)
{
	dktp_connection_state* res;

	res = NULL;

	qsc_async_mutex_lock(m_pool_mutex);

	for (size_t i = 0; i < m_connection_set.count; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			res = &m_connection_set.conset[i];
		}
	}

	qsc_async_mutex_unlock(m_pool_mutex);

	return res;
}

bool dktp_connections_initialize(size_t count)
{
	DKTP_ASSERT(count != 0U);

	bool res;

	res = false;

	if (count != 0U)
	{
		m_pool_mutex = qsc_async_mutex_create();

		m_connection_set.count = count;
		m_connection_set.conset = qsc_memutils_malloc(count * sizeof(dktp_connection_state));

		if (m_connection_set.conset != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, count * sizeof(dktp_connection_state));
			m_connection_set.active = qsc_memutils_malloc(count * sizeof(bool));

			if (m_connection_set.active != NULL)
			{
				for (size_t i = 0U; i < count; ++i)
				{
					m_connection_set.conset[i].cid = (uint32_t)i;
					m_connection_set.active[i] = false;
				}

				res = true;
			}
		}
	}

	return res;
}

dktp_connection_state* dktp_connections_next(void)
{
	dktp_connection_state* res;

	res = NULL;

	qsc_async_mutex_lock(m_pool_mutex);

	for (size_t i = 0U; i < m_connection_set.count; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = &m_connection_set.conset[i];
			m_connection_set.active[i] = true;
#if defined(DKTP_ASYMMETRIC_RATCHET)
			res->txlock = qsc_async_mutex_create();
#endif
			break;
		}
	}
	
	qsc_async_mutex_unlock(m_pool_mutex);

	return res;
}

void dktp_connections_reset(uint32_t cid)
{
	qsc_async_mutex_lock(m_pool_mutex);

	for (size_t i = 0U; i < m_connection_set.count; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
#if defined(DKTP_ASYMMETRIC_RATCHET)
			qsc_mutex mtmp = m_connection_set.conset[i].txlock;
#endif
			qsc_memutils_clear(&m_connection_set.conset[i], sizeof(dktp_connection_state));
			m_connection_set.conset[i].cid = (uint32_t)i;
			m_connection_set.active[i] = false;
#if defined(DKTP_ASYMMETRIC_RATCHET)
			if (mtmp)
			{
				qsc_async_mutex_destroy(mtmp);
			}
#endif
			break;
		}
	}

	qsc_async_mutex_unlock(m_pool_mutex);
}

size_t dktp_connections_size(void)
{
	size_t res;

	qsc_async_mutex_lock(m_pool_mutex);
	res =  m_connection_set.count;
	qsc_async_mutex_unlock(m_pool_mutex);

	return res;
}

