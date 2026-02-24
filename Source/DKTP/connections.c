#include "connections.h"
#include "async.h"
#include "memutils.h"

/** \cond */
typedef struct dktp_connection_set
{
	dktp_connection_state* conset;
	bool* active;
	size_t maximum;
	size_t length;
} dktp_connection_set;

static dktp_connection_set m_connection_set;
/** \endcond */

bool dktp_connections_active(size_t index)
{
	bool res;

	res = false;

	if (index < m_connection_set.length)
	{
		res = m_connection_set.active[index];
	}

	return res;
}

dktp_connection_state* dktp_connections_add(void)
{
	dktp_connection_state* cns;

	cns = NULL;

	if ((m_connection_set.length + 1U) <= m_connection_set.maximum)
	{
		dktp_connection_state* tcon;

		tcon = qsc_memutils_realloc(m_connection_set.conset, (m_connection_set.length + 1U) * sizeof(dktp_connection_state));

		if (tcon != NULL)
		{
			bool* tact;

			m_connection_set.conset = tcon;
			tact = qsc_memutils_realloc(m_connection_set.active, (m_connection_set.length + 1U) * sizeof(bool));

			if (tact != NULL)
			{
				m_connection_set.active = tact;

				if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
				{
					qsc_memutils_clear(&m_connection_set.conset[m_connection_set.length], sizeof(dktp_connection_state));
					m_connection_set.conset[m_connection_set.length].cid = (uint32_t)m_connection_set.length;
					m_connection_set.active[m_connection_set.length] = true;
					cns = &m_connection_set.conset[m_connection_set.length];
					++m_connection_set.length;
				}
			}
		}
	}

	return cns;
}

size_t dktp_connections_available(void)
{
	size_t count;

	count = 0U;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			++count;
		}
	}
	
	return count;
}

void dktp_connections_clear(void)
{
	qsc_memutils_clear(m_connection_set.conset, sizeof(dktp_connection_state) * m_connection_set.length);

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		m_connection_set.active[i] = false;
		m_connection_set.conset[i].cid = (uint32_t)i;
	}
}

void dktp_connections_dispose(void)
{
	if (m_connection_set.conset != NULL)
	{
#if defined(DKTP_ASYMMETRIC_RATCHET)
		for (size_t i = 0U; i < m_connection_set.length; ++i)
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

	m_connection_set.length = 0U;
	m_connection_set.maximum = 0U;
}

dktp_connection_state* dktp_connections_index(size_t index)
{
	dktp_connection_state* res;

	res = NULL;

	if (index < m_connection_set.length)
	{
		res = &m_connection_set.conset[index];
	}

	return res;
}

bool dktp_connections_full(void)
{
	bool res;

	res = true;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = false;
			break;
		}
	}

	return res;
}

dktp_connection_state* dktp_connections_get(uint32_t cid)
{
	dktp_connection_state* res;

	res = NULL;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			res = &m_connection_set.conset[i];
		}
	}

	return res;
}

void dktp_connections_initialize(size_t count, size_t maximum)
{
	DKTP_ASSERT(count != 0U);
	DKTP_ASSERT(maximum != 0U);
	DKTP_ASSERT(count <= maximum);
	
	if (count != 0U && maximum != 0U && count <= maximum)
	{
		m_connection_set.length = count;
		m_connection_set.maximum = maximum;
		m_connection_set.conset = (dktp_connection_state*)qsc_memutils_malloc(sizeof(dktp_connection_state) * m_connection_set.length);
		m_connection_set.active = (bool*)qsc_memutils_malloc(sizeof(bool) * m_connection_set.length);

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, sizeof(dktp_connection_state) * m_connection_set.length);

			for (size_t i = 0; i < count; ++i)
			{
				m_connection_set.conset[i].cid = (uint32_t)i;
				m_connection_set.active[i] = false;
			}
		}
	}
}

dktp_connection_state* dktp_connections_next(void)
{
	dktp_connection_state* res;

	res = NULL;

	if (dktp_connections_full() == false)
	{
		for (size_t i = 0U; i < m_connection_set.length; ++i)
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
	}
	else
	{
		res = dktp_connections_add();
#if defined(DKTP_ASYMMETRIC_RATCHET)
		res->txlock = qsc_async_mutex_create();
#endif
	}

	return res;
}

void dktp_connections_reset(uint32_t cid)
{
	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			qsc_memutils_clear(&m_connection_set.conset[i], sizeof(dktp_connection_state));
			m_connection_set.conset[i].cid = (uint32_t)i;
			m_connection_set.active[i] = false;
#if defined(DKTP_ASYMMETRIC_RATCHET)
			if (m_connection_set.conset[i].txlock)
			{
				qsc_async_mutex_destroy(m_connection_set.conset[i].txlock);
			}
#endif
			break;
		}
	}
}

size_t dktp_connections_size(void)
{
	return m_connection_set.length;
}

#if defined(DKTP_DEBUG_MODE)
void dktp_connections_self_test(void)
{
	dktp_connection_state* xn[20U] = { 0 };
	size_t cnt;
	bool full;

	(void)xn;
	(void)full;
	(void)cnt;
	dktp_connections_initialize(1U, 10U); /* init with 1 */

	for (size_t i = 1U; i < 10U; ++i)
	{
		xn[i] = dktp_connections_next(); /* init next 9 */
	}

	cnt = dktp_connections_available(); /* expected 0 */
	full = dktp_connections_full(); /* expected true */

	dktp_connections_reset(1U); /* release 5 */
	dktp_connections_reset(3U);
	dktp_connections_reset(5U);
	dktp_connections_reset(7U);
	dktp_connections_reset(9U);

	full = dktp_connections_full(); /* expected false */

	xn[11] = dktp_connections_next(); /* reclaim 5 */
	xn[12] = dktp_connections_next();
	xn[13] = dktp_connections_next();
	xn[14] = dktp_connections_next();
	xn[15] = dktp_connections_next();

	full = dktp_connections_full(); /* expected true */

	xn[16] = dktp_connections_next(); /* should exceed max */

	cnt = dktp_connections_size(); /* expected 10 */

	dktp_connections_clear();
	dktp_connections_dispose();
}
#endif
