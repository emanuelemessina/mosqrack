#include "memory_mosq.h"

#include <memory>

void* mosquitto_calloc(size_t nmemb, size_t size)
{
	void* mem;
#ifdef REAL_WITH_MEMORY_TRACKING
	if (mem_limit && memcount + size > mem_limit) {
		return NULL;
	}
#endif
	mem = calloc(nmemb, size);

#ifdef REAL_WITH_MEMORY_TRACKING
	if (mem) {
		memcount += malloc_usable_size(mem);
		if (memcount > max_memcount) {
			max_memcount = memcount;
		}
	}
#endif

	return mem;
}

void mosquitto_free(void* mem)
{
#ifdef REAL_WITH_MEMORY_TRACKING
	if (!mem) {
		return;
	}
	memcount -= malloc_usable_size(mem);
#endif
	free(mem);
}