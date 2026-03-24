/*
 * audit.c
 * package audit log functions
 *
 * Copyright (c) 2016 pkgconf authors (see AUTHORS).
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include <libpkgconf/libpkgconf.h>

/*
 * !doc
 *
 * libpkgconf `allocate` module
 * =========================
 *
 * The libpkgconf `allocate` module contains wrapper functions for allocation and
 * returning errors on OOM.
 * 
 * In the event of OOM, the OOM handler in ``client`` is called.
 */

/*
 * !doc
 *
 * .. c:function:: void *pkgconf_alloc(pkgconf_client_t *client, size_t n, size_t elemb)
 *
 *    Allocates memory on the heap. The callee must free with pkgconf_free().
 *
 *    :param pkgconf_client_t* client: The client object.
 *    :param size_t n: Number of elements
 *    :param size_t elemb: Size of each element
 *    :return: Cleared pointer to allocated data, or NULL on failure.
 *             client->oom_handler will be called if the allocation fails.
 */
void *
pkgconf_alloc(const pkgconf_client_t *client, size_t n, size_t elemb)
{
	void *ret = calloc(n, elemb);
	if (!ret)
	{
		pkgconf_oom(client, "Out of memory: allocation size %zu count %zu", n, elemb);
		return NULL;
	}
	return ret;
}

/*
 * !doc
 *
 * .. c:function:: void *pkgconf_realloc(pkgconf_client_t *client, void *ptr, size_t old_n, size_t n, size_t elemb)
 *
 *    Rellocates memory on the heap. The callee must free with pkgconf_free().
 *    Additional reallocated memory is set to zero.
 *
 *    :param pkgconf_client_t* client: The client object.
 *    :param void *ptr: Memory pointed to resize
 *    :param size_t old_n: Old number of elements
 *    :param size_t n: New number of elements
 *    :param size_t elemb: Size of each element
 *    :return: Cleared pointer to allocated data, or NULL on failure.
 *             client->oom_handler will be called if the allocation fails.
 */
void *
pkgconf_realloc(const pkgconf_client_t *client, void *ptr, size_t old_n, size_t n, size_t elemb)
{
	if (elemb == 0 || n == 0 || n > SIZE_MAX / elemb)
	{
		// Overflow or zero allocation
		return NULL;
	}

	size_t size = n * elemb;
	void *ret = realloc(ptr, size);
	if (!ret)
	{
		pkgconf_oom(client, "Out of memory: allocation length %zu, element size %zu", n, elemb);
		return NULL;
	}

	if (old_n < n)
	{
		// Zeroize new space (guaranteed not to overflow because old_n < n and we checked if n overflows)
		size_t oldsize = old_n * elemb;
		size_t len = size - oldsize;
		char *off = ((char *)ret) + oldsize; // Byte offset
		memset(off, 0, len);
	}

	return ret;
}

/*
 * !doc
 *
 * .. c:function:: void pkgconf_free(pkgconf_client_t *client, void *ptr) 
 *
 *    Frees memory previously allocated on the heap.
 *
 *    :param pkgconf_client_t* client: The client object.
 *    :param void *ptr: Data to free.
 */
void
pkgconf_free(const pkgconf_client_t *client, void *ptr)
{
	(void) client;
	free(ptr);
}

