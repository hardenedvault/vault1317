/*
 * Copyright (C) 2018-2024, HardenedVault (https://hardenedvault.net)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include "sigaddr_holder.h"

ptrdiff_t sigaddr_compare_name(const signal_protocol_address* a1,
			       const signal_protocol_address* a2)
{
  ptrdiff_t diff = a1->name_len - a2->name_len;
  if (diff)
    return diff;
  return strncmp(a1->name, a2->name, a1->name_len);
}

ptrdiff_t sigaddr_compare_full(const signal_protocol_address* a1,
			       const signal_protocol_address* a2)
{
  ptrdiff_t diff = sigaddr_compare_name(a1, a2);
  if (diff)
    return diff;
  return a1->device_id - a2->device_id;
}

bool sigaddr_sane(const signal_protocol_address* addr)
{
  return strlen(addr->name) == addr->name_len;
}

bool sigaddr_holder_sane(const sigaddr_holder* h)
{
  return (h && (h->buf_name) &&
	  (h->addr.name == (const char*)signal_buffer_data(h->buf_name)) &&
	  (h->addr.name_len == signal_buffer_len(h->buf_name) - 1) &&
	  sigaddr_sane(&h->addr));
}

int sigaddr_holder_reassemble(sigaddr_holder* h,
			      const char* name,
			      size_t name_len,
			      uint32_t devid)
{
  if (sigaddr_holder_sane(h))
    sigaddr_holder_uninit(h);

  h->buf_name = signal_buffer_create((const uint8_t*)name,
				     name_len + 1);
  if (!h->buf_name)
    return SG_ERR_NOMEM;

  h->addr.name = (const char*)signal_buffer_data(h->buf_name);
  h->addr.name_len = name_len;
  h->addr.device_id = devid;
  return SG_SUCCESS;
}

int sigaddr_holder_reinit(sigaddr_holder* h,
			  const signal_protocol_address* addr)
{
  if (!sigaddr_sane(addr))
    return SG_ERR_INVAL;

  return sigaddr_holder_reassemble(h, addr->name,
				 addr->name_len,
				 addr->device_id);
}

const signal_protocol_address*
sigaddr_holder_get_addr(const sigaddr_holder* h)
{
  return &h->addr;
}

int sigaddr_holder_copy(sigaddr_holder* h,
			const sigaddr_holder* h_src)
{
  return sigaddr_holder_reinit(h, sigaddr_holder_get_addr(h_src));
}

void sigaddr_holder_uninit(sigaddr_holder* h)
{
  signal_buffer_free(h->buf_name);
  *h = EMPTY_SIGADDR_HOLDER;
}
