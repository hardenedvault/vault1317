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

#include "hasher_signal.h"

void copy_imp_signal(hasher_imp* imp, const signal_crypto_provider* provider)
{
  imp->name = "signal-sha512";
  imp->init = provider->sha512_digest_init_func;
  imp->update = provider->sha512_digest_update_func;
  imp->final = provider->sha512_digest_final_func;
  imp->cleanup = provider->sha512_digest_cleanup_func;
}

void* copy_userdata_signal(const signal_crypto_provider* provider)
{
  return provider->user_data;
}
