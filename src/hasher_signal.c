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
