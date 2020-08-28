#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rsig.h"
#include "hasher_signal.h"
#include "signal_protocol.h"
#include "signal_protocol_internal.h"
#include "curve.h"
#include "test_common.h"

/* 
 * This structure below is essentially identical to 
 * ec_public_key and ec_private_key
 */
typedef struct ec_key
{
    signal_type_base base;
    keybytes data;
} ec_key;

static inline const keybytes* ec_key_get_bytes(const ec_key* key)
{
  return &(key->data);
}

static size_t sig_buf_to_file(FILE* fp, const signal_buffer* buf)
{
  return fwrite(signal_buffer_const_data(buf), sizeof(char),
		signal_buffer_len(buf), fp);
}

static signal_buffer* file_to_sig_buf(FILE* fp)
{
  struct stat st;
  if(0 != fstat(fileno(fp), &st)) {
    return NULL;
  }
  signal_buffer* buf = signal_buffer_alloc(st.st_size);
  fseek(fp, 0, SEEK_SET);
  size_t rsize = fread(signal_buffer_data(buf), sizeof(char),
		       st.st_size, fp);
  if(st.st_size != rsize) {
    signal_buffer_free(buf);
    buf = NULL;
  }
  return buf;
}

#define CMD_HANDLER(x) int (x)(int argc, const char** argv, signal_context* ctx)
typedef CMD_HANDLER(cmd_handler);

typedef struct subcmd {
  const char* name;
  cmd_handler* handler;
} subcmd;

#define SUBCMD(f) { #f, f }
		    
CMD_HANDLER(genkeypair)
{
  ec_key_pair* pair = NULL;
  signal_buffer* skbuf = NULL;
  signal_buffer* pkbuf = NULL;
  int res = 0;
  FILE* skfile = NULL;
  FILE* pkfile = NULL;
  do {
    res = curve_generate_key_pair(ctx, &pair);
    if (res != 0) {
      fputs("Failed to generate keypair!\n", stderr);
      break;
    }
    res = ec_private_key_serialize(&skbuf, ec_key_pair_get_private(pair));
    if (res != 0) {
      fputs("Failed to serialize private key!\n", stderr);
      break;
    }
    res = ec_public_key_serialize(&pkbuf, ec_key_pair_get_public(pair));
    if (res != 0) {
      fputs("Failed to serialize public key!\n", stderr);
      break;
    }
    skfile = fopen(argv[0], "wb");
    pkfile = fopen(argv[1], "wb");
    if (skfile == NULL || pkfile == NULL) {
      perror("Failed to open files for output!");
      break;
    }
    sig_buf_to_file(skfile, skbuf);
    sig_buf_to_file(pkfile, pkbuf);
  } while (0);
  {
    ec_key_pair_destroy((signal_type_base*)pair);
    signal_buffer_bzero_free(skbuf);
    signal_buffer_free(pkbuf);
    if (skfile) {
      fclose(skfile);
    }
    if (pkfile) {
      fclose(pkfile);
    }
    return res;
  }
}

CMD_HANDLER(sec2pub)
{
  ec_private_key* sk = NULL;
  ec_public_key* pk = NULL;
  signal_buffer* skbuf = NULL;
  signal_buffer* pkbuf = NULL;
  int res = 0;
  FILE* skfile = NULL;
  FILE* pkfile = NULL;
  do {
    skfile = fopen(argv[0], "rb");
    pkfile = fopen(argv[1], "wb");
    if (skfile == NULL || pkfile == NULL) {
      perror("Failed to open files!");
      break;
    }
    skbuf = file_to_sig_buf(skfile);
    if(skbuf == NULL) {
      fprintf(stderr, "Failed to read %s into memory!\n", argv[0]);
      break;
    }
    res = curve_decode_private_point(&sk, signal_buffer_const_data(skbuf),
				     signal_buffer_len(skbuf), ctx);
    if(res != 0) {
      fputs("Failed to decode private key!\n", stderr);
      break;
    }
    res = curve_generate_public_key(&pk, sk);
    if(res != 0) {
      fputs("Failed to compute public key!\n", stderr);
      break;
    }
    res = ec_public_key_serialize(&pkbuf, pk);
    if (res != 0) {
      fputs("Failed to serialize public key!\n", stderr);
      break;
    }
    sig_buf_to_file(pkfile, pkbuf);
  } while (0);
  {
    ;
    ec_private_key_destroy((signal_type_base*)sk);
    signal_buffer_bzero_free(skbuf);
    signal_buffer_free(pkbuf);
    if (skfile) {
      fclose(skfile);
    }
    if (pkfile) {
      fclose(pkfile);
    }
    return res;
  }
}

CMD_HANDLER(rsign)
{
  hasher_imp hi;
  hasher h;
  signal_buffer* pk[3] = { NULL, NULL, NULL };
  ec_public_key *ecpk[3] = { NULL, NULL, NULL };
  signal_buffer* sk = NULL;
  signal_buffer* msg = NULL;
  signal_buffer* ad = NULL;
  signal_buffer* iht = NULL;
  signal_buffer* random = NULL;
  
  FILE* file = NULL;
  rsig sig;
  copy_imp_signal(&hi, &(ctx->crypto_provider));
  hasher_init(&h, &hi, copy_userdata_signal(&(ctx->crypto_provider)));

  int res = -1;
  do {
    file = fopen(argv[0], "r");
    if (file == NULL) {
      break;
    }
    pk[0] = file_to_sig_buf(file);
    if(freopen(argv[1], "r", file) == NULL) {
      break;
    }
    pk[1] = file_to_sig_buf(file);
    if(freopen(argv[2], "r", file) == NULL) {
      break;
    }
    pk[2] = file_to_sig_buf(file);
    if(freopen(argv[3], "r", file) == NULL) {
      break;
    }
    sk = file_to_sig_buf(file);
    if(freopen(argv[4], "r", file) == NULL) {
      break;
    }
    msg = file_to_sig_buf(file);
    if(freopen(argv[5], "r", file) == NULL) {
      break;
    }
    ad = file_to_sig_buf(file);
    if(freopen(argv[6], "r", file) == NULL) {
      break;
    }
    iht = file_to_sig_buf(file);
    if(freopen(argv[7], "r", file) == NULL) {
      break;
    }
    random = file_to_sig_buf(file);
    
    fputs("Input files is all successfully read!\n", stderr);
    
    int i;
    for(i = 0; i < 3; i++) {
      res = curve_decode_point(&ecpk[i], signal_buffer_const_data(pk[i]),
				     signal_buffer_len(pk[i]), ctx);
      if(res != 0) {
	fprintf(stderr, "Failed to decode public key %d!\n", i);
	break;
      }
    }
    if(res != 0) {
      break;
    }
    res = rsign_xed25519(&h, ec_key_get_bytes((const ec_key*)ecpk[0]),
			 ec_key_get_bytes((const ec_key*)ecpk[1]),
			 ec_key_get_bytes((const ec_key*)ecpk[2]),
			 (const keybytes*)signal_buffer_const_data(sk),
			 signal_buffer_const_data(msg),
			 signal_buffer_len(msg),
			 signal_buffer_const_data(ad),
			 signal_buffer_len(ad),
			 signal_buffer_const_data(iht),
			 signal_buffer_len(iht),
			 signal_buffer_const_data(random),
			 signal_buffer_len(random),
			 &sig);
    if(res == 0 && freopen(argv[8], "w", file) != NULL) {
      fwrite(&sig, sizeof(char), sizeof(rsig), file);
      fprintf(stderr, "Ring signature is successfully written to %s.\n",
	      argv[8]);
    }
  } while (0);
  {
    signal_buffer_bzero_free(sk);
    signal_buffer_free(pk[0]);
    signal_buffer_free(pk[1]);
    signal_buffer_free(pk[2]);
    signal_buffer_free(msg);
    signal_buffer_free(ad);
    signal_buffer_free(iht);
    signal_buffer_free(random);
    ec_public_key_destroy((signal_type_base*)ecpk[0]);
    ec_public_key_destroy((signal_type_base*)ecpk[1]);
    ec_public_key_destroy((signal_type_base*)ecpk[2]);
    if (file) {
      fclose(file);
    }
    return res;
  }
}

CMD_HANDLER(rvrf)
{
  hasher_imp hi;
  hasher h;
  signal_buffer* pk[3] = { NULL, NULL, NULL };
  ec_public_key* ecpk[3] = { NULL, NULL, NULL };
  signal_buffer* proof = NULL;
  signal_buffer* msg = NULL;
  signal_buffer* ad = NULL;
  signal_buffer* iht = NULL;
  FILE* file = NULL;
  rsig sig;
  copy_imp_signal(&hi, &(ctx->crypto_provider));
  hasher_init(&h, &hi, copy_userdata_signal(&(ctx->crypto_provider)));

  int res = -1;
  do {
    file = fopen(argv[0], "r");
    if (file == NULL) {
      break;
    }
    pk[0] = file_to_sig_buf(file);
    if(freopen(argv[1], "r", file) == NULL) {
      break;
    }
    pk[1] = file_to_sig_buf(file);
    if(freopen(argv[2], "r", file) == NULL) {
      break;
    }
    pk[2] = file_to_sig_buf(file);
    if(freopen(argv[3], "r", file) == NULL) {
      break;
    }
    proof = file_to_sig_buf(file);
    if(freopen(argv[4], "r", file) == NULL) {
      break;
    }
    msg = file_to_sig_buf(file);
    if(freopen(argv[5], "r", file) == NULL) {
      break;
    }
    ad = file_to_sig_buf(file);
    if(freopen(argv[6], "r", file) == NULL) {
      break;
    }
    iht = file_to_sig_buf(file);
    
    fputs("Input files is all successfully read!\n", stderr);

    int i;
    for(i = 0; i < 3; i++) {
      res = curve_decode_point(&ecpk[i], signal_buffer_const_data(pk[i]),
				     signal_buffer_len(pk[i]), ctx);
      if(res != 0) {
	fprintf(stderr, "Failed to decode public key %d!\n", i);
	break;
      }
    }
    if(res != 0) {
      break;
    }
    
    res = rvrf_xed25519(&h, ec_key_get_bytes((const ec_key*)ecpk[0]),
			ec_key_get_bytes((const ec_key*)ecpk[1]),
			ec_key_get_bytes((const ec_key*)ecpk[2]),
			(const rsig*)signal_buffer_const_data(proof),
			signal_buffer_const_data(msg),
			signal_buffer_len(msg),
			signal_buffer_const_data(ad),
			signal_buffer_len(ad),
			signal_buffer_const_data(iht),
			signal_buffer_len(iht));
  } while (0);
  {
    signal_buffer_free(proof);
    signal_buffer_free(pk[0]);
    signal_buffer_free(pk[1]);
    signal_buffer_free(pk[2]);
    signal_buffer_free(msg);
    signal_buffer_free(ad);
    signal_buffer_free(iht);
    ec_public_key_destroy((signal_type_base*)ecpk[0]);
    ec_public_key_destroy((signal_type_base*)ecpk[1]);
    ec_public_key_destroy((signal_type_base*)ecpk[2]);
    if (file) {
      fclose(file);
    }
    return res;
  }
}

const subcmd subcmds[] = {
  SUBCMD(genkeypair),
  SUBCMD(sec2pub),
  SUBCMD(rsign),
  SUBCMD(rvrf),
  { NULL, NULL }
};

static const subcmd* match_subcmd(const char* name)
{
  const subcmd* cmd = NULL;
  for(cmd = subcmds; cmd->name != NULL; cmd++) {
    if(0 == strcmp(name, cmd->name)) {
      return cmd;
    }
  }
  return NULL;
}

signal_context *global_context;

int test_setup(void)
{
    int result = signal_context_create(&global_context, 0);
    if (result != 0) {
      return result;
    }
    signal_context_set_log_function(global_context, test_log);

    setup_test_crypto_provider(global_context);
    return result;
}

void test_teardown(void)
{
    signal_context_destroy(global_context);
}

const char usage[]=
  "The test application supports the following sub-commands:\n"
  "genkeypair <seckey> <pubkey>;\n"
  "sec2pub <seckey> <pubkey> (compute pubkey from secret key);\n"
  "rsign <pk1> <pk2> <pk3> <sk> <message> <associatedata> <implHashTag> <random> <proof>;\n"
  "(create ring sig)\n"
  "rvrf <pk1> <pk2> <pk3> <proof> <message> <associatedata> <implHashTag>;\n"
  "(verify ring sig)\n";

int main(int argc, char** argv)
{
  if(argc == 1) {
    fputs(usage, stderr);
    return 0;
  }
  
  int res = test_setup();
  if(res != 0) {
    fputs("Failed to set up signal global context!", stderr);
    return res;
  }
  
  const subcmd* cmd = match_subcmd(argv[1]);
  if(cmd == NULL) {
    fprintf(stderr, "Unrecognized sub command \"%s\"!\n", argv[1]);
    fputs(usage, stderr);
    return 0;
  }
  res = cmd->handler(argc - 2, (const char**)argv + 2, global_context);
  if(res < 0) {
    fprintf(stderr, "Test failed for sub command %s, with result %d.\n",
	    cmd->name, res);
  } else if(0 == strcmp(cmd->name, "rvrf")) {
    fprintf(stderr, "Ring signature is %s!\n", (res)?"valid":"invalid");
    res = 0;
  }
  test_teardown();
  return res;
}
