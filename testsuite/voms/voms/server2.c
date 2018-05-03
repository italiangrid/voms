/*
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vomsssl.h>

#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
#include <string.h>
//#undef DEBUG
//#define DEBUG( out )

// Namespace

//---------------------------------------------------------------------------

int main(int argc, char *argv[])
{
  // default paths currently point to my test certificates
  char *m_caCertPath;
  char *m_serverCert;
  char *m_serverKey;
  char *stoparg;

  m_caCertPath= argv[1];
  fprintf(stdout,  "phase1\n");
  m_serverCert = strchr(m_caCertPath, ';');
  fprintf(stdout,  "phase2\n");
  *m_serverCert++ ='\0';
  m_serverKey  = strchr(m_serverCert, ';');
  fprintf(stdout,  "phase3\n");
  *m_serverKey++ ='\0';
  stoparg = strchr(m_serverKey, ';');
  fprintf(stdout,  "phase4\n");
  *stoparg++ = '\0';

  fprintf(stdout, "ca:%s\ncert:%s\nkey:%s\nstop:%s\n", m_caCertPath, m_serverCert, m_serverKey, stoparg);

  SSL_CTX *m_sslCtx = NULL;

  // Initializing OpenSSL
  // FIXME should this only be called once?

  OpenSSL_add_all_algorithms();
  SSLeay_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
  SSL_library_init();


  m_sslCtx = SSL_CTX_new( SSLv23_method() );
  if (!m_sslCtx) {
    ERR_print_errors_fp( stdout );
    printf("error1\n");

  }

  SSL_CTX_set_options(m_sslCtx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
/*   SSL_CTX_set_cipher_list(m_sslCtx, "ALL:!LOW:!EXP:!MD5:!MD2");      */
  SSL_CTX_set_purpose(m_sslCtx, X509_PURPOSE_ANY);
  /*  SSL_CTX_set_mode(m_sslCtx, SSL_MODE_AUTO_RETRY); */

  printf("test\n");
  // load server certificate
  if ( SSL_CTX_use_certificate_file( m_sslCtx,
        m_serverCert, SSL_FILETYPE_PEM ) <= 0 )
  {
    ERR_print_errors_fp( stdout );
    printf("error1\n");
  }

  // load private key
  if ( SSL_CTX_use_PrivateKey_file( m_sslCtx,
        m_serverKey, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp( stdout );
    printf("error2\n");
  }

  // load trusted Certificate Authority
  if ( !SSL_CTX_load_verify_locations( m_sslCtx, 0,
        m_caCertPath ) )
  {
    ERR_print_errors_fp( stdout );
    printf("error3\n");
  }

  // require peer (client) certificate verification
  SSL_CTX_set_verify( m_sslCtx, SSL_VERIFY_PEER, 0 );
  // Set the verification depth to 1
  SSL_CTX_set_verify_depth( m_sslCtx, 100 );

  // set the verify call back to girdsite, which understands
  // proxy certificates
  SSL_CTX_set_cert_verify_callback( m_sslCtx,
      proxy_verify_callback_server, 0);

  // create new ssl structure and pass the fd to it
  SSL *m_sslCon = SSL_new( m_sslCtx );

  BIO *bio = BIO_new_accept("33334");
  if (BIO_do_accept(bio) <= 0)
    fprintf(stdout, "BIO_do_accept failed\n");
  fprintf(stdout, "now accepting\n");
  fprintf(stdout, "bio=%ld\n", bio);
  BIO_do_accept(bio);
  fprintf(stdout, "part1\n");
  BIO *client= BIO_pop(bio);
  fprintf(stdout, "part2\n");
  SSL_set_bio(m_sslCon, client, client);
  fprintf(stdout,"bio set\n");

  // initiate the handshake
  int error;
  if ( (error = SSL_accept( m_sslCon )) <= 0 ) {
    unsigned long l;
    char buf[256];
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
    const char *file;
#else
    char *file;
#endif
    char *dat;
    int line;

  /* WIN32 does not have the ERR_get_error_line_data */
  /* exported, so simulate it till it is fixed */
  /* in SSLeay-0.9.0 */

    while ( ERR_peek_error() != 0 ) {

      int i;
      ERR_STATE *es;

      es = ERR_get_state();
      i = (es->bottom+1)%ERR_NUM_ERRORS;

      if (es->err_data[i] == NULL)
        dat = (char*)"";
      else
        dat = es->err_data[i];
      if (dat) {
        l = ERR_get_error_line(&file, &line);
        //      if (debug)
        fprintf(stdout, "%s:%s,%d,%s\n", ERR_error_string(l, buf),
                file, line, dat);
        //      error += std::string(ERR_reason_error_string(l)) + ":" + std::string(ERR_func_error_string(l)) + "\n";
      }
    }
/*     fprintf(stdout, "%s\n", */
/*             ERR_reason_error_string( ERR_get_error() )); */
    fprintf(stdout, "ERROR\n");
    exit(1);
  }

  fprintf(stdout, "Handshake done!\n");
  /* connected */
  sleep(100);

  exit(0);
}
