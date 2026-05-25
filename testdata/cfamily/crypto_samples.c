/* Sample for cryptobom regression testing (OpenSSL, C). */
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

void weak_and_misused(unsigned char *data, size_t len, unsigned char *out) {
    /* Weak hashes and ciphers. */
    MD5(data, len, out);
    const EVP_MD *sha1 = EVP_sha1();
    const EVP_CIPHER *des3 = EVP_des_ede3_cbc();
    const EVP_CIPHER *ecb = EVP_aes_128_ecb();
    const EVP_CIPHER *rc4 = EVP_rc4();

    /* OpenSSL 3.0 fetch (algorithm as a string). */
    const EVP_MD *m = EVP_MD_fetch(NULL, "MD5", NULL);
}

void vulnerable(RSA *rsa, BIGNUM *e, SSL_CTX *ctx) {
    /* Quantum-vulnerable key generation. */
    RSA_generate_key_ex(rsa, 2048, e, NULL);

    /* Deprecated TLS protocols (method constructor + version constant). */
    const SSL_METHOD *meth = SSLv3_method();
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
}

void strong(unsigned char *data, size_t len, unsigned char *out) {
    /* Good usage — must NOT be flagged. */
    SHA256(data, len, out);
    const EVP_CIPHER *gcm = EVP_aes_256_gcm();
}
