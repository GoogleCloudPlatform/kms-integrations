#ifndef KMSP11_OPENSSL_H_
#define KMSP11_OPENSSL_H_

#include "openssl/bio.h"       // IWYU pragma: export
#include "openssl/bn.h"        // IWYU pragma: export
#include "openssl/conf.h"      // IWYU pragma: export
#include "openssl/crypto.h"    // IWYU pragma: export
#include "openssl/ec.h"        // IWYU pragma: export
#include "openssl/ecdsa.h"     // IWYU pragma: export
#include "openssl/err.h"       // IWYU pragma: export
#include "openssl/evp.h"       // IWYU pragma: export
#include "openssl/pem.h"       // IWYU pragma: export
#include "openssl/rand.h"      // IWYU pragma: export
#include "openssl/rsa.h"       // IWYU pragma: export
#include "openssl/x509.h"      // IWYU pragma: export
#include "openssl/x509_vfy.h"  // IWYU pragma: export
#include "openssl/x509v3.h"    // IWYU pragma: export

#ifdef BORINGSSL_FIPS

// X509_SIG_get0 and X509_SIG_getm were added to BoringSSL after the most
// recent FIPS validation.
// https://boringssl-review.googlesource.com/c/boringssl/+/42344

inline void X509_SIG_get0(const X509_SIG* sig, const X509_ALGOR** out_alg,
                          const ASN1_OCTET_STRING** out_digest) {
  if (out_alg != nullptr) {
    *out_alg = sig->algor;
  }
  if (out_digest != nullptr) {
    *out_digest = sig->digest;
  }
}

inline void X509_SIG_getm(X509_SIG* sig, X509_ALGOR** out_alg,
                          ASN1_OCTET_STRING** out_digest) {
  if (out_alg != nullptr) {
    *out_alg = sig->algor;
  }
  if (out_digest != nullptr) {
    *out_digest = sig->digest;
  }
}

#endif  // BORINGSSL_FIPS

#endif  // KMSP11_OPENSSL_H_
