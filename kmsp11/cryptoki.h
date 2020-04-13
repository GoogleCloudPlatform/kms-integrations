// A wrapper for pkcs11.h, which declares the required macros.
//
// Cryptoki requires that libraries and applications declare a number of macros
// before including the pkcs11.h header. Full details at:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc405794626

#ifndef KMSP11_CRYPTOKI_H_
#define KMSP11_CRYPTOKI_H_

#ifdef _WIN32
// Platform-specific struct packing. By convention, default packing is used on
// *nix, and structs are packed at 1-byte alignment on Windows.
#pragma pack(push, cryptoki, 1)
#endif

#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include "pkcs11.h"

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

#endif  // KMSP11_CRYPTOKI_H_
