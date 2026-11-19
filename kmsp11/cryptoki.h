/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

// ML-DSA (FIPS 204) definitions from PKCS #11 v3.2.
//
// The library is built against the v2.40 headers and exposes the v2.40
// function list, but supports the v3.2 ML-DSA key type and mechanisms. The
// values below are copied verbatim from the OASIS v3.2 pkcs11t.h:
// https://github.com/oasis-tcs/pkcs11/blob/master/published/3-02/pkcs11t.h
#ifndef CKK_ML_DSA
#define CKK_ML_DSA 0x0000004aUL

#define CKA_PARAMETER_SET 0x0000061dUL
#define CKA_SEED 0x00000637UL

#define CKM_ML_DSA_KEY_PAIR_GEN 0x0000001cUL
#define CKM_ML_DSA 0x0000001dUL

typedef CK_ULONG CK_HEDGE_TYPE;
#define CKH_HEDGE_PREFERRED 0x00000000UL
#define CKH_HEDGE_REQUIRED 0x00000001UL
#define CKH_DETERMINISTIC_REQUIRED 0x00000002UL

typedef struct CK_SIGN_ADDITIONAL_CONTEXT {
  CK_HEDGE_TYPE hedgeVariant;
  CK_BYTE_PTR pContext;
  CK_ULONG ulContextLen;
} CK_SIGN_ADDITIONAL_CONTEXT;

typedef CK_ULONG CK_ML_DSA_PARAMETER_SET_TYPE;
#define CKP_ML_DSA_44 0x00000001UL
#define CKP_ML_DSA_65 0x00000002UL
#define CKP_ML_DSA_87 0x00000003UL
#endif  // CKK_ML_DSA

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

#endif  // KMSP11_CRYPTOKI_H_
