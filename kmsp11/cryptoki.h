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

// The PKCS#11 v2.40 Errata 01 specification defines CK_GCM_PARAMS in chapter
// 2.12.3 without a ulIvBits member, but the PKCS#11 v2.40 Errata 01 headers
// define CK_GCM_PARAMS with ulIvBits. We support both, for compatibility. See
// https://github.com/Pkcs11Interop/Pkcs11Interop/issues/126#issuecomment-496687863
// for a more detailed explanation.
typedef struct CK_GCM_PARAMS_errata {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CK_GCM_PARAMS_errata;

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

#endif  // KMSP11_CRYPTOKI_H_
