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

#ifndef KMSP11_OPERATION_OPERATION_H_
#define KMSP11_OPERATION_OPERATION_H_

#include "absl/types/variant.h"
#include "kmsp11/operation/crypter_ops.h"
#include "kmsp11/operation/find.h"

namespace kmsp11 {

// Operation models an in progress stateful PKCS #11 operation.
using Operation = absl::variant<FindOp, DecryptOp, EncryptOp, SignOp, VerifyOp>;

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_OPERATION_H_
