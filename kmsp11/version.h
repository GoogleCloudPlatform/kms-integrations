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

#ifndef KMSP11_VERSION_H_
#define KMSP11_VERSION_H_

#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

constexpr CK_VERSION kLibraryVersion = {1, 4};

}

#endif  // KMSP11_VERSION_H_
