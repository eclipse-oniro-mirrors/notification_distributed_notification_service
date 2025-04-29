/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FUZZ_COMMON_BASE_H
#define FUZZ_COMMON_BASE_H

#include <iostream>
#include <string>
#include <vector>
#include "securec.h"
#include "fuzz_data.h"

extern "C" {
uint32_t GetU32Size();

uint32_t GetU32Data(const char* ptr);

char* ParseData(const uint8_t* data, size_t size);

void NativeTokenGet(const std::vector<std::string> &permissions);

void SystemHapTokenGet(const std::vector<std::string> &permissions);
}

#endif // FUZZ_COMMON_BASE_H
