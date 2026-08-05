/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include "securec.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
void NativeTokenGet(const std::vector<std::string> &permissions);

void NormalHapTokenGet();

void SystemHapTokenGet(const std::vector<std::string> &permissions);

void MockRandomToken(FuzzedDataProvider *fdp, const std::vector<std::string> &permissions);
}

#define ENSURE_ANS_SERVICE_CLEANED_AT_EXIT() \
    do { \
        auto _drain_svc = OHOS::Notification::AdvancedNotificationService::GetInstance(); \
        if (_drain_svc != nullptr) { _drain_svc->SelfClean(); } \
    } while(0)

#endif // FUZZ_COMMON_BASE_H