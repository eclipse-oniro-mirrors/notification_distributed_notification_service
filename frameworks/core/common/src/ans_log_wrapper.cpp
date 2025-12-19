/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const int32_t MIN_DATA_LENGTH = 4;
constexpr const int32_t MAS_DISPLAY_DATA_LENGTH = 2;
constexpr const char* ANONYMOUS_STRING = "******";
}

std::string StringAnonymous(const std::string& data)
{
    if (data.empty()) {
        return data;
    }
    std::string result;
    if (data.length() <= MIN_DATA_LENGTH) {
        result = data.substr(0, 1) + ANONYMOUS_STRING;
    } else {
        result = data.substr(0, MAS_DISPLAY_DATA_LENGTH) + ANONYMOUS_STRING +
            data.substr(data.length() - MAS_DISPLAY_DATA_LENGTH);
    }
    return result;
}
}
}