/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "string_utils.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

void StringUtils::Split(const std::string &str, const std::string &splitFlag, std::vector<std::string> &res)
{
    if (str.empty()) {
        return;
    }
    std::string strs = str + splitFlag;
    size_t pos = strs.find(splitFlag);
    while (pos != strs.npos) {
        std::string temp = strs.substr(0, pos);
        res.push_back(temp);
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(splitFlag);
    }
}

}  // namespace Notification
}  // namespace OHOS