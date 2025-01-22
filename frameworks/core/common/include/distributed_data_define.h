/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_COMMON_INCLUDE_DISTRIBUTED_DATA_DEFINE_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_COMMON_INCLUDE_DISTRIBUTED_DATA_DEFINE_H

#include <string>
#include <set>
#include <mutex>
#include <unordered_set>

namespace OHOS {
namespace Notification {

struct DistributedDeviceConfig {
    int32_t maxTitleLength;
    int32_t maxContentLength;
    uint32_t startAbilityTimeout;
    std::string localType;
    std::set<std::string> supportPeerDevice;
    std::unordered_set<std::string> collaborativeDeleteTypes;
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_COMMON_INCLUDE_DISTRIBUTED_DATA_DEFINE_H
