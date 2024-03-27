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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_DISTRIBUTED_DEVICE_STATUS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_DISTRIBUTED_DEVICE_STATUS_H

#include "errors.h"
#include "ans_log_wrapper.h"
#include <string>
#include <map>

namespace OHOS {
namespace Notification {
class DistributedDeviceStatus {
public:
    DistributedDeviceStatus();
    ~DistributedDeviceStatus();
    ErrCode setDeviceStatus(std::string deviceType, int status);

    int32_t getDeviceStatus(std::string deviceType);
private:
    std::map<std::string, int> deviceStatus_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_DISTRIBUTED_DEVICE_STATUS_H