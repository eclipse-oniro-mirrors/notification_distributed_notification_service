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

#include "distributed_device_status.h"

namespace OHOS {
namespace Notification {
DistributedDeviceStatus::DistributedDeviceStatus() = default;

DistributedDeviceStatus::~DistributedDeviceStatus() = default;

ErrCode DistributedDeviceStatus::SetDeviceStatus(const std::string &deviceType, const uint32_t status)
{
    deviceStatus_.EnsureInsert(deviceType, status);
    return ERR_OK;
}

uint32_t DistributedDeviceStatus::GetDeviceStatus(const std::string &deviceType)
{
    return deviceStatus_.ReadVal(deviceType);
}
} // namespace Notification
} // namespace OHOS
