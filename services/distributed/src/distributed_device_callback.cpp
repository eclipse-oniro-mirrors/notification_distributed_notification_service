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

#include "distributed_device_callback.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
DistributedDeviceCallback::DistributedDeviceCallback(const IDeviceChange &callback) : callback_(callback)
{}
DistributedDeviceCallback::~DistributedDeviceCallback()
{}

void DistributedDeviceCallback::OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    ANS_LOGD("start");
    if (callback_.OnConnected) {
        ANS_LOGD("device is online");
        callback_.OnConnected(deviceInfo.deviceId);
    }
}

void DistributedDeviceCallback::OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    ANS_LOGD("start");
    if (callback_.OnConnected) {
        ANS_LOGD("device is offline");
        callback_.OnDisconnected(deviceInfo.deviceId);
    }
}

void DistributedDeviceCallback::OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    ANS_LOGD("device is changed");
}

void DistributedDeviceCallback::OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo)
{
    ANS_LOGD("device is ready");
}
}  // namespace Notification
}  // namespace OHOS
