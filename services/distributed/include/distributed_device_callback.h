/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_DISTRIBUTED_INCLUDE_DEVICE_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_DISTRIBUTED_INCLUDE_DEVICE_CALLBACK_H

#include <string>

#include "device_manager.h"
#include "dm_device_info.h"

namespace OHOS {
namespace Notification {
class DistributedDeviceCallback : public DistributedHardware::DeviceStateCallback {
public:
    /**
     * @brief Device connection status changed callback function structure.
     */
    struct IDeviceChange {
        std::function<void(const std::string &deviceId)> OnConnected;
        std::function<void(const std::string &deviceId)> OnDisconnected;
    };

    /**
     * @brief The constructor.
     *
     * @param callback Device connection status changed callback.
     */
    explicit DistributedDeviceCallback(const IDeviceChange &callback);

    /**
     * @brief The deconstructor.
     */
    virtual ~DistributedDeviceCallback();

private:
    void OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo) override;

    IDeviceChange callback_;
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_DISTRIBUTED_INCLUDE_DEVICE_CALLBACK_H