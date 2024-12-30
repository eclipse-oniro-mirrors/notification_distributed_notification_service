/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_DISTRIBUTED_DEVICE_MANAGER_H
#define NOTIFICATION_DISTRIBUTED_DEVICE_MANAGER_H

#include "device_manager_callback.h"

namespace OHOS {
namespace Notification {
using namespace DistributedHardware;

class DmsInitCallback : public DmInitCallback {
public:
    void OnRemoteDied() override;
};

class DmsStateCallback : public DeviceStateCallback {
public:
    void OnDeviceOnline(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const DmDeviceInfo &deviceInfo) override;
};

class DistributedDeviceManager {
public:
    void Init();
    void RegisterDms();
    static DistributedDeviceManager& GetInstance();
private:
    std::shared_ptr<DmsInitCallback> initCallback_;
    std::shared_ptr<DmsStateCallback> stateCallback_;
};

}
}
#endif // NOTIFICATION_DISTRIBUTED_DEVICE_MANAGER_H
