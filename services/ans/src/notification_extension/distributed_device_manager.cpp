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

#include "distributed_device_manager.h"

#include "ans_log_wrapper.h"
#include "distributed_extension_service.h"

namespace OHOS {
namespace Notification {

namespace {
constexpr char const APP_ID[] = "com.ohos.notification_service.3203";
}

void DmsInitCallback::OnRemoteDied()
{
    ANS_LOGW("Dms on remote died.");
}

void DmsStateCallback::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    ANS_LOGI("AnsDevice online %{public}d, %{public}d, %{public}s, %{public}s", deviceInfo.deviceTypeId,
        deviceInfo.networkType, StringAnonymous(deviceInfo.deviceId).c_str(),
        StringAnonymous(deviceInfo.networkId).c_str());
    DistributedExtensionService::GetInstance().OnDeviceOnline(deviceInfo);
}

void DmsStateCallback::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    ANS_LOGI("AnsDevice offline %{public}d, %{public}d, %{public}s, %{public}s", deviceInfo.deviceTypeId,
        deviceInfo.networkType, StringAnonymous(deviceInfo.deviceId).c_str(),
        StringAnonymous(deviceInfo.networkId).c_str());
    DistributedExtensionService::GetInstance().OnDeviceOffline(deviceInfo);
}

void DmsStateCallback::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    ANS_LOGI("AnsDevice change %{public}d, %{public}d, %{public}s, %{public}s", deviceInfo.deviceTypeId,
        deviceInfo.networkType, StringAnonymous(deviceInfo.deviceId).c_str(),
        StringAnonymous(deviceInfo.networkId).c_str());
    DistributedExtensionService::GetInstance().OnDeviceChanged(deviceInfo);
}

void DmsStateCallback::OnDeviceReady(const DmDeviceInfo &deviceInfo)
{
    ANS_LOGI("AnsDevice ready %{public}d, %{public}d, %{public}s, %{public}s", deviceInfo.deviceTypeId,
        deviceInfo.networkType, StringAnonymous(deviceInfo.deviceId).c_str(),
        StringAnonymous(deviceInfo.networkId).c_str());
}

DistributedDeviceManager& DistributedDeviceManager::GetInstance()
{
    static DistributedDeviceManager distributedDeviceManager;
    return distributedDeviceManager;
}

void DistributedDeviceManager::InitTrustList()
{
    if (!RegisterDms(false)) {
        return;
    }
    std::vector<DmDeviceInfo> deviceInfoList;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(APP_ID, "",
        true, deviceInfoList);
    if (ret != 0) {
        ANS_LOGE("Get trust list failed, ret:%{public}d", ret);
        return;
    }
    for (auto& deviceInfo : deviceInfoList) {
        ANS_LOGI("AnsDevice trustlist %{public}d, %{public}d, %{public}s, %{public}s", deviceInfo.deviceTypeId,
            deviceInfo.networkType, StringAnonymous(deviceInfo.deviceId).c_str(),
            StringAnonymous(deviceInfo.networkId).c_str());
        DistributedExtensionService::GetInstance().OnDeviceOnline(deviceInfo);
    }
}

bool DistributedDeviceManager::RegisterDms(bool forceInit)
{
    if (hasInit.load() && !forceInit) {
        ANS_LOGE("init device manager has inited.");
        return true;
    }
    if (initCallback_ == nullptr) {
        initCallback_ = std::make_shared<DmsInitCallback>();
    }
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(APP_ID, initCallback_);
    if (ret != 0) {
        ANS_LOGE("init device manager failed, ret:%{public}d", ret);
        return false;
    }

    if (stateCallback_ == nullptr) {
        stateCallback_ = std::make_shared<DmsStateCallback>();
    }
    ret = DistributedHardware::DeviceManager::GetInstance().RegisterDevStateCallback(APP_ID, "", stateCallback_);
    if (ret != 0) {
        ANS_LOGE("register state callback failed, ret:%{public}d", ret);
        return false;
    }
    hasInit.store(true);
    ANS_LOGI("Notification distributed register dms successfully.");
    return true;
}
}
}
