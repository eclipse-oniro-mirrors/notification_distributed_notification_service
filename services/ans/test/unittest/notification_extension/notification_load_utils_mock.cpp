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

#include "notifictaion_load_utils.h"

#include <map>
#include <dlfcn.h>
#include "distributed_data_define.h"
#include "ans_log_wrapper.h"
#include "mock_device_manager_impl.h"

namespace OHOS {
namespace Notification {

static bool g_notificationProxyValid = false;
static std::map<std::string, std::string> g_deviceList;

void DeviceCheck::ResetDeviceData()
{
    return g_deviceList.clear();
}

bool DeviceCheck::CheckDeviceOnline()
{
    return !g_deviceList.empty();
}

std::string DeviceCheck::GetDeviceNetworkId(std::string deviceId)
{
    if (g_deviceList.find(deviceId) == g_deviceList.end()) {
        return std::string();
    }
    return g_deviceList[deviceId];
}

int32_t InitLocalDevice(const std::string &deviceId, uint16_t deviceType,
    DistributedDeviceConfig config)
{
    return 0;
}

void AddDevice(const std::string &deviceId, const std::string &udid, uint16_t deviceType,
    const std::string &networkId)
{
    g_deviceList.insert({deviceId, networkId});
    return;
}

void DeviceStatusChange(const DeviceStatueChangeInfo& changeInfo)
{
    return;
}

void ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    g_deviceList.erase(deviceId);
    return;
}

void RefreshDevice(const std::string &deviceId, uint16_t deviceType, const std::string &networkId)
{
    if (g_deviceList.find(deviceId) == g_deviceList.end()) {
        return;
    }
    g_deviceList[deviceId] = networkId;
    return;
}

void ReleaseLocalDevice()
{
    return;
}

void InitHACallBack(std::function<void(int32_t, int32_t, uint32_t, std::string)> callback)
{
    return;
}

void InitSendReportCallBack(std::function<void(int32_t, int32_t, std::string)> callback)
{
    return;
}

NotificationLoadUtils::NotificationLoadUtils(const std::string& path) : path_(path)
{
    g_notificationProxyValid = true;
    return;
}

NotificationLoadUtils::~NotificationLoadUtils()
{
    g_notificationProxyValid = false;
    if (proxyHandle_ == nullptr) {
        return;
    }
    int result = dlclose(proxyHandle_);
    ANS_LOGI("Release symbol %{public}d, name: %{public}s", result, path_.c_str());
    proxyHandle_ = nullptr;
}

void* NotificationLoadUtils::GetProxyFunc(const std::string& func)
{
    if (func == "InitLocalDevice") {
        return (void*)&InitLocalDevice;
    }
    if (func == "InitSendReportCallBack") {
        return (void*)&InitSendReportCallBack;
    }
    if (func == "InitHACallBack") {
        return (void*)&InitHACallBack;
    }
    if (func == "ReleaseLocalDevice") {
        return (void*)&ReleaseLocalDevice;
    }
    if (func == "AddDevice") {
        return (void*)&AddDevice;
    }
    if (func == "ReleaseDevice") {
        return (void*)&ReleaseDevice;
    }
    if (func == "RefreshDevice") {
        return (void*)&RefreshDevice;
    }
    if (func == "DeviceStatusChange") {
        return (void*)&DeviceStatusChange;
    }
    return nullptr;
}

bool NotificationLoadUtils::IsValid()
{
    return g_notificationProxyValid;
}

}
}
