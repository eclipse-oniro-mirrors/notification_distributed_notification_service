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

#include "distributed_manager.h"

#include "distributed_server.h"
#include "distributed_client.h"
#include "distributed_service.h"
#include "distributed_local_config.h"
#include "ans_log_wrapper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {
DistributedManager::DistributedManager()
{
    DistributedClient::GetInstance();
    DistributedServer::GetInstance();
}

DistributedManager& DistributedManager::GetInstance()
{
    static DistributedManager distributedManager;
    return distributedManager;
}

void DistributedManager::ReleaseLocalDevice()
{
    DistributedServer::GetInstance().ReleaseServer();
}

int32_t DistributedManager::InitLocalDevice(const std::string &deviceId, uint16_t deviceType,
    int32_t titleLength, int32_t contentLength, std::function<bool(std::string, int32_t, bool)> callback)
{
    ANS_LOGI("InitLocalDevice %{public}s %{public}u.", deviceId.c_str(), deviceType);
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->InitExtentionWrapper();
    DistributedLocalConfig::GetInstance().SetLocalDevice(deviceId, deviceType, titleLength, contentLength);
    return DistributedService::GetInstance().InitService(deviceId, deviceType, callback);
}

void DistributedManager::AddDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    ANS_LOGI("InitLocalDevice %{public}s %{public}u %{public}s.", deviceId.c_str(), deviceType, networkId.c_str());
    DistributedDeviceInfo peerDevice = DistributedDeviceInfo(deviceType, deviceId, networkId);
    DistributedClient::GetInstance().AddDevice(peerDevice);
    DistributedService::GetInstance().AddDevice(peerDevice);
}

void DistributedManager::ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    ANS_LOGI("ReleaseDevice %{public}s %{public}u.", deviceId.c_str(), deviceType);
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->CloseExtentionWrapper();
    DistributedClient::GetInstance().ReleaseDevice(deviceId, deviceType);
    DistributedService::GetInstance().UnSubscribeNotifictaion(deviceId, deviceType);
}

void DistributedManager::RefreshDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    ANS_LOGI("RefreshDevice %{public}s %{public}u %{public}s.", deviceId.c_str(), deviceType, networkId.c_str());
    DistributedClient::GetInstance().RefreshDevice(deviceId, deviceType, networkId);
}

}
}
