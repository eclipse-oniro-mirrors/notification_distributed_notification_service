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

void DistributedManager::InitLocalDevice(const std::string &deviceId, uint16_t deviceType)
{
    DistributedService::GetInstance().initService(deviceId, deviceType);
    DistributedServer::GetInstance().InitServer(deviceId, deviceType);
}

void DistributedManager::AddDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    DistributedDeviceInfo peerDevice = DistributedDeviceInfo(deviceType, deviceId, networkId);
    DistributedClient::GetInstance().AddDevice(peerDevice);
    DistributedService::GetInstance().SubscribeNotifictaion(peerDevice);
    DistributedService::GetInstance().InitDeviceState(peerDevice);
}

void DistributedManager::ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    DistributedClient::GetInstance().ReleaseDevice(deviceId, deviceType);
    DistributedService::GetInstance().UnSubscribeNotifictaion(deviceId, deviceType);
}

void DistributedManager::RefreshDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    DistributedClient::GetInstance().RefreshDevice(deviceId, deviceType, networkId);
}

}
}
