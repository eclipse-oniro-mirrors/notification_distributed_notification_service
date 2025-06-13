/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "device_manager_impl.h"

#include "mock_device_manager_impl.h"
namespace OHOS {

namespace Notification {
static std::shared_ptr<DistributedHardware::DeviceStateCallback> deviceManagerCallback = nullptr;

void DeviceTrigger::TriggerDeviceOnline()
{
    DistributedHardware::DmDeviceInfo remoteDevice;
    memset_s(&remoteDevice, sizeof(remoteDevice), 0, sizeof(remoteDevice));
    strcpy_s(remoteDevice.deviceId, sizeof(remoteDevice.deviceId) - 1, "remoteDeviceId");
    strcpy_s(remoteDevice.networkId, sizeof(remoteDevice.networkId) - 1, "remoteNetWorkId");
    remoteDevice.deviceTypeId = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    deviceManagerCallback->OnDeviceOnline(remoteDevice);
}

void DeviceTrigger::TriggerDeviceOffline()
{
    DistributedHardware::DmDeviceInfo remoteDevice;
    memset_s(&remoteDevice, sizeof(remoteDevice), 0, sizeof(remoteDevice));
    strcpy_s(remoteDevice.deviceId, sizeof(remoteDevice.deviceId) - 1, "remoteDeviceId");
    strcpy_s(remoteDevice.networkId, sizeof(remoteDevice.networkId) - 1, "remoteNetWorkId");
    deviceManagerCallback->OnDeviceOffline(remoteDevice);
}

void DeviceTrigger::TriggerDeviceChanged()
{
    DistributedHardware::DmDeviceInfo remoteDevice;
    memset_s(&remoteDevice, sizeof(remoteDevice), 0, sizeof(remoteDevice));
    strcpy_s(remoteDevice.deviceId, sizeof(remoteDevice.deviceId) - 1, "remoteDeviceId");
    strcpy_s(remoteDevice.networkId, sizeof(remoteDevice.networkId) - 1, "newRemoteNetWorkId");
    deviceManagerCallback->OnDeviceChanged(remoteDevice);
}

void DeviceTrigger::TriggerDeviceReady()
{
    DistributedHardware::DmDeviceInfo remoteDevice;
    deviceManagerCallback->OnDeviceReady(remoteDevice);
}
}

namespace DistributedHardware {

DeviceManagerImpl &DeviceManagerImpl::GetInstance()
{
    static DeviceManagerImpl deviceManagerImpl;
    return deviceManagerImpl;
}

int32_t DeviceManagerImpl::InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback)
{
    (void)dmInitCallback;
    printf("InitDeviceManager pkgName:%s\n", pkgName.c_str());
    return 0;
}

int32_t DeviceManagerImpl::UnInitDeviceManager(const std::string &pkgName)
{
    printf("UnInitDeviceManager pkgName:%s\n", pkgName.c_str());
    return 0;
}

int32_t DeviceManagerImpl::GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
                                                std::vector<DmDeviceInfo> &deviceList)
{
    DmDeviceInfo remoteDevice;
    memset_s(&remoteDevice, sizeof(remoteDevice), 0, sizeof(remoteDevice));
    strcpy_s(remoteDevice.deviceId, sizeof(remoteDevice.deviceId) - 1, "remoteDeviceId");
    strcpy_s(remoteDevice.deviceName, sizeof(remoteDevice.deviceName) - 1, "remoteDeviceId");
    remoteDevice.deviceTypeId = DmDeviceType::DEVICE_TYPE_WATCH;
    deviceList.push_back(remoteDevice);
    return 0;
}

int32_t DeviceManagerImpl::GetTrustedDeviceList(
    const std::string &pkgName, const std::string &extra, bool isRefresh, std::vector<DmDeviceInfo> &deviceList)
{
    DmDeviceInfo remoteDevice;
    memset_s(&remoteDevice, sizeof(remoteDevice), 0, sizeof(remoteDevice));
    strcpy_s(remoteDevice.deviceId, sizeof(remoteDevice.deviceId) - 1, "remoteDeviceId");
    strcpy_s(remoteDevice.deviceName, sizeof(remoteDevice.deviceName) - 1, "remoteDeviceId");
    remoteDevice.deviceTypeId = DmDeviceType::DEVICE_TYPE_WATCH;
    deviceList.push_back(remoteDevice);
    return 0;
}

int32_t DeviceManagerImpl::GetLocalDeviceInfo(const std::string &pkgName, DmDeviceInfo &deviceInfo)
{
    memset_s(&deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    strcpy_s(deviceInfo.deviceId, sizeof(deviceInfo.deviceId) - 1, "localDeviceId");
    strcpy_s(deviceInfo.deviceName, sizeof(deviceInfo.deviceName) - 1, "localDeviceName");
    deviceInfo.deviceTypeId = DmDeviceType::DEVICE_TYPE_PHONE;
    return 0;
}

int32_t DeviceManagerImpl::RegisterDevStateCallback(const std::string &pkgName, const std::string &extra,
                                                    std::shared_ptr<DeviceStateCallback> callback)
{
    Notification::deviceManagerCallback = callback;
    return 0;
}

int32_t DeviceManagerImpl::UnRegisterDevStateCallback(const std::string &pkgName)
{
    Notification::deviceManagerCallback = nullptr;
    return 0;
}

int32_t DeviceManagerImpl::StartDeviceDiscovery(const std::string &pkgName, const DmSubscribeInfo &subscribeInfo,
                                                const std::string &extra, std::shared_ptr<DiscoveryCallback> callback)
{
    return 0;
}

int32_t DeviceManagerImpl::StopDeviceDiscovery(const std::string &pkgName, uint16_t subscribeId)
{
    return 0;
}

int32_t DeviceManagerImpl::PublishDeviceDiscovery(const std::string &pkgName, const DmPublishInfo &publishInfo,
    std::shared_ptr<PublishCallback> callback)
{
    return 0;
}

int32_t DeviceManagerImpl::UnPublishDeviceDiscovery(const std::string &pkgName, int32_t publishId)
{
    return 0;
}

int32_t DeviceManagerImpl::AuthenticateDevice(const std::string &pkgName, int32_t authType,
                                              const DmDeviceInfo &deviceInfo, const std::string &extra,
                                              std::shared_ptr<AuthenticateCallback> callback)
{
    return 0;
}

int32_t DeviceManagerImpl::UnAuthenticateDevice(const std::string &pkgName, const DmDeviceInfo &deviceInfo)
{
    return 0;
}

int32_t DeviceManagerImpl::RegisterDeviceManagerFaCallback(const std::string &pkgName,
                                                           std::shared_ptr<DeviceManagerUiCallback> callback)
{
    return 0;
}

int32_t DeviceManagerImpl::UnRegisterDeviceManagerFaCallback(const std::string &pkgName)
{
    return 0;
}

int32_t DeviceManagerImpl::VerifyAuthentication(const std::string &pkgName, const std::string &authPara,
                                                std::shared_ptr<VerifyAuthCallback> callback)
{
    return 0;
}

int32_t DeviceManagerImpl::GetFaParam(const std::string &pkgName, DmAuthParam &dmFaParam)
{
    return 0;
}

int32_t DeviceManagerImpl::SetUserOperation(const std::string &pkgName, int32_t action, const std::string &params)
{
    return 0;
}

int32_t DeviceManagerImpl::GetUdidByNetworkId(const std::string &pkgName, const std::string &netWorkId,
                                              std::string &udid)
{
    return 0;
}

int32_t DeviceManagerImpl::GetUuidByNetworkId(const std::string &pkgName, const std::string &netWorkId,
                                              std::string &uuid)
{
    return 0;
}

int32_t DeviceManagerImpl::RegisterDevStateCallback(const std::string &pkgName, const std::string &extra)
{
    return 0;
}

int32_t DeviceManagerImpl::UnRegisterDevStateCallback(const std::string &pkgName, const std::string &extra)
{
    return 0;
}

int32_t DeviceManagerImpl::RequestCredential(const std::string &pkgName, const std::string &reqJsonStr,
    std::string &returnJsonStr)
{
    return 0;
}

int32_t DeviceManagerImpl::ImportCredential(const std::string &pkgName, const std::string &credentialInfo)
{
    return 0;
}

int32_t DeviceManagerImpl::DeleteCredential(const std::string &pkgName, const std::string &deleteInfo)
{
    return 0;
}

int32_t DeviceManagerImpl::RegisterCredentialCallback(const std::string &pkgName,
    std::shared_ptr<CredentialCallback> callback)
{
    return 0;
}

int32_t DeviceManagerImpl::UnRegisterCredentialCallback(const std::string &pkgName)
{
    return 0;
}

int32_t DeviceManagerImpl::NotifyEvent(const std::string &pkgName, const int32_t eventId, const std::string &event)
{
    return 0;
}

int32_t DeviceManagerImpl::OnDmServiceDied()
{
    return 0;
}
} // namespace DistributedHardware
} // namespace OHOS
