/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "dm_constants.h"
#include "device_manager_impl.h"

namespace {
    bool g_mockInitDeviceManager = true;
    bool g_mockRegisterDevStateCallback = true;
    bool g_mockGetLocalDeviceRet = true;
    bool g_mockGetTrustedDeviceList = true;
}

void MockInitDeviceManager(bool mockRet)
{
    g_mockInitDeviceManager = mockRet;
}

void MockRegisterDevStateCallback(bool mockRet)
{
    g_mockRegisterDevStateCallback = mockRet;
}

void MockGetLocalDevice(bool mockRet)
{
    g_mockGetLocalDeviceRet = mockRet;
}

void MockGetTrustedDeviceList(bool mockRet)
{
    g_mockGetTrustedDeviceList = mockRet;
}

namespace OHOS {
namespace DistributedHardware {
int32_t DeviceManagerImpl::InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback)
{
    if (false == g_mockInitDeviceManager) {
        return DM_OK;
    }
    return ERR_DM_INPUT_PARA_INVALID;
}

int32_t DeviceManagerImpl::RegisterDevStateCallback(const std::string &pkgName, const std::string &extra,
    std::shared_ptr<DeviceStateCallback> callback)
{
    if (false == g_mockRegisterDevStateCallback) {
        return DM_OK;
    }
    return ERR_DM_INPUT_PARA_INVALID;
}

int32_t DeviceManagerImpl::GetLocalDeviceInfo(const std::string &pkgName, DmDeviceInfo &info)
{
    if (false == g_mockGetLocalDeviceRet) {
        return DM_OK;
    }
    return ERR_DM_INPUT_PARA_INVALID;
}

int32_t DeviceManagerImpl::GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
                                                std::vector<DmDeviceInfo> &deviceList)
{
    if (false == g_mockGetTrustedDeviceList) {
        return DM_OK;
    }
    return ERR_DM_INPUT_PARA_INVALID;
}
} // namespace DistributedHardware
} // namespace OHOS
