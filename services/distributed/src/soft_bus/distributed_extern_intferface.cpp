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

#include <dlfcn.h>
#include <cstdint>
#include <unordered_set>
#include <utility>

#define SYMBOL_EXPORT __attribute__ ((visibility("default")))
namespace OHOS {
namespace Notification {
#ifdef __cplusplus
extern "C" {
#endif

SYMBOL_EXPORT int32_t InitLocalDevice(const std::string &deviceId, uint16_t deviceType,
    std::pair<int32_t, int32_t> titleAndContentLength, std::unordered_set<std::string> collaborativeDeleteTypes,
    std::function<bool(std::string, int32_t, bool)> callback)
{
    return DistributedManager::GetInstance().InitLocalDevice(deviceId, deviceType, titleAndContentLength,
        collaborativeDeleteTypes, callback);
}

SYMBOL_EXPORT void AddDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    DistributedManager::GetInstance().AddDevice(deviceId, deviceType, networkId);
}

SYMBOL_EXPORT void ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    DistributedManager::GetInstance().ReleaseDevice(deviceId, deviceType);
}

SYMBOL_EXPORT void RefreshDevice(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId)
{
    DistributedManager::GetInstance().RefreshDevice(deviceId, deviceType, networkId);
}

SYMBOL_EXPORT void ReleaseLocalDevice()
{
    DistributedManager::GetInstance().ReleaseLocalDevice();
}

SYMBOL_EXPORT void InitHACallBack(
    std::function<void(int32_t, int32_t, uint32_t, std::string)> callback)
{
    DistributedManager::GetInstance().InitHACallBack(callback);
}

SYMBOL_EXPORT void InitSendReportCallBack(
    std::function<void(int32_t, int32_t, std::string)> callback)
{
    DistributedManager::GetInstance().InitSendReportCallBack(callback);
}

#ifdef __cplusplus
}
#endif
}  // namespace Notification
}  // namespace OHOS
