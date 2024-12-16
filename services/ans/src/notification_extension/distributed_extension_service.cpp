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

#include "distributed_extension_service.h"

#include "ans_log_wrapper.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {

using namespace DistributedHardware;

typedef void (*INIT_LOCAL_DEVICE)(const std::string &deviceId, uint16_t deviceType);
typedef void (*RELEASE_LOCAL_DEVICE)();
typedef void (*ADD_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId);
typedef void (*RELEASE_DEVICE)(const std::string &deviceId, uint16_t deviceType);
typedef void (*REFRESH_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId);

namespace {
constexpr uint64_t IDEL_TASK_DELAY = 30 * 1000 * 1000;
constexpr char const APP_ID[] = "com.ohos.notification_service.3203";
constexpr const char* CFG_KEY_DISTRIBUTED = "distribuedConfig";
constexpr const char* CFG_KEY_LOCAL_TYPE = "localType";
constexpr const char* CFG_KEY_SUPPORT_DEVICES = "supportPeerDevice";
}

std::string TransDeviceTypeToName(uint16_t deviceType_)
{
    switch (deviceType_) {
        case DmDeviceType::DEVICE_TYPE_WATCH: {
            return "Watch";
        }
        case DmDeviceType::DEVICE_TYPE_PAD: {
            return "Pad";
        }
        case DmDeviceType::DEVICE_TYPE_PHONE: {
            return "Phone";
        }
        default:
            return "";
    }
}

DistributedExtensionService& DistributedExtensionService::GetInstance()
{
    static DistributedExtensionService distributedExtensionService;
    return distributedExtensionService;
}

DistributedExtensionService::DistributedExtensionService()
{
    if (!initConfig()) {
        return;
    }
    distributedQueue_ = std::make_shared<ffrt::queue>("ans_extension");
    if (distributedQueue_ == nullptr) {
        ANS_LOGW("ffrt create failed!");
        return;
    }
}

bool DistributedExtensionService::initConfig()
{
    nlohmann::json root;
    std::string jsonPoint = "/";
    jsonPoint.append(NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE);
    jsonPoint.append("/");
    jsonPoint.append(CFG_KEY_DISTRIBUTED);
    if (!NotificationConfigParse::GetInstance()->GetConfigJson(jsonPoint, root)) {
        return false;
    }

    if (root.find(NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("Dans initConfig failed as can not find notificationService.");
        return false;
    }

    nlohmann::json configJson = root[NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE][CFG_KEY_DISTRIBUTED];
    if (configJson.is_null() || configJson.empty()) {
        ANS_LOGE("Dans initConfig failed as invalid json.");
        return false;
    }

    nlohmann::json localTypeJson = configJson[CFG_KEY_LOCAL_TYPE];
    if (localTypeJson.is_null() || localTypeJson.empty()) {
        ANS_LOGE("Dans initConfig local type as invalid json.");
    } else {
        deviceConfig_.localType = localTypeJson.get<std::string>();
        ANS_LOGI("Dans initConfig local type %{public}s.", deviceConfig_.localType.c_str());
    }

    nlohmann::json supportJson = configJson[CFG_KEY_SUPPORT_DEVICES];
    if (supportJson.is_null() || supportJson.empty() || !supportJson.is_array()) {
        ANS_LOGE("Dans initConfig support type as invalid json.");
        return false;
    }

    for (auto &deviceJson : supportJson) {
        ANS_LOGI("Dans initConfig support type %{public}s.", deviceJson.get<std::string>().c_str());
        deviceConfig_.supportPeerDevice_.insert(deviceJson.get<std::string>());
    }
    return true;
}

int32_t DistributedExtensionService::InitDans()
{
    if (dansRunning_.load() && dansHandler_ != nullptr && dansHandler_->IsValid()) {
        return 0;
    }
    dansHandler_ = std::make_shared<NotificationLoadUtils>("libans_softbus_distributed.z.so");
    if (dansHandler_ == nullptr) {
        ANS_LOGW("Dans handler init failed.");
        return -1;
    }

    INIT_LOCAL_DEVICE handler = (INIT_LOCAL_DEVICE)dansHandler_->GetProxyFunc("InitLocalDevice");
    if (handler == nullptr) {
        ANS_LOGW("Dans init failed.");
        return -1;
    }

    DmDeviceInfo deviceInfo;
    int32_t result = DeviceManager::GetInstance().GetLocalDeviceInfo(APP_ID, deviceInfo);
    if (result != 0) {
        ANS_LOGW("Dans get local device failed.");
        return -1;
    }
    ANS_LOGI("Dans get local device %{public}s, %{public}d.", deviceInfo.deviceId, deviceInfo.deviceTypeId);
    handler(deviceInfo.deviceId, deviceInfo.deviceTypeId);
    dansRunning_.store(true);
    return 0;
}

int32_t DistributedExtensionService::ReleaseLocalDevice()
{
    if (!dansRunning_.load() || dansHandler_ == nullptr || !dansHandler_->IsValid()) {
        return 0;
    }

    RELEASE_LOCAL_DEVICE handler = (RELEASE_LOCAL_DEVICE)dansHandler_->GetProxyFunc("ReleaseLocalDevice");
    if (handler == nullptr) {
        ANS_LOGW("Dans release failed, handler is null.");
        return -1;
    }
    handler();
    ANS_LOGI("Dans release successfully.");
    return 0;
}

bool DistributedExtensionService::releaseSameDevice(const DmDeviceInfo &deviceInfo)
{
    for (auto& deviceItem : deviceMap_) {
        if (deviceItem.second.deviceType_ == deviceInfo.deviceTypeId) {
            if (dansHandler_ == nullptr) {
                return false;
            }
            RELEASE_DEVICE handler = (RELEASE_DEVICE)dansHandler_->GetProxyFunc("ReleaseDevice");
            if (handler == nullptr) {
                return false;
            }
            ANS_LOGI("Dans release repeat device %{public}d %{public}s.", deviceItem.second.deviceType_,
                deviceItem.second.deviceId_.c_str());
            handler(deviceItem.second.deviceId_, deviceItem.second.deviceType_);
            deviceMap_.erase(deviceItem.second.deviceId_);
        }
    }
    return true;
}

void DistributedExtensionService::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    std::string name = TransDeviceTypeToName(deviceInfo.deviceTypeId);
    if (deviceConfig_.supportPeerDevice_.find(name) == deviceConfig_.supportPeerDevice_.end()) {
        return;
    }
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> onlineTask = std::bind([&, deviceInfo]() {
        if (InitDans() != 0) {
            ANS_LOGW("OnDeviceOnline init dans failed.");
            return;
        };
        if (!releaseSameDevice(deviceInfo)) {
            return;
        }
        REFRESH_DEVICE handler = (REFRESH_DEVICE)dansHandler_->GetProxyFunc("AddDevice");
        if (handler == nullptr) {
            ANS_LOGW("Dans handler is null ptr.");
            return;
        }
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceInfo.networkId);
        DistributedDeviceInfo device = DistributedDeviceInfo(deviceInfo.deviceId, deviceInfo.deviceName,
            deviceInfo.networkId, deviceInfo.deviceTypeId);
        deviceMap_.insert(std::make_pair(deviceInfo.deviceId, device));
        idle_.store(false);
    });
    distributedQueue_->submit(onlineTask);
}

void DistributedExtensionService::CloseDans()
{
    idle_.store(true);
    std::function<void()> idleTask = std::bind([&]() {
        ANS_LOGI("Dans handler is relesse %{public}d.", idle_.load());
        if (idle_.load()) {
            ReleaseLocalDevice();
            dansHandler_.reset();
            idle_.store(false);
            dansRunning_.store(false);
        }
    });
    ANS_LOGI("Dans handler is releasing start.");
    distributedQueue_->submit(idleTask, ffrt::task_attr().name("idle").delay(IDEL_TASK_DELAY));
}

void DistributedExtensionService::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> offlineTask = std::bind([&, deviceInfo]() {
        if (deviceMap_.count(deviceInfo.deviceId) == 0) {
            ANS_LOGI("Not target device %{public}s", deviceInfo.deviceId);
            return;
        }
        if (!dansRunning_.load() || dansHandler_ == nullptr || !dansHandler_->IsValid()) {
            ANS_LOGW("Dans state not normal %{public}d", dansRunning_.load());
            return;
        }
        RELEASE_DEVICE handler = (RELEASE_DEVICE)dansHandler_->GetProxyFunc("ReleaseDevice");
        if (handler == nullptr) {
            ANS_LOGW("Dans handler is null ptr.");
            return;
        }
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId);
        deviceMap_.erase(deviceInfo.deviceId);
        if (!idle_.load() && deviceMap_.empty()) {
            CloseDans();
        }
    });
    distributedQueue_->submit(offlineTask);
}

void DistributedExtensionService::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    if (distributedQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> changeTask = std::bind([&, deviceInfo]() {
        if (deviceMap_.count(deviceInfo.deviceId) == 0) {
            ANS_LOGI("Not target device %{public}s", deviceInfo.deviceId);
            return;
        }
        if (!dansRunning_.load() || dansHandler_ == nullptr || !dansHandler_->IsValid()) {
            ANS_LOGW("Dans state not normal %{public}d", dansRunning_.load());
            return;
        }
        REFRESH_DEVICE handler = (REFRESH_DEVICE)dansHandler_->GetProxyFunc("RefreshDevice");
        if (handler == nullptr) {
            ANS_LOGW("Dans handler is null ptr.");
            return;
        }
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceInfo.networkId);
        ANS_LOGI("Dans refresh %{public}s %{public}s.", deviceInfo.deviceId, deviceInfo.networkId);
    });
    distributedQueue_->submit(changeTask);
}
}
}
