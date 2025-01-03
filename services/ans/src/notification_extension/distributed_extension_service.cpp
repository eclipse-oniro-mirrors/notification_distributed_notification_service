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

#include "distributed_extension_service.h"

#include "ans_log_wrapper.h"
#include "notification_config_parse.h"

namespace OHOS {
namespace Notification {

using namespace DistributedHardware;

using DeviceCallback = std::function<bool(std::string, int32_t, bool)>;
typedef int32_t (*INIT_LOCAL_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    int32_t titleLength, int32_t contentLength, DeviceCallback callback);
typedef void (*RELEASE_LOCAL_DEVICE)();
typedef void (*ADD_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId);
typedef void (*RELEASE_DEVICE)(const std::string &deviceId, uint16_t deviceType);
typedef void (*REFRESH_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId);

namespace {
constexpr int32_t DEFAULT_TITLE_LENGTH = 200;
constexpr int32_t DEFAULT_CONTENT_LENGTH = 400;
constexpr uint64_t IDEL_TASK_DELAY = 30 * 1000 * 1000;
constexpr char const APP_ID[] = "com.ohos.notification_service.3203";
constexpr const char* CFG_KEY_DISTRIBUTED = "distribuedConfig";
constexpr const char* CFG_KEY_LOCAL_TYPE = "localType";
constexpr const char* CFG_KEY_SUPPORT_DEVICES = "supportPeerDevice";
constexpr const char* CFG_KEY_TITLE_LENGTH = "maxTitleLength";
constexpr const char* CFG_KEY_CONTENT_LENGTH = "maxContentLength";
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

    nlohmann::json titleJson = configJson[CFG_KEY_TITLE_LENGTH];
    if (titleJson.is_null() || titleJson.empty() || !titleJson.is_number_integer()) {
        deviceConfig_.maxTitleLength = DEFAULT_TITLE_LENGTH;
    } else {
        deviceConfig_.maxTitleLength = titleJson.get<int32_t>();
        ANS_LOGI("Dans initConfig title length %{public}d.", deviceConfig_.maxTitleLength);
    }

    nlohmann::json contentJson = configJson[CFG_KEY_CONTENT_LENGTH];
    if (contentJson.is_null() || contentJson.empty() || !contentJson.is_number_integer()) {
        deviceConfig_.maxContentLength = DEFAULT_CONTENT_LENGTH;
    } else {
        deviceConfig_.maxContentLength = contentJson.get<int32_t>();
        ANS_LOGI("Dans initConfig content length %{public}d.", deviceConfig_.maxContentLength);
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

    ANS_LOGI("Dans get local device %{public}s, %{public}d, %{public}d, %{public}d.", deviceInfo.deviceId,
        deviceInfo.deviceTypeId, deviceConfig_.maxTitleLength, deviceConfig_.maxContentLength);
    if (handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceConfig_.maxTitleLength,
        deviceConfig_.maxContentLength, std::bind(&DistributedExtensionService::DeviceStatusCallback, this,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)) != 0) {
        dansRunning_.store(false);
        return -1;
    }
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

void DistributedExtensionService::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    std::string name = TransDeviceTypeToName(deviceInfo.deviceTypeId);
    if (deviceConfig_.supportPeerDevice_.find(name) == deviceConfig_.supportPeerDevice_.end()) {
        return;
    }
    if (distributedQueue_ == nullptr) {
        return;
    }
    std::function<void()> onlineTask = std::bind([&, deviceInfo]() {
        if (InitDans() != 0) {
            ANS_LOGW("OnDeviceOnline init dans failed.");
            return;
        };

        ADD_DEVICE handler = (ADD_DEVICE)dansHandler_->GetProxyFunc("AddDevice");
        if (handler == nullptr) {
            ANS_LOGW("Dans handler is null ptr.");
            return;
        }
        std::lock_guard<std::mutex> lock(mapLock_);
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceInfo.networkId);
        DistributedDeviceInfo device = DistributedDeviceInfo(deviceInfo.deviceId, deviceInfo.deviceName,
            deviceInfo.networkId, deviceInfo.deviceTypeId);
        deviceMap_.insert(std::make_pair(deviceInfo.deviceId, device));
    });
    distributedQueue_->submit(onlineTask);
}

bool DistributedExtensionService::CheckAllDeviceOffLine()
{
    std::lock_guard<std::mutex> lock(mapLock_);
    for (auto& device : deviceMap_) {
        if (device.second.status_ == DeviceState::STATE_INIT ||
            device.second.status_ == DeviceState::STATE_ONLINE) {
            return false;
        }
    }
    return true;
}

bool DistributedExtensionService::DeviceStatusCallback(std::string deviceId, int32_t status,
    bool checkStatus)
{
    ANS_LOGI("Dans device status %{public}s, %{public}d, %{public}d.", deviceId.c_str(), status, checkStatus);
    if (!checkStatus) {
        std::lock_guard<std::mutex> lock(mapLock_);
        auto iter = deviceMap_.find(deviceId);
        if (iter != deviceMap_.end()) {
            iter->second.status_ = status;
        }
        return false;
    }

    bool release = CheckAllDeviceOffLine();
    std::function<void()> task = std::bind([&]() {
        if (CheckAllDeviceOffLine()) {
            ReleaseLocalDevice();
            dansHandler_.reset();
            dansRunning_.store(false);
        }
    });
    ANS_LOGI("Dans status %{public}s, %{public}d, %{public}d.", deviceId.c_str(), status, release);
    if (release) {
        distributedQueue_->submit(task);
    }
    return release;
}

void DistributedExtensionService::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    if (distributedQueue_ == nullptr) {
        return;
    }
    std::function<void()> offlineTask = std::bind([&, deviceInfo]() {
        std::lock_guard<std::mutex> lock(mapLock_);
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
    });
    distributedQueue_->submit(offlineTask);
}

void DistributedExtensionService::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    if (distributedQueue_ == nullptr) {
        return;
    }
    std::function<void()> changeTask = std::bind([&, deviceInfo]() {
        std::lock_guard<std::mutex> lock(mapLock_);
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