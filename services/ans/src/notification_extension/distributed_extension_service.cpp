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
#include "event_report.h"
#include "notification_analytics_util.h"

#include <utility>

namespace OHOS {
namespace Notification {

using namespace DistributedHardware;

using DeviceCallback = std::function<bool(std::string, int32_t, bool)>;
typedef int32_t (*INIT_LOCAL_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    DistributedDeviceConfig config);
typedef void (*RELEASE_LOCAL_DEVICE)();
typedef void (*ADD_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId);
typedef void (*RELEASE_DEVICE)(const std::string &deviceId, uint16_t deviceType);
typedef void (*REFRESH_DEVICE)(const std::string &deviceId, uint16_t deviceType,
    const std::string &networkId);
typedef void (*CHANGE_STATUS)(const DeviceStatueChangeInfo& changeInfo);
typedef void (*INIT_HA_CALLBACK)(
    std::function<void(int32_t, int32_t, uint32_t, std::string)> callback);
typedef void (*INIT_SENDREPORT_CALLBACK)(
    std::function<void(int32_t, int32_t, std::string)> callback);

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
constexpr const char* CFG_KEY_REPLY_TIMEOUT = "operationReplyTimeout";
constexpr const int32_t PUBLISH_ERROR_EVENT_CODE = 0;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;
constexpr const int32_t ANS_CUSTOMIZE_CODE = 7;

constexpr int64_t DURATION_ONE_SECOND = 1000;  // 1s, millisecond
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
        ANS_LOGE("ffrt create failed!");
        return;
    }
}

DistributedExtensionService::~DistributedExtensionService()
{
    std::function<void()> task = std::bind([&]() {
        ReleaseLocalDevice();
        dansHandler_.reset();
        dansRunning_.store(false);
    });
    ANS_LOGI("Dans release.");
    ffrt::task_handle handler = distributedQueue_->submit_h(task);
    distributedQueue_->wait(handler);
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
        deviceConfig_.supportPeerDevice.insert(deviceJson.get<std::string>());
    }

    nlohmann::json titleJson = configJson[CFG_KEY_TITLE_LENGTH];
    if (titleJson.is_null() || titleJson.empty() || !titleJson.is_number_integer()) {
        deviceConfig_.maxTitleLength = DEFAULT_TITLE_LENGTH;
    } else {
        deviceConfig_.maxTitleLength = titleJson.get<int32_t>();
        ANS_LOGI("Dans initConfig title length %{public}d.", deviceConfig_.maxTitleLength);
    }

    SetMaxContentLength(configJson);
    SetOperationReplyTimeout(configJson);

    deviceConfig_.collaborativeDeleteTypes = NotificationConfigParse::GetInstance()->GetCollaborativeDeleteType();
    deviceConfig_.startAbilityTimeout = NotificationConfigParse::GetInstance()->GetStartAbilityTimeout();
    return true;
}

int32_t DistributedExtensionService::InitDans()
{
    if (dansRunning_.load() && dansHandler_ != nullptr && dansHandler_->IsValid()) {
        return 0;
    }
    dansHandler_ = std::make_shared<NotificationLoadUtils>("libdans.z.so");
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

    ANS_LOGI("Dans get local device %{public}s, %{public}d, %{public}d, %{public}d.",
        StringAnonymous(deviceInfo.deviceId).c_str(), deviceInfo.deviceTypeId,
        deviceConfig_.maxTitleLength, deviceConfig_.maxContentLength);
    if (handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceConfig_) != 0) {
        dansRunning_.store(false);
        return -1;
    }

    INIT_HA_CALLBACK haHandler = (INIT_HA_CALLBACK)dansHandler_->GetProxyFunc("InitHACallBack");
    if (haHandler != nullptr) {
        haHandler(std::bind(&DistributedExtensionService::HADotCallback, this, std::placeholders::_1,
        std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
    }

    INIT_SENDREPORT_CALLBACK sendHandler =
        (INIT_SENDREPORT_CALLBACK)dansHandler_->GetProxyFunc("InitSendReportCallBack");
    if (sendHandler != nullptr) {
        sendHandler(std::bind(&DistributedExtensionService::SendReportCallback, this, std::placeholders::_1,
        std::placeholders::_2, std::placeholders::_3));
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
    if (deviceConfig_.supportPeerDevice.find(name) == deviceConfig_.supportPeerDevice.end()) {
        ANS_LOGE("The current device type not support %{public}d.", deviceInfo.deviceTypeId);
        return;
    }
    if (distributedQueue_ == nullptr) {
        return;
    }
    std::function<void()> onlineTask = std::bind([&, deviceInfo]() {
        if (InitDans() != 0) {
            ANS_LOGE("OnDeviceOnline init dans failed.");
            return;
        };

        ADD_DEVICE handler = (ADD_DEVICE)dansHandler_->GetProxyFunc("AddDevice");
        if (handler == nullptr) {
            ANS_LOGE("Dans handler is null ptr.");
            return;
        }
        std::lock_guard<std::mutex> lock(mapLock_);
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceInfo.networkId);
        std::string reason = "deviceType: " + std::to_string(deviceInfo.deviceTypeId) +
            " ; deviceId: " + StringAnonymous(deviceInfo.deviceId) + " ; networkId: " +
            StringAnonymous(deviceInfo.networkId);
        HADotCallback(PUBLISH_ERROR_EVENT_CODE, 0, EventSceneId::SCENE_1, reason);
        DistributedDeviceInfo device = DistributedDeviceInfo(deviceInfo.deviceId, deviceInfo.deviceName,
            deviceInfo.networkId, deviceInfo.deviceTypeId);
        deviceMap_.insert(std::make_pair(deviceInfo.deviceId, device));
    });
    distributedQueue_->submit(onlineTask);
}

void DistributedExtensionService::HADotCallback(int32_t code, int32_t ErrCode, uint32_t branchId, std::string reason)
{
    ANS_LOGI("Dans ha callback %{public}d, %{public}d, %{public}s.", code, ErrCode, reason.c_str());
    if (code == PUBLISH_ERROR_EVENT_CODE) {
        if (reason.find("deviceType") != std::string::npos ||
            reason.find("ShutdownReason") != std::string::npos) {
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_21, branchId).Message(reason);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(message);
        } else {
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_20, branchId)
                                        .ErrorCode(ErrCode)
                                        .Message(reason);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(message);
        }
    } else if (code == DELETE_ERROR_EVENT_CODE) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_20, branchId)
                                    .DeleteReason(NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE)
                                    .ErrorCode(ErrCode)
                                    .Message(reason);
        NotificationAnalyticsUtil::ReportDeleteFailedEvent(message);
    } else if (code == ANS_CUSTOMIZE_CODE) {
        if (branchId == BRANCH_3) {
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, branchId)
                                        .ClickByWatch()
                                        .SlotType(ErrCode);
            NotificationAnalyticsUtil::ReportOperationsDotEvent(message);
        } else if (branchId == BRANCH_4) {
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, branchId)
                                        .ReplyByWatch()
                                        .SlotType(ErrCode);
            NotificationAnalyticsUtil::ReportOperationsDotEvent(message);
        } else {
            bool isLiveView = false;
            if (ErrCode == NotificationConstant::SlotType::LIVE_VIEW) {
                isLiveView = true;
            }
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, branchId)
                                        .DelByWatch(isLiveView)
                                        .SlotType(ErrCode);
            NotificationAnalyticsUtil::ReportOperationsDotEvent(message);
        }
    } else if (code == MODIFY_ERROR_EVENT_CODE) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_20, branchId)
                                    .ErrorCode(ErrCode)
                                    .Message(reason);
        NotificationAnalyticsUtil::ReportSkipFailedEvent(message);
    }
}

void DistributedExtensionService::SendReportCallback(
    int32_t messageType, int32_t errCode, std::string reason)
{
    EventInfo eventInfo;
    eventInfo.messageType = messageType;
    eventInfo.errCode = errCode;
    eventInfo.reason = reason;
    EventReport::SendHiSysEvent(EVENT_NOTIFICATION_ERROR, eventInfo);
}

void DistributedExtensionService::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    if (distributedQueue_ == nullptr) {
        return;
    }
    std::function<void()> offlineTask = std::bind([&, deviceInfo]() {
        std::lock_guard<std::mutex> lock(mapLock_);
        if (deviceMap_.count(deviceInfo.deviceId) == 0) {
            ANS_LOGE("Not target device %{public}s", StringAnonymous(deviceInfo.deviceId).c_str());
            return;
        }
        if (!dansRunning_.load() || dansHandler_ == nullptr || !dansHandler_->IsValid()) {
            ANS_LOGE("Dans state not normal %{public}d", dansRunning_.load());
            return;
        }
        RELEASE_DEVICE handler = (RELEASE_DEVICE)dansHandler_->GetProxyFunc("ReleaseDevice");
        if (handler == nullptr) {
            ANS_LOGE("Dans handler is null ptr.");
            return;
        }
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId);
        std::string reason = "deviceType: " + std::to_string(deviceInfo.deviceTypeId) +
                             " ; deviceId: " + StringAnonymous(deviceInfo.deviceId);
        HADotCallback(PUBLISH_ERROR_EVENT_CODE, 0, EventSceneId::SCENE_2, reason);
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
            ANS_LOGE("Not target device %{public}s", StringAnonymous(deviceInfo.deviceId).c_str());
            return;
        }
        if (!dansRunning_.load() || dansHandler_ == nullptr || !dansHandler_->IsValid()) {
            ANS_LOGE("Dans state not normal %{public}d", dansRunning_.load());
            return;
        }
        REFRESH_DEVICE handler = (REFRESH_DEVICE)dansHandler_->GetProxyFunc("RefreshDevice");
        if (handler == nullptr) {
            ANS_LOGE("Dans handler is null ptr.");
            return;
        }
        handler(deviceInfo.deviceId, deviceInfo.deviceTypeId, deviceInfo.networkId);
        std::string reason = "deviceType: " + std::to_string(deviceInfo.deviceTypeId) +
            " deviceId: " + StringAnonymous(deviceInfo.deviceId) + " networkId: " +
            StringAnonymous(deviceInfo.networkId);
        HADotCallback(PUBLISH_ERROR_EVENT_CODE, 0, EventSceneId::SCENE_3, reason);
        ANS_LOGI("Dans refresh %{public}s %{public}s.", StringAnonymous(deviceInfo.deviceId).c_str(),
            StringAnonymous(deviceInfo.networkId).c_str());
    });
    distributedQueue_->submit(changeTask);
}

void DistributedExtensionService::DeviceStatusChange(const DeviceStatueChangeInfo& changeInfo)
{
    if (distributedQueue_ == nullptr) {
        return;
    }
    std::function<void()> changeTask = std::bind([&, changeInfo]() {
        if (!dansRunning_.load() || dansHandler_ == nullptr || !dansHandler_->IsValid()) {
            ANS_LOGE("Dans state not normal %{public}d", dansRunning_.load());
            return;
        }
        CHANGE_STATUS handler = (CHANGE_STATUS)dansHandler_->GetProxyFunc("DeviceStatusChange");
        if (handler == nullptr) {
            ANS_LOGE("Dans handler is null ptr.");
            return;
        }
        handler(changeInfo);
        ANS_LOGI("Dans statuc change %{public}s %{public}d %{public}d %{public}d.",
            StringAnonymous(changeInfo.deviceId).c_str(), changeInfo.changeType, changeInfo.enableChange,
            changeInfo.liveViewChange);
    });
    distributedQueue_->submit(changeTask);
}

int32_t DistributedExtensionService::GetOperationReplyTimeout()
{
    return deviceConfig_.operationReplyTimeout * DURATION_ONE_SECOND;
}

void DistributedExtensionService::SetOperationReplyTimeout(nlohmann::json &configJson)
{
    nlohmann::json contentJson = configJson[CFG_KEY_REPLY_TIMEOUT];
    if (contentJson.is_null() || contentJson.empty() || !contentJson.is_number_integer()) {
        deviceConfig_.operationReplyTimeout = DEFAULT_REPLY_TIMEOUT;
    } else {
        deviceConfig_.operationReplyTimeout = contentJson.get<int32_t>();
        ANS_LOGI("Dans initConfig reply timeout %{public}d.", deviceConfig_.operationReplyTimeout);
    }
}

void DistributedExtensionService::SetMaxContentLength(nlohmann::json &configJson)
{
    nlohmann::json contentJson = configJson[CFG_KEY_CONTENT_LENGTH];
    if (contentJson.is_null() || contentJson.empty() || !contentJson.is_number_integer()) {
        deviceConfig_.maxContentLength = DEFAULT_CONTENT_LENGTH;
    } else {
        deviceConfig_.maxContentLength = contentJson.get<int32_t>();
        ANS_LOGI("Dans initConfig content length %{public}d.", deviceConfig_.maxContentLength);
    }
}
}
}
