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

#include "distributed_subscriber.h"

#include "ans_log_wrapper.h"
#include "distributed_service.h"
#include "notification_config_parse.h"
#include "distributed_preferences.h"
#include "distributed_local_config.h"
#include "distributed_device_service.h"

namespace OHOS {
namespace Notification {

DistribuedSubscriber::~DistribuedSubscriber()
{
}

void DistribuedSubscriber::OnDied()
{
    ANS_LOGW("Subscriber on died %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str());
}

void DistribuedSubscriber::OnConnected()
{
    ANS_LOGI("Subscriber on connected %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str());
}

void DistribuedSubscriber::OnDisconnected()
{
    ANS_LOGI("Subscriber on disconnected %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str());
}

void DistribuedSubscriber::OnCanceled(const std::shared_ptr<Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGI("Subscriber on canceled %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str());
    if (deleteReason == NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE ||
        deleteReason == NotificationConstant::DISTRIBUTED_ENABLE_CLOSE_DELETE ||
        deleteReason == NotificationConstant::DISTRIBUTED_RELEASE_DELETE) {
        ANS_LOGD("is cross device deletion");
        return;
    }

    if (CheckNeedCollaboration(request)) {
        DistributedService::GetInstance().OnCanceled(request, peerDevice_);
    }
}

void DistribuedSubscriber::OnConsumed(const std::shared_ptr<Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGI("Subscriber on consumed %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str());
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        ANS_LOGI("No need consumed notification %{public}d %{public}s.",
            localDevice_.deviceType_, StringAnonymous(localDevice_.deviceId_).c_str());
        return;
    }
    if (peerDevice_.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        DistributedService::GetInstance().OnConsumed(request, peerDevice_);
        return;
    }
    if (request == nullptr || request->GetNotificationRequestPoint() == nullptr) {
        return;
    }
    auto requestPoint = request->GetNotificationRequestPoint();
    auto params = requestPoint->GetExtendInfo();
    if (params == nullptr) {
        ANS_LOGI("Dans OnConsumed invalid extend info.");
        return;
    }
    std::string deviceId = params->GetStringParam("notification_collaboration_deviceId_" +
        DistributedDeviceService::DeviceTypeToTypeString(peerDevice_.deviceType_));
    if (deviceId.empty() || deviceId != peerDevice_.udid_) {
        ANS_LOGI("Dans OnConsumed invalid device %{public}s %{public}s.", StringAnonymous(deviceId).c_str(),
            StringAnonymous(peerDevice_.deviceId_).c_str());
        return;
    }
    DistributedService::GetInstance().OnConsumed(request, peerDevice_);
}

void DistribuedSubscriber::OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGI("Subscriber on update.");
}

void DistribuedSubscriber::OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
}

void DistribuedSubscriber::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData)
{
}

void DistribuedSubscriber::OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData)
{
}

void DistribuedSubscriber::OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
}

void DistribuedSubscriber::OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGI("Subscriber on batch canceled %{public}d %{public}s %{public}d %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str());
    if (deleteReason == NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE ||
        deleteReason == NotificationConstant::DISTRIBUTED_ENABLE_CLOSE_DELETE ||
        deleteReason == NotificationConstant::DISTRIBUTED_RELEASE_DELETE) {
        ANS_LOGD("is cross device deletion");
        return;
    }
    std::vector<std::shared_ptr<Notification>> notifications;
    for (auto notification : requestList) {
        if (CheckNeedCollaboration(notification)) {
            notifications.push_back(notification);
        }
    }
    if (!notifications.empty()) {
        DistributedService::GetInstance().OnBatchCanceled(notifications, peerDevice_);
    }
}

ErrCode DistribuedSubscriber::OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> &operationInfo)
{
    DistributedDeviceInfo operRespDevice;
    DistributedDeviceService::GetInstance().GetDeviceInfoByUdid(operationInfo->GetNotificationUdid(), operRespDevice);
    ANS_LOGI("Subscriber on response %{public}d %{public}s %{public}d %{public}s, OperRespDeviceId: %{public}s.",
        peerDevice_.deviceType_, StringAnonymous(peerDevice_.deviceId_).c_str(), localDevice_.deviceType_,
        StringAnonymous(localDevice_.deviceId_).c_str(), operRespDevice.deviceId_.c_str());
    if (operRespDevice.deviceId_.compare(peerDevice_.deviceId_) != 0) {
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return DistributedService::GetInstance().OnOperationResponse(operationInfo, peerDevice_);
}

void DistribuedSubscriber::OnApplicationInfoNeedChanged(const std::string& bundleName)
{
    ANS_LOGI("Notify changed %{public}s %{public}d.", bundleName.c_str(), localDevice_.deviceType_);
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }
    DistributedService::GetInstance().OnApplicationInfnChanged(bundleName);
}

void DistribuedSubscriber::SetLocalDevice(DistributedDeviceInfo localDevice)
{
    localDevice_ = localDevice;
}

void DistribuedSubscriber::SetPeerDevice(DistributedDeviceInfo peerDevice)
{
    peerDevice_ = peerDevice;
}

bool DistribuedSubscriber::CheckNeedCollaboration(const std::shared_ptr<Notification>& notification)
{
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or request is nullptr");
        return false;
    }
    if (!CheckCollaborativeRemoveType(notification->GetNotificationRequestPoint()->GetSlotType())) {
        ANS_LOGE("CheckCollaborativeRemoveType failed");
        return false;
    }
    return true;
}

bool DistribuedSubscriber::CheckCollaborativeRemoveType(const NotificationConstant::SlotType& slotType)
{
    auto type = SlotEnumToSring(slotType);
    if (type.empty()) {
        ANS_LOGW("slotType is undefine");
        return false;
    }

    auto localDeviceType = DistributedDeviceService::DeviceTypeToTypeString(localDevice_.deviceType_);
    auto peerDeviceType = DistributedDeviceService::DeviceTypeToTypeString(peerDevice_.deviceType_);
    if (localDeviceType.empty() || peerDeviceType.empty()) {
        ANS_LOGW("localDeviceType OR  localDeviceType null");
        return false;
    }

    if (!CheckTypeByCcmRule(type, localDeviceType, peerDeviceType)) {
        return false;
    }

    return true;
}

bool DistribuedSubscriber::CheckTypeByCcmRule(const std::string& slotType,
    const std::string& localDeviceType, const std::string& peerDeviceType)
{
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> deleteConfigDevice;
    DistributedLocalConfig::GetInstance().GetCollaborativeDeleteTypesByDevices(deleteConfigDevice);
    if (deleteConfigDevice.empty()) {
        ANS_LOGW("distributed delete ccm is undefined");
        return false;
    }

    auto peerdeleteConfigDeviceIt = deleteConfigDevice.find(localDeviceType);
    if (peerdeleteConfigDeviceIt == deleteConfigDevice.end()) {
        ANS_LOGW("peerdeleteConfigDevice err, local:%{public}s, per:%{public}s",
            localDeviceType.c_str(), peerDeviceType.c_str());
        return false;
    }

    auto peerdeleteConfigDevice = peerdeleteConfigDeviceIt->second;
    auto deleteSlotTypeListIt = peerdeleteConfigDevice.find(peerDeviceType);
    if (deleteSlotTypeListIt == peerdeleteConfigDevice.end()) {
        ANS_LOGW("deleteSlotTypeList err, local:%{public}s, per:%{public}s",
            localDeviceType.c_str(), peerDeviceType.c_str());
        return false;
    }

    auto deleteSlotTypeList = deleteSlotTypeListIt->second;
    if (deleteSlotTypeList.find(slotType) == deleteSlotTypeList.end()) {
        ANS_LOGD("deleteSlotTypeList no slottype:%{public}s, local:%{public}s, per:%{public}s",
            slotType.c_str(), localDeviceType.c_str(), peerDeviceType.c_str());
        return false;
    }

    return true;
}


std::string DistribuedSubscriber::SlotEnumToSring(const NotificationConstant::SlotType& slotType)
{
    std::string type;
    switch (slotType) {
        case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
            type = "SOCIAL_COMMUNICATION";
            break;
        case NotificationConstant::SlotType::SERVICE_REMINDER:
            type = "SERVICE_REMINDER";
            break;
        case NotificationConstant::SlotType::CONTENT_INFORMATION:
            type = "CONTENT_INFORMATION";
            break;
        case NotificationConstant::SlotType::OTHER:
            type = "OTHER";
            break;
        case NotificationConstant::SlotType::CUSTOM:
            type = "CUSTOM";
            break;
        case NotificationConstant::SlotType::LIVE_VIEW:
            type = "LIVE_VIEW";
            break;
        case NotificationConstant::SlotType::CUSTOMER_SERVICE:
            type = "CUSTOMER_SERVICE";
            break;
        case NotificationConstant::SlotType::EMERGENCY_INFORMATION:
            type = "EMERGENCY_INFORMATION";
            break;
        case NotificationConstant::SlotType::ILLEGAL_TYPE:
            type = "ILLEGAL_TYPE";
            break;
        default:
            break;
    }
    return type;
}
}
}
