/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "distributed_publish_service.h"

#include <memory>
#include <string>
#include <sstream>

#include "request_box.h"
#include "remove_box.h"
#include "batch_remove_box.h"
#include "notification_sync_box.h"
#include "analytics_util.h"
#include "ans_image_util.h"
#include "distributed_client.h"
#include "notification_helper.h"
#include "in_process_call_wrapper.h"
#include "distributed_device_service.h"
#include "distributed_data_define.h"
#include "distributed_preference.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "bool_wrapper.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "distributed_subscribe_service.h"
#include "remove_all_distributed_box.h"
#include "bundle_resource_helper.h"
#include "distributed_service.h"
#include "distributed_send_adapter.h"

namespace OHOS {
namespace Notification {

static const std::string DISTRIBUTED_LABEL = "ans_distributed";
static const std::string EXTENDINFO_INFO_PRE = "notification_collaboration_";
static const std::string EXTENDINFO_FLAG = "flag";
static const std::string EXTENDINFO_USERID = "userId_";
static const std::string EXTENDINFO_APP_NAME = "app_name";
static const std::string EXTENDINFO_APP_LABEL = "app_label";
static const std::string EXTENDINFO_APP_ICON = "app_icon";
static const std::string EXTENDINFO_APP_INDEX = "app_index";
static const std::string EXTENDINFO_APP_UID = "app_uid";
static const std::string EXTENDINFO_DEVICE_USERID = "userId";
static const std::string EXTENDINFO_DEVICE_ID = "deviceId";
static const std::string EXTENDINFO_ENABLE_CHECK = "check";
static const std::string EXTENDINFO_DEVICETYPE = "deviceType";
static const std::string EXTENDINFO_LOCALTYPE = "localType";
static const uint32_t UNLOCKED_USED_FLAG = 3;

DistributedPublishService& DistributedPublishService::GetInstance()
{
    static DistributedPublishService distributedPublishService;
    return distributedPublishService;
}

void DistributedPublishService::RemoveNotification(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::string hashCode;
    int32_t slotType;
    NotificationRemoveBox removeBox = NotificationRemoveBox(boxMessage);
    removeBox.GetNotificationHashCode(hashCode);
    removeBox.GetNotificationSlotType(slotType);

    if (hashCode.empty()) {
        ANS_LOGW("dans remove hashCode empty");
        return;
    }
    std::string deviceId;
    removeBox.GetLocalDeviceId(deviceId);
#ifdef DISTRIBUTED_FEATURE_MASTER
    std::shared_ptr<NotificationRemoveBox> forwardBox = MakeRemvoeBox(hashCode, slotType);
    if (forwardBox != nullptr) {
        ForWardRemove(forwardBox, deviceId);
    }
#else
#endif
    std::vector<std::string> hashCodes;
    hashCodes.push_back(hashCode);

    int result = RemoveDistributedNotifications(hashCodes);
    std::string errorReason = "delete message failed";
    if (result == 0) {
        errorReason = "delete message success";
        int32_t deviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
        DistributedDeviceInfo device;
        if (DistributedDeviceService::GetInstance().GetDeviceInfo(deviceId, device)) {
            deviceType = device.deviceType_;
        }
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH4_ID, errorReason);
        AnalyticsUtil::GetInstance().OperationalReporting(deviceType, HaOperationType::COLLABORATE_DELETE, slotType);
    } else {
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH3_ID, errorReason);
    }
    ANS_LOGI("dans remove message %{public}d.", result);
}

void DistributedPublishService::RemoveNotifications(const std::shared_ptr<TlvBox>& boxMessage)
{
    BatchRemoveNotificationBox removeBox = BatchRemoveNotificationBox(boxMessage);
    std::vector<std::string> hashCodes;
    std::string hashCodesString;
    removeBox.GetNotificationHashCodes(hashCodesString);
    if (hashCodesString.empty()) {
        ANS_LOGW("dans remove hashCodesString empty");
        return;
    }
    std::string slotTypesString;
    removeBox.GetNotificationSlotTypes(slotTypesString);
    std::istringstream hashCodesStream(hashCodesString);
    std::string hashCode;
    while (hashCodesStream >> hashCode) {
        if (!hashCode.empty()) {
            hashCodes.push_back(hashCode);
        }
    }
    std::string deviceId;
    removeBox.GetLocalDeviceId(deviceId);
#ifdef DISTRIBUTED_FEATURE_MASTER
    std::shared_ptr<BatchRemoveNotificationBox> forwardBox = MakeBatchRemvoeBox(hashCodes, slotTypesString);
    if (forwardBox != nullptr) {
        ForWardRemove(forwardBox, deviceId);
    }
#else
#endif

    int result = RemoveDistributedNotifications(hashCodes);
    BatchRemoveReport(slotTypesString, deviceId, result);
    ANS_LOGI("dans br re:%{public}d., hs:%{public}s", result, hashCodesString.c_str());
}

int DistributedPublishService::RemoveDistributedNotifications(const std::vector<std::string>& hashcodes)
{
    int res = 0;
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    if (local.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        res = IN_PROCESS_CALL(NotificationHelper::RemoveNotifications(
            hashcodes, NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
    } else {
        res = IN_PROCESS_CALL(NotificationHelper::RemoveDistributedNotifications(hashcodes,
            NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
            NotificationConstant::DistributedDeleteType::HASHCODES,
            NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
    }
    return res;
}

void DistributedPublishService::BatchRemoveReport(const std::string &slotTypesString, const std::string &deviceId,
    const int result)
{
    int32_t deviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    DistributedDeviceInfo device;
    if (DistributedDeviceService::GetInstance().GetDeviceInfo(deviceId, device)) {
        deviceType = device.deviceType_;
    }
    if (result == 0) {
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH4_ID,
            "delete message success");
        std::istringstream slotTypesStream(slotTypesString);
        std::string slotTypeString;
        while (slotTypesStream >> slotTypeString) {
            if (!slotTypeString.empty()) {
                AnalyticsUtil::GetInstance().OperationalReporting(deviceType,
                    HaOperationType::COLLABORATE_DELETE, atoi(slotTypeString.c_str()));
            }
        }
    } else {
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH3_ID,
            "delete message failed");
    }
}

void DistributedPublishService::OnRemoveNotification(const DistributedDeviceInfo& peerDevice,
    std::string hashCode, int32_t slotTypes)
{
    std::shared_ptr<NotificationRemoveBox> removeBox = std::make_shared<NotificationRemoveBox>();
    if (removeBox == nullptr) {
        ANS_LOGE("create batchRemoveBox err");
        return;
    }

    ANS_LOGI("dans OnCanceled %{public}s", hashCode.c_str());
    removeBox->SetNotificationHashCode(hashCode);
    removeBox->SetNotificationSlotType(slotTypes);
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    removeBox->SetLocalDeviceId(local.deviceId_);

    if (!removeBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return;
    }
    TransDataType dataType = TransDataType::DATA_TYPE_MESSAGE;
    if (peerDevice.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        dataType = TransDataType::DATA_TYPE_BYTES;
    }
    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(removeBox, peerDevice,
            dataType, DELETE_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
}

void DistributedPublishService::OnRemoveNotifications(const DistributedDeviceInfo& peerDevice,
    std::string hashCodes, std::string slotTypes)
{
    std::shared_ptr<BatchRemoveNotificationBox> batchRemoveBox = std::make_shared<BatchRemoveNotificationBox>();
    if (batchRemoveBox == nullptr) {
        ANS_LOGE("create batchRemoveBox err");
        return;
    }
    batchRemoveBox->SetNotificationHashCodes(hashCodes);
    batchRemoveBox->SetNotificationSlotTypes(slotTypes);
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    batchRemoveBox->SetLocalDeviceId(local.deviceId_);

    if (!batchRemoveBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return;
    }
    TransDataType dataType = TransDataType::DATA_TYPE_MESSAGE;
    if (peerDevice.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        dataType = TransDataType::DATA_TYPE_BYTES;
    }
    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(batchRemoveBox, peerDevice,
        dataType, DELETE_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
}

#ifdef DISTRIBUTED_FEATURE_MASTER
void DistributedPublishService::RemoveAllDistributedNotifications(DistributedDeviceInfo& deviceInfo)
{
    std::shared_ptr<RemoveAllDistributedNotificationsBox> removeBox =
        std::make_shared<RemoveAllDistributedNotificationsBox>();
    if (removeBox == nullptr) {
        ANS_LOGW("create box error");
        return;
    }
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    removeBox->SetLocalDeviceId(local.deviceId_);

    if (!removeBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return;
    }
    ANS_LOGI("Remove all:%{public}s", StringAnonymous(deviceInfo.deviceId_).c_str());
    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(removeBox, deviceInfo,
        TransDataType::DATA_TYPE_BYTES, DELETE_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
}

bool DistributedPublishService::ForWardRemove(const std::shared_ptr<BoxBase>& boxMessage,
    std::string& deviceId)
{
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    if (local.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        ANS_LOGD("no need forward");
        return false;
    }
    std::map<std::string, DistributedDeviceInfo> peerDevices;
    DistributedDeviceService::GetInstance().GetDeviceList(peerDevices);
    if (peerDevices.empty()) {
        ANS_LOGW("no peerDevices");
        return false;
    }

    for (auto peerDevice : peerDevices) {
        auto peerDeviceInfo = peerDevice.second;
        if (peerDeviceInfo.deviceId_ == deviceId ||
            (peerDeviceInfo.IsPadOrPc() && peerDeviceInfo.peerState_ != DeviceState::STATE_ONLINE)) {
            ANS_LOGD("no need ForWardRemove");
            continue;
        }
        std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(boxMessage, peerDeviceInfo,
            TransDataType::DATA_TYPE_BYTES, DELETE_ERROR_EVENT_CODE);
        DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
        ANS_LOGI("ForWardRemove,deviceId:%{public}s", StringAnonymous(peerDeviceInfo.deviceId_).c_str());
    }
    return true;
}

std::shared_ptr<NotificationRemoveBox> DistributedPublishService::MakeRemvoeBox(
    std::string &hashCode, int32_t &slotTypes)
{
    std::shared_ptr<NotificationRemoveBox> removeBox = std::make_shared<NotificationRemoveBox>();
    if (removeBox == nullptr) {
        ANS_LOGE("MakeRemvoeBox ERR");
        return nullptr;
    }
    removeBox->SetNotificationHashCode(DISTRIBUTED_LABEL + hashCode);
    removeBox->SetNotificationSlotType(slotTypes);

    if (!removeBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return nullptr;
    }

    return removeBox;
}

std::shared_ptr<BatchRemoveNotificationBox> DistributedPublishService::MakeBatchRemvoeBox(
    std::vector<std::string>& hashCodes, std::string &slotTypes)
{
    std::shared_ptr<BatchRemoveNotificationBox> batchRemoveBox = std::make_shared<BatchRemoveNotificationBox>();
    if (batchRemoveBox == nullptr) {
        ANS_LOGE("MakeBatchRemvoeBox ERR");
        return nullptr;
    }
    std::ostringstream keysStream;
    for (auto hashCode : hashCodes) {
        auto key = DISTRIBUTED_LABEL + hashCode;
        keysStream << key << ' ';
    }
    std::string hashCodeStrings = keysStream.str();
    batchRemoveBox->SetNotificationHashCodes(hashCodeStrings);
    batchRemoveBox->SetNotificationSlotTypes(slotTypes);

    if (!batchRemoveBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return nullptr;
    }
    return batchRemoveBox;
}

void DistributedPublishService::SyncLiveViewList(const DistributedDeviceInfo device,
    const std::vector<sptr<Notification>>& notifications)
{
    if (device.IsPadOrPc()) {
        ANS_LOGI("Dans no need sync list.");
        return;
    }

    std::vector<std::string> notificationList;
    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            ANS_LOGI("Dans no need sync remove notification.");
            continue;
        }
        notificationList.push_back(notification->GetKey());
    }
    SyncNotifictionList(device, notificationList);
}

void DistributedPublishService::SyncLiveViewContent(const DistributedDeviceInfo device,
    const std::vector<sptr<Notification>>& notifications)
{
    std::vector<std::string> labelList;
    std::vector<std::string> bundlesList;
    bool checkBundleExist = false;
    if (device.IsPadOrPc()) {
        std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
        if (deviceType.empty()) {
            ANS_LOGW("Dans %{public}s %{public}u.", StringAnonymous(device.deviceId_).c_str(), device.deviceType_);
            return;
        }
        if (NotificationHelper::GetTargetDeviceBundleList(deviceType, device.udid_, bundlesList, labelList) != ERR_OK) {
            ANS_LOGW("Get %{public}s %{public}u.", StringAnonymous(device.deviceId_).c_str(), device.deviceType_);
            return;
        }
        ANS_LOGI("Get bundles size %{public}zu.", bundlesList.size());
        checkBundleExist = true;
    }

    std::unordered_set<std::string> labelSet(labelList.begin(), labelList.end());
    std::unordered_set<std::string> bundleSet(bundlesList.begin(), bundlesList.end());
    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            continue;
        }

        auto requestPoint = notification->GetNotificationRequestPoint();
        if (checkBundleExist) {
            std::string bundleName = requestPoint->GetOwnerBundleName();
            if (bundleSet.count(bundleName)) {
                ANS_LOGI("Dans no need sync %{public}d %{public}s.", checkBundleExist, bundleName.c_str());
                continue;
            }
            int32_t userId = requestPoint->GetOwnerUserId();
            if (DelayedSingleton<BundleResourceHelper>::GetInstance()->CheckSystemApp(bundleName, userId)) {
                continue;
            }

            AppExecFwk::BundleResourceInfo resourceInfo;
            if (DelayedSingleton<BundleResourceHelper>::GetInstance()->GetBundleInfo(bundleName, resourceInfo)
                != ERR_OK) {
                ANS_LOGW("Dans get bundle failed %{public}s.", bundleName.c_str());
                continue;
            }

            if (checkBundleExist && labelSet.count(resourceInfo.label)) {
                ANS_LOGI("Bundle system no sycn %{public}s.", bundleName.c_str());
                continue;
            }
        }

        std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
        SendNotifictionRequest(sharedNotification, device, true);
    }
}

void DistributedPublishService::SyncLiveViewNotification(const DistributedDeviceInfo peerDevice, bool isForce)
{
    if (!DistributedDeviceService::GetInstance().IsSyncLiveView(peerDevice.deviceId_, isForce)) {
        return;
    }

    DistributedDeviceInfo device;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfo(peerDevice.deviceId_, device)) {
        return;
    }
    // wearable switch set by litewearable
    std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
    if (deviceType == DistributedService::WEARABLE_DEVICE_TYPE) {
        deviceType = DistributedService::LITEWEARABLE_DEVICE_TYPE;
    }

    bool enable = false;
    auto result = NotificationHelper::IsDistributedEnabledBySlot(NotificationConstant::SlotType::LIVE_VIEW,
        deviceType, enable);
    if (result != ERR_OK || !enable) {
        ANS_LOGW("Dans get switch %{public}s failed %{public}d.", deviceType.c_str(), result);
        return;
    }

    std::vector<sptr<Notification>> notifications;
    result = NotificationHelper::GetAllNotificationsBySlotType(notifications,
        NotificationConstant::SlotType::LIVE_VIEW);
    if (result != ERR_OK) {
        ANS_LOGI("Dans get all active %{public}d.", result);
        return;
    }

    SyncLiveViewList(device, notifications);
    SyncLiveViewContent(device, notifications);
    DistributedDeviceService::GetInstance().SetDeviceSyncData(device.deviceId_,
        DistributedDeviceService::SYNC_LIVE_VIEW, true);
}

void DistributedPublishService::SyncNotifictionList(const DistributedDeviceInfo& peerDevice,
    const std::vector<std::string>& notificationList)
{
    ANS_LOGI("Dans sync notification %{public}zu.", notificationList.size());
    std::shared_ptr<NotificationSyncBox> notificationSyncBox = std::make_shared<NotificationSyncBox>();
    notificationSyncBox->SetLocalDeviceId(peerDevice.deviceId_);
    notificationSyncBox->SetNotificationEmpty(notificationList.empty());
    if (!notificationList.empty()) {
        notificationSyncBox->SetNotificationList(notificationList);
    }

    if (!notificationSyncBox->Serialize()) {
        ANS_LOGW("Dans SyncNotifictionList serialize failed.");
        return;
    }
    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(notificationSyncBox, peerDevice,
            TransDataType::DATA_TYPE_BYTES, PUBLISH_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
    ANS_LOGI("Dans SyncNotifictionList %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_);
}

void DistributedPublishService::SendNotifictionRequest(const std::shared_ptr<Notification> request,
    const DistributedDeviceInfo& peerDevice, bool isSyncNotification)
{
    std::shared_ptr<NotificationRequestBox> requestBox = std::make_shared<NotificationRequestBox>();
    if (request == nullptr || request->GetNotificationRequestPoint() == nullptr) {
        return;
    }

    auto requestPoint = request->GetNotificationRequestPoint();
    ANS_LOGI("Dans OnConsumed Notification key = %{public}s, notificationFlag = %{public}s", request->GetKey().c_str(),
        requestPoint->GetFlags() == nullptr ? "null" : requestPoint->GetFlags()->Dump().c_str());
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    requestBox->SetDeviceId(local.deviceId_);
    requestBox->SetAutoDeleteTime(requestPoint->GetAutoDeletedTime());
    requestBox->SetFinishTime(requestPoint->GetFinishDeadLine());
    requestBox->SetNotificationHashCode(request->GetKey());
    requestBox->SetSlotType(static_cast<int32_t>(requestPoint->GetSlotType()));
    requestBox->SetContentType(static_cast<int32_t>(requestPoint->GetNotificationType()));

    int32_t reminderFlag = isSyncNotification ? 0 : requestPoint->GetFlags()->GetReminderFlags();
    requestBox->SetReminderFlag(reminderFlag);
    if (!requestPoint->GetAppMessageId().empty()) {
        requestBox->SetAppMessageId(requestPoint->GetAppMessageId());
    }
    if (request->GetBundleName().empty()) {
        requestBox->SetCreatorBundleName(request->GetCreateBundle());
    } else {
        requestBox->SetCreatorBundleName(request->GetBundleName());
    }
    if (requestPoint->IsCommonLiveView()) {
        std::vector<uint8_t> buffer;
        std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(peerDevice.deviceType_);
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewEncodeContent(
            requestPoint, buffer, deviceType);
        requestBox->SetCommonLiveView(buffer);
    }
    if (!SetNotificationExtendInfo(requestPoint, peerDevice.deviceType_, isSyncNotification, requestBox)) {
        return;
    }
    SetNotificationButtons(requestPoint, peerDevice.deviceType_, requestPoint->GetSlotType(), requestBox);
    SetNotificationContent(request->GetNotificationRequestPoint()->GetContent(),
        requestPoint->GetNotificationType(), requestBox);
    if (!requestBox->Serialize()) {
        ANS_LOGW("Dans OnConsumed serialize failed.");
        AnalyticsUtil::GetInstance().SendHaReport(PUBLISH_ERROR_EVENT_CODE, -1, BRANCH3_ID,
            "serialization failed");
        return;
    }
    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(requestBox, peerDevice,
            TransDataType::DATA_TYPE_BYTES, PUBLISH_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
}

void DistributedPublishService::SetNotificationContent(const std::shared_ptr<NotificationContent> &content,
    NotificationContent::Type type, std::shared_ptr<NotificationRequestBox>& requestBox)
{
    if (content == nullptr || content->GetNotificationContent() == nullptr) {
        return;
    }

    ANS_LOGI("Set Notification notification content %{public}d.", type);
    switch (type) {
        case NotificationContent::Type::PICTURE: {
            auto picture = std::static_pointer_cast<NotificationPictureContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(picture->GetTitle());
            requestBox->SetNotificationText(picture->GetText());
            requestBox->SetNotificationAdditionalText(picture->GetAdditionalText());
            requestBox->SetNotificationExpandedTitle(picture->GetExpandedTitle());
            requestBox->SetNotificationBriefText(picture->GetBriefText());
            requestBox->SetNotificationBigPicture(picture->GetBigPicture());
            break;
        }
        case NotificationContent::Type::MULTILINE: {
            auto multiline = std::static_pointer_cast<NotificationMultiLineContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(multiline->GetTitle());
            requestBox->SetNotificationText(multiline->GetText());
            requestBox->SetNotificationAdditionalText(multiline->GetAdditionalText());
            requestBox->SetNotificationExpandedTitle(multiline->GetExpandedTitle());
            requestBox->SetNotificationBriefText(multiline->GetBriefText());
            requestBox->SetNotificationAllLines(multiline->GetAllLines());
            break;
        }
        case NotificationContent::Type::LONG_TEXT: {
            std::shared_ptr<NotificationLongTextContent> contentLong =
                std::static_pointer_cast<NotificationLongTextContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(contentLong->GetTitle());
            requestBox->SetNotificationText(contentLong->GetText());
            requestBox->SetNotificationAdditionalText(contentLong->GetAdditionalText());
            requestBox->SetNotificationExpandedTitle(contentLong->GetExpandedTitle());
            requestBox->SetNotificationBriefText(contentLong->GetBriefText());
            requestBox->SetNotificationLongText(contentLong->GetLongText());
            break;
        }
        case NotificationContent::Type::LIVE_VIEW:
        case NotificationContent::Type::LOCAL_LIVE_VIEW:
        case NotificationContent::Type::BASIC_TEXT:
        default: {
            std::shared_ptr<NotificationBasicContent> contentBasic =
                std::static_pointer_cast<NotificationBasicContent>(content->GetNotificationContent());
            requestBox->SetNotificationTitle(contentBasic->GetTitle());
            requestBox->SetNotificationText(contentBasic->GetText());
            requestBox->SetNotificationAdditionalText(contentBasic->GetAdditionalText());
            break;
        }
    }
}

void DistributedPublishService::SetNotificationButtons(const sptr<NotificationRequest> notificationRequest,
    int32_t deviceType, NotificationConstant::SlotType slotType, std::shared_ptr<NotificationRequestBox>& requestBox)
{
    auto actionButtons = notificationRequest->GetActionButtons();
    if (actionButtons.empty()) {
        ANS_LOGE("Check actionButtons is null.");
        return;
    }
    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD ||
        deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_PC) {
        std::vector<std::string> buttonsTitle;
        size_t length = actionButtons.size();
        if (length > NotificationConstant::MAX_BTN_NUM) {
            length = NotificationConstant::MAX_BTN_NUM;
        }
        for (size_t i = 0; i < length; i++) {
            if (actionButtons[i] == nullptr) {
                return;
            }
            if (actionButtons[i]->GetUserInput() != nullptr) {
                ANS_LOGI("distributed override reply button.");
                continue;
            }
            buttonsTitle.push_back(actionButtons[i]->GetTitle());
        }
        requestBox->SetActionButtonsTitle(buttonsTitle);
        return;
    }
    if (slotType == NotificationConstant::SlotType::SOCIAL_COMMUNICATION) {
        std::shared_ptr<NotificationActionButton> button = nullptr;
        for (std::shared_ptr<NotificationActionButton> buttonItem : actionButtons) {
            if (buttonItem != nullptr && buttonItem->GetUserInput() != nullptr &&
                !buttonItem->GetUserInput()->GetInputKey().empty()) {
                button = buttonItem;
                break;
            }
        }
        if (button != nullptr && button->GetUserInput() != nullptr) {
            requestBox->SetNotificationActionName(button->GetTitle());
            requestBox->SetNotificationUserInput(button->GetUserInput()->GetInputKey());
        }
    }
}

bool DistributedPublishService::FillSyncRequestExtendInfo(const sptr<NotificationRequest> notificationRequest,
    int32_t deviceTypeId, std::shared_ptr<NotificationRequestBox>& requestBox, AAFwk::WantParams& wantParam)
{
    std::string appName;
    auto params = notificationRequest->GetExtendInfo();
    if (params != nullptr) {
        wantParam = *params;
        appName = params->GetStringParam("notification_collaboration_app_name");
    }
    std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(deviceTypeId);
    std::string bundleName = appName.empty() ? notificationRequest->GetOwnerBundleName() : appName;
    AppExecFwk::BundleResourceInfo resourceInfo;
    if (DelayedSingleton<BundleResourceHelper>::GetInstance()->GetBundleInfo(bundleName, resourceInfo) != ERR_OK) {
        ANS_LOGW("Dans get bundle icon failed %{public}s.", bundleName.c_str());
        return false;
    }

    int32_t userId;
    std::string deviceId;
    if (NotificationHelper::GetMutilDeviceStatus(deviceType, UNLOCKED_USED_FLAG, deviceId, userId) != ERR_OK) {
        ANS_LOGW("Dans get status failed %{public}s.", deviceType.c_str());
        return false;
    }

    if (appName.empty()) {
        int32_t ownerUserId = notificationRequest->GetOwnerUserId();
        AppExecFwk::BundleInfo bundleInfo;
        if (DelayedSingleton<BundleResourceHelper>::GetInstance()->GetBundleInfoV9(bundleName, ownerUserId,
            bundleInfo) != ERR_OK) {
            ANS_LOGE("Dans get application, %{public}d, %{public}s", deviceTypeId, bundleName.c_str());
            return false;
        }
        int32_t index = DelayedSingleton<BundleResourceHelper>::GetInstance()->GetAppIndexByUid(
            notificationRequest->GetOwnerUid());
        AppExecFwk::ApplicationInfo appInfo = bundleInfo.applicationInfo;
        wantParam.SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_APP_NAME, AAFwk::String::Box(appInfo.name));
        wantParam.SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_APP_LABEL, AAFwk::String::Box(resourceInfo.label));
        wantParam.SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_APP_UID,
            AAFwk::Integer::Box(notificationRequest->GetOwnerUid()));
        wantParam.SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_APP_INDEX, AAFwk::Integer::Box(index));
        wantParam.SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_DEVICE_ID + "_" + deviceType,
            AAFwk::String::Box(deviceId));
        requestBox->SetSmallIcon(AnsImageUtil::CreatePixelMapByString(resourceInfo.icon));
        requestBox->SetReceiverUserId(userId);
        ANS_LOGI("Dans fill %{public}s %{public}d %{public}s %{public}d %{public}d", resourceInfo.label.c_str(), index,
            StringAnonymous(deviceId).c_str(), userId, notificationRequest->GetOwnerUid());
        return true;
    }
    wantParam.SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_DEVICE_ID + "_" + deviceType, AAFwk::String::Box(deviceId));
    requestBox->SetSmallIcon(AnsImageUtil::CreatePixelMapByString(resourceInfo.icon));
    requestBox->SetReceiverUserId(userId);
    return true;
}

bool DistributedPublishService::FillNotSyncRequestExtendInfo(const sptr<NotificationRequest> notificationRequest,
    int32_t deviceType, std::shared_ptr<NotificationRequestBox>& requestBox, AAFwk::WantParams& wantParam)
{
    auto params = notificationRequest->GetExtendInfo();
    if (params == nullptr) {
        ANS_LOGW("Fill box invalid data.");
        return false;
    }
    std::string content = params->GetStringParam("notification_collaboration_app_name");
    if (content.empty()) {
        ANS_LOGI("Fill box invalid app name.");
        return false;
    }
    AppExecFwk::BundleResourceInfo resourceInfo;
    if (DelayedSingleton<BundleResourceHelper>::GetInstance()->GetBundleInfo(content, resourceInfo) != 0) {
        ANS_LOGW("Dans get bundle icon failed %{public}s.", content.c_str());
        return false;
    }
    std::shared_ptr<Media::PixelMap> icon = AnsImageUtil::CreatePixelMapByString(resourceInfo.icon);
    requestBox->SetSmallIcon(icon);
    std::string key = EXTENDINFO_INFO_PRE + EXTENDINFO_USERID +
        DistributedDeviceService::DeviceTypeToTypeString(deviceType);
    int32_t userId = params->GetIntParam(key, -1);
    if (userId != -1) {
        requestBox->SetReceiverUserId(userId);
    }
    wantParam = *params;
    return true;
}

bool DistributedPublishService::SetNotificationExtendInfo(const sptr<NotificationRequest> notificationRequest,
    int32_t deviceType, bool isSyncNotification, std::shared_ptr<NotificationRequestBox>& requestBox)
{
    if (notificationRequest->GetBigIcon() != nullptr) {
        requestBox->SetBigIcon(notificationRequest->GetBigIcon(), deviceType);
    }
    if (notificationRequest->GetOverlayIcon() != nullptr) {
        requestBox->SetOverlayIcon(notificationRequest->GetOverlayIcon(), deviceType);
    }
    if (notificationRequest->GetLittleIcon() != nullptr) {
        requestBox->SetSmallIcon(notificationRequest->GetLittleIcon());
    }
    if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        ANS_LOGI("Send request no extend info %{public}d.", deviceType);
        return true;
    }

    std::string basicInfo;
    if (!notificationRequest->CollaborationToJson(basicInfo)) {
        ANS_LOGW("Dans OnConsumed collaboration json failed.");
        return false;
    }
    requestBox->SetNotificationBasicInfo(basicInfo);

    AAFwk::WantParams wantParam;
    if (isSyncNotification) {
        if (!FillSyncRequestExtendInfo(notificationRequest, deviceType, requestBox, wantParam)) {
            ANS_LOGW("Dans fill sync failed.");
            return false;
        }
    } else {
        if (!FillNotSyncRequestExtendInfo(notificationRequest, deviceType, requestBox, wantParam)) {
            ANS_LOGW("Dans fill not sync failed.");
            return false;
        }
    }
    wantParam.DumpInfo(0);
    AAFwk::WantParamWrapper wantWrapper(wantParam);
    requestBox->SetBoxExtendInfo(wantWrapper.ToString());
    requestBox->SetDeviceUserId(DistributedSubscribeService::GetCurrentActiveUserId());
    return true;
}

#else
void DistributedPublishService::RemoveAllDistributedNotifications(const std::shared_ptr<TlvBox>& boxMessage)
{
    RemoveAllDistributedNotificationsBox removeBox = RemoveAllDistributedNotificationsBox(boxMessage);
    std::string deviceId;
    removeBox.GetLocalDeviceId(deviceId);
    DistributedDeviceInfo device;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfo(deviceId, device)) {
        ANS_LOGW("Dans bundle get device info failed %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }
    std::vector<std::string> hashcodes;
    IN_PROCESS_CALL(NotificationHelper::RemoveDistributedNotifications(hashcodes,
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
        NotificationConstant::DistributedDeleteType::DEVICE_ID,
        NotificationConstant::DISTRIBUTED_RELEASE_DELETE,
        device.udid_));
}

void DistributedPublishService::PublishNotification(const std::shared_ptr<TlvBox>& boxMessage)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    if (request == nullptr) {
        ANS_LOGE("NotificationRequest is nullptr");
        return;
    }
    int32_t slotType = 0;
    int32_t contentType = 0;
    NotificationRequestBox requestBox = NotificationRequestBox(boxMessage);
    std::string basicInfo;
    if (requestBox.GetNotificationBasicInfo(basicInfo)) {
        request = NotificationRequest::CollaborationFromJson(basicInfo);
        if (request == nullptr) {
            ANS_LOGE("NotificationRequest is nullptr");
            return;
        }
    }
    bool isCommonLiveView = false;
    if (requestBox.GetSlotType(slotType) && requestBox.GetContentType(contentType)) {
        isCommonLiveView =
            (static_cast<NotificationContent::Type>(contentType) == NotificationContent::Type::LIVE_VIEW) &&
            (static_cast<NotificationConstant::SlotType>(slotType) == NotificationConstant::SlotType::LIVE_VIEW);
    }
    MakeExtendInfo(requestBox, request);
    MakeNotificationButtons(requestBox, static_cast<NotificationConstant::SlotType>(slotType), request);
    MakeNotificationContent(requestBox, request, isCommonLiveView, contentType);
    MakeNotificationIcon(requestBox, request);
    MakeNotificationReminderFlag(requestBox, request);
    int result = IN_PROCESS_CALL(NotificationHelper::PublishNotification(*request));
    ANS_LOGI("Dans publish message %{public}s %{public}d.", request->GetDistributedHashCode().c_str(), result);
}

void DistributedPublishService::PublishSynchronousLiveView(const std::shared_ptr<TlvBox>& boxMessage)
{
    bool empty = true;
    NotificationSyncBox notificationSyncBox = NotificationSyncBox(boxMessage);
    if (!notificationSyncBox.GetNotificationEmpty(empty)) {
        ANS_LOGW("Dans get sync notification empty failed.");
        return;
    }

    std::unordered_set<std::string> notificationList;
    if (!empty) {
        if (!notificationSyncBox.GetNotificationList(notificationList)) {
            ANS_LOGW("Dans get sync notification failed.");
            return;
        }
    }
    std::vector<sptr<Notification>> notifications;
    auto result = NotificationHelper::GetAllNotificationsBySlotType(notifications,
        NotificationConstant::SlotType::LIVE_VIEW);
    if (result != ERR_OK || notifications.empty()) {
        ANS_LOGI("Dans get all active %{public}d %{public}d.", result, notifications.empty());
        return;
    }

    ANS_LOGI("Dans sync notification %{public}zu %{public}zu.", notificationList.size(), notifications.size());
    for (auto item : notificationList) {
        ANS_LOGI("Dans sync %{public}s.", item.c_str());
    }
    std::vector<std::string> removeList;
    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            ANS_LOGI("Dans no need sync remove notification.");
            continue;
        }
        std::string hashCode = notification->GetKey();
        ANS_LOGI("Dans sync remove %{public}s.", hashCode.c_str());
        size_t pos = hashCode.find(DISTRIBUTED_LABEL);
        if (pos != std::string::npos) {
            hashCode.erase(pos, DISTRIBUTED_LABEL.length());
        }
        if (notificationList.find(hashCode) == notificationList.end()) {
            removeList.push_back(notification->GetKey());
            ANS_LOGI("Dans sync remove notification %{public}s.", notification->GetKey().c_str());
        }
    }
    if (!removeList.empty()) {
        int result = IN_PROCESS_CALL(NotificationHelper::RemoveNotifications(removeList,
            NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
        ANS_LOGI("Dans sync remove message %{public}d.", result);
    }
}

void DistributedPublishService::MakeNotificationButtons(const NotificationRequestBox& box,
    NotificationConstant::SlotType slotType, sptr<NotificationRequest>& request)
{
    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    if ((localDevice.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD ||
        localDevice.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PC)) {
        MakePadNotificationButtons(box, request);
        return;
    }

    if (request != nullptr && slotType == NotificationConstant::SlotType::SOCIAL_COMMUNICATION) {
        std::string actionName;
        std::string userInputKey;
        box.GetNotificationActionName(actionName);
        if (actionName.empty()) {
            ANS_LOGE("Check actionButtons is null.");
            return;
        }
        box.GetNotificationUserInput(userInputKey);
        std::shared_ptr<NotificationUserInput> userInput  = NotificationUserInput::Create(userInputKey);
        if (!userInput) {
            ANS_LOGE("Failed to create NotificationUserInput by inputKey=%{public}s", userInputKey.c_str());
            return;
        }
        std::shared_ptr<NotificationActionButton> actionButton =
            NotificationActionButton::Create(nullptr, actionName, nullptr);
        actionButton->AddNotificationUserInput(userInput);
        request->AddActionButton(actionButton);
    }
}

void DistributedPublishService::MakePadNotificationButtons(
    const NotificationRequestBox& box, sptr<NotificationRequest>& request)
{
    if (request == nullptr) {
        return;
    }
    std::vector<std::string> buttonsTitle;
    if (!box.GetActionButtonsTitle(buttonsTitle) || buttonsTitle.size() <= 0) {
        return;
    }
    for (size_t i = 0; i < buttonsTitle.size(); i++) {
        std::shared_ptr<NotificationActionButton> actionButton =
            NotificationActionButton::Create(nullptr, buttonsTitle[i], nullptr);
        request->AddActionButton(actionButton);
    }
}

void DistributedPublishService::MakeNotificationReminderFlag(const NotificationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    int32_t type = 0;
    std::string context;
    if (box.GetSlotType(type)) {
        request->SetSlotType(static_cast<NotificationConstant::SlotType>(type));
    }
    if (box.GetReminderFlag(type)) {
        request->SetCollaboratedReminderFlag(static_cast<uint32_t>(type));
    }
    if (box.GetAppMessageId(context)) {
        request->SetAppMessageId(context);
    }
    if (box.GetCreatorBundleName(context)) {
        request->SetOwnerBundleName(context);
        request->SetCreatorBundleName(context);
    }
    if (box.GetNotificationHashCode(context)) {
        request->SetDistributedHashCode(context);
    }
    request->SetDistributedCollaborate(true);
}

void DistributedPublishService::MakeExtendInfo(const NotificationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    std::string contentInfo;
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    if (box.GetBoxExtendInfo(contentInfo)) {
        if (!contentInfo.empty()) {
            AAFwk::WantParams extendInfoParams = AAFwk::WantParamWrapper::ParseWantParams(contentInfo);
            extendInfo = std::make_shared<AAFwk::WantParams>(extendInfoParams);
        }
    }
    extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG, AAFwk::Boolean::Box(true));
    auto local = DistributedDeviceService::GetInstance().GetLocalDevice();
    if (local.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
        extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_ENABLE_CHECK, AAFwk::Boolean::Box(false));
    } else {
        extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_ENABLE_CHECK, AAFwk::Boolean::Box(true));
        if (box.GetDeviceId(contentInfo)) {
            DistributedDeviceInfo peerDevice;
            if (DistributedDeviceService::GetInstance().GetDeviceInfo(contentInfo, peerDevice)) {
                std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(peerDevice.deviceType_);
                extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_DEVICETYPE, AAFwk::String::Box(deviceType));
                extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_DEVICE_ID, AAFwk::String::Box(peerDevice.udid_));
            }
        }
        std::string localType = DistributedDeviceService::DeviceTypeToTypeString(local.deviceType_);
        extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_LOCALTYPE, AAFwk::String::Box(localType));
        int32_t userId;
        if (box.GetDeviceUserId(userId)) {
            extendInfo->SetParam(EXTENDINFO_INFO_PRE + EXTENDINFO_DEVICE_USERID, AAFwk::Integer::Box(userId));
        }
        if (box.GetReceiverUserId(userId)) {
            request->SetReceiverUserId(userId);
        }
    }
    extendInfo->DumpInfo(0);
    request->SetExtendInfo(extendInfo);
}

void DistributedPublishService::MakeNotificationIcon(const NotificationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    std::shared_ptr<Media::PixelMap> icon;
    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    if (box.GetBigIcon(icon, localDevice.deviceType_)) {
        request->SetBigIcon(icon);
    }
    if (box.GetOverlayIcon(icon, localDevice.deviceType_)) {
        request->SetOverlayIcon(icon);
    }
    if (box.GetSmallIcon(icon)) {
        request->SetLittleIcon(icon);
    }
}

void DistributedPublishService::MakeNotificationContent(const NotificationRequestBox& box,
    sptr<NotificationRequest>& request, bool isCommonLiveView, int32_t contentType)
{
    if (isCommonLiveView) {
        std::vector<uint8_t> buffer;
        if (box.GetCommonLiveView(buffer)) {
            int64_t deleteTime;
            std::string context;
            auto liveviewContent = std::make_shared<NotificationLiveViewContent>();
            if (box.GetNotificationText(context)) {
                liveviewContent->SetText(context);
            }
            if (box.GetNotificationTitle(context)) {
                liveviewContent->SetTitle(context);
            }
            if (box.GetAutoDeleteTime(deleteTime)) {
                request->SetAutoDeletedTime(deleteTime);
            }
            if (box.GetFinishTime(deleteTime)) {
                request->SetFinishDeadLine(deleteTime);
            }
            auto content = std::make_shared<NotificationContent>(liveviewContent);
            request->SetContent(content);
            std::shared_ptr<AAFwk::WantParams> extraInfo = std::make_shared<AAFwk::WantParams>();
            liveviewContent->SetExtraInfo(extraInfo);
            auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
            std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(localDevice.deviceType_);
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewDecodeContent(
                request, buffer, deviceType);
        }
        return;
    }
    MakeNotificationBasicContent(box, request, contentType);
}

struct TransferNotification {
    std::string title;
    std::string context;
    std::string additionalText;
    std::string briefText;
    std::string expandedTitle;
};

static void ConvertBoxToLongContent(const TransferNotification& notificationItem, const NotificationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    auto pContent = std::make_shared<NotificationLongTextContent>();
    pContent->SetText(notificationItem.context);
    pContent->SetTitle(notificationItem.title);
    pContent->SetAdditionalText(notificationItem.additionalText);
    pContent->SetBriefText(notificationItem.briefText);
    pContent->SetExpandedTitle(notificationItem.expandedTitle);
    std::string longText;
    box.GetNotificationLongText(longText);
    pContent->SetLongText(longText);
    auto content = std::make_shared<NotificationContent>(pContent);
    request->SetContent(content);
}

static void ConvertBoxToMultileContent(const TransferNotification& notificationItem, const NotificationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    auto pContent = std::make_shared<NotificationMultiLineContent>();
    pContent->SetText(notificationItem.context);
    pContent->SetTitle(notificationItem.title);
    pContent->SetAdditionalText(notificationItem.additionalText);
    pContent->SetBriefText(notificationItem.briefText);
    pContent->SetExpandedTitle(notificationItem.expandedTitle);
    std::vector<std::string> allLines;
    box.GetNotificationAllLines(allLines);
    for (auto& item : allLines) {
        pContent->AddSingleLine(item);
    }
    auto content = std::make_shared<NotificationContent>(pContent);
    request->SetContent(content);
}

static void ConvertBoxToPictureContent(const TransferNotification& notificationItem, const NotificationRequestBox& box,
    sptr<NotificationRequest>& request)
{
    auto pContent = std::make_shared<NotificationPictureContent>();
    pContent->SetText(notificationItem.context);
    pContent->SetTitle(notificationItem.title);
    pContent->SetAdditionalText(notificationItem.additionalText);
    pContent->SetBriefText(notificationItem.briefText);
    pContent->SetExpandedTitle(notificationItem.expandedTitle);
    std::shared_ptr<Media::PixelMap> bigPicture;
    box.GetNotificationBigPicture(bigPicture);
    pContent->SetBigPicture(bigPicture);
    auto content = std::make_shared<NotificationContent>(pContent);
    request->SetContent(content);
}

void DistributedPublishService::MakeNotificationBasicContent(const NotificationRequestBox& box,
    sptr<NotificationRequest>& request, int32_t contentType)
{
    TransferNotification notificationItem;
    box.GetNotificationText(notificationItem.context);
    box.GetNotificationTitle(notificationItem.title);
    box.GetNotificationAdditionalText(notificationItem.additionalText);
    NotificationContent::Type type = static_cast<NotificationContent::Type>(contentType);
    if (type == NotificationContent::Type::LONG_TEXT || type == NotificationContent::Type::MULTILINE ||
        type == NotificationContent::Type::PICTURE) {
        box.GetNotificationBriefText(notificationItem.briefText);
        box.GetNotificationExpandedTitle(notificationItem.expandedTitle);
    }
    switch (type) {
        case NotificationContent::Type::BASIC_TEXT: {
            auto pContent = std::make_shared<NotificationNormalContent>();
            pContent->SetText(notificationItem.context);
            pContent->SetTitle(notificationItem.title);
            pContent->SetAdditionalText(notificationItem.additionalText);
            auto content = std::make_shared<NotificationContent>(pContent);
            request->SetContent(content);
            break;
        }
        case NotificationContent::Type::CONVERSATION: {
            auto pContent = std::make_shared<NotificationConversationalContent>();
            pContent->SetText(notificationItem.context);
            pContent->SetTitle(notificationItem.title);
            pContent->SetAdditionalText(notificationItem.additionalText);
            auto content = std::make_shared<NotificationContent>(pContent);
            request->SetContent(content);
            break;
        }
        case NotificationContent::Type::LONG_TEXT: {
            ConvertBoxToLongContent(notificationItem, box, request);
            break;
        }
        case NotificationContent::Type::MULTILINE: {
            ConvertBoxToMultileContent(notificationItem, box, request);
            break;
        }
        case NotificationContent::Type::PICTURE: {
            ConvertBoxToPictureContent(notificationItem, box, request);
            break;
        }
        default: {
            ANS_LOGE("Set notifictaion content %{public}d", type);
            break;
        }
    }
}
#endif
}
}
