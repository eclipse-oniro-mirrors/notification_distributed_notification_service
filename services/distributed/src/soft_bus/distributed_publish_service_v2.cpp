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

namespace OHOS {
namespace Notification {

static const std::string DISTRIBUTED_LABEL = "ans_distributed";

DistributedPublishService& DistributedPublishService::GetInstance()
{
    static DistributedPublishService distributedPublishService;
    return distributedPublishService;
}

void DistributedPublishService::RemoveNotification(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::string hashCode;
    int32_t slotType;
    if (boxMessage == nullptr) {
        ANS_LOGE("boxMessage is nullptr");
        return;
    }
    boxMessage->GetStringValue(NOTIFICATION_HASHCODE, hashCode);
    boxMessage->GetInt32Value(NOTIFICATION_SLOT_TYPE, slotType);

    int result = IN_PROCESS_CALL(NotificationHelper::RemoveNotification(
        hashCode, NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
    std::string errorReason = "delete message failed";
    if (result == 0) {
        errorReason = "delete message success";
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH4_ID, errorReason);
        AnalyticsUtil::GetInstance().OperationalReporting(OPERATION_DELETE_BRANCH, slotType);
    } else {
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH3_ID, errorReason);
    }
    ANS_LOGI("dans remove message %{public}d.", result);
}

void DistributedPublishService::RemoveNotifications(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::vector<std::string> hashCodes;
    std::string hashCodesString;
    if (boxMessage == nullptr) {
        ANS_LOGE("boxMessage is nullptr");
        return;
    }
    if (!boxMessage->GetStringValue(NOTIFICATION_HASHCODE, hashCodesString)) {
        ANS_LOGE("failed GetStringValue from boxMessage");
        return;
    }
    std::istringstream hashCodesStream(hashCodesString);
    std::string hashCode;
    while (hashCodesStream >> hashCode) {
        if (!hashCode.empty()) {
            hashCodes.push_back(hashCode);
        }
    }

    int result = IN_PROCESS_CALL(
        NotificationHelper::RemoveNotifications(hashCodes, NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
    ANS_LOGI("dans batch remove message %{public}d.", result);
    if (result == 0) {
        AnalyticsUtil::GetInstance().AbnormalReporting(DELETE_ERROR_EVENT_CODE, result, BRANCH4_ID,
            "delete message success");
        std::string slotTypesString;
        if (!boxMessage->GetStringValue(BATCH_REMOVE_SLOT_TYPE, slotTypesString)) {
            ANS_LOGE("failed GetStringValue from boxMessage");
            return;
        }
        std::istringstream slotTypesStream(slotTypesString);
        std::string slotTypeString;
        while (slotTypesStream >> slotTypeString) {
            if (!slotTypeString.empty()) {
                AnalyticsUtil::GetInstance().OperationalReporting(OPERATION_DELETE_BRANCH,
                    atoi(slotTypeString.c_str()));
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
    ANS_LOGI("dans OnCanceled %{public}s", hashCode.c_str());
    removeBox->SetNotificationHashCode(hashCode);
    removeBox->setNotificationSlotType(slotTypes);
    if (!removeBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return;
    }
    DistributedClient::GetInstance().SendMessage(removeBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, DELETE_ERROR_EVENT_CODE);
}

void DistributedPublishService::OnRemoveNotifications(const DistributedDeviceInfo& peerDevice,
    std::string hashCodes, std::string slotTypes)
{
    std::shared_ptr<BatchRemoveNotificationBox> batchRemoveBox = std::make_shared<BatchRemoveNotificationBox>();
    if (!hashCodes.empty()) {
        batchRemoveBox->SetNotificationHashCode(hashCodes);
    }
    batchRemoveBox->SetNotificationSlotTypes(slotTypes);

    if (!batchRemoveBox->Serialize()) {
        ANS_LOGW("dans OnCanceled serialize failed");
        return;
    }
    DistributedClient::GetInstance().SendMessage(batchRemoveBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, DELETE_ERROR_EVENT_CODE);
}

#ifdef DISTRIBUTED_FEATURE_MASTER
void DistributedPublishService::SyncLiveViewNotification(const DistributedDeviceInfo peerDevice, bool isForce)
{
    if (!DistributedDeviceService::GetInstance().CheckDeviceExist(peerDevice.deviceId_)) {
        return;
    }
    bool sync = DistributedDeviceService::GetInstance().IsDeviceSyncData(peerDevice.deviceId_);
    if (!isForce && sync) {
        ANS_LOGI("Dans %{public}d %{public}d.", isForce, sync);
        return;
    }

    std::vector<sptr<Notification>> notifications;
    auto result = NotificationHelper::GetAllNotificationsBySlotType(notifications,
        NotificationConstant::SlotType::LIVE_VIEW);
    if (result != ERR_OK) {
        ANS_LOGI("Dans get all active %{public}d.", result);
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
    SyncNotifictionList(peerDevice, notificationList);

    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            ANS_LOGI("Dans no need sync notification.");
            continue;
        }
        std::shared_ptr<Notification> sharedNotification = std::make_shared<Notification>(*notification);
        SendNotifictionRequest(sharedNotification, peerDevice, true);
    }
}

void DistributedPublishService::SyncNotifictionList(const DistributedDeviceInfo& peerDevice,
    const std::vector<std::string>& notificationList)
{
    ANS_LOGI("Dans sync notification %{public}d.", (int32_t)(notificationList.size()));
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
    int32_t result = DistributedClient::GetInstance().SendMessage(notificationSyncBox,
        TransDataType::DATA_TYPE_BYTES, peerDevice.deviceId_, PUBLISH_ERROR_EVENT_CODE);
    ANS_LOGI("Dans SyncNotifictionList %{public}s %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_, result);
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
    requestBox->SetAutoDeleteTime(requestPoint->GetAutoDeletedTime());
    requestBox->SetFinishTime(requestPoint->GetFinishDeadLine());
    requestBox->SetNotificationHashCode(request->GetKey());
    requestBox->SetSlotType(static_cast<int32_t>(requestPoint->GetSlotType()));
    requestBox->SetContentType(static_cast<int32_t>(requestPoint->GetNotificationType()));
    if (isSyncNotification) {
        requestBox->SetReminderFlag(0);
    } else {
        requestBox->SetReminderFlag(requestPoint->GetFlags()->GetReminderFlags());
    }
    if (request->GetBundleName().empty()) {
        requestBox->SetCreatorBundleName(request->GetCreateBundle());
    } else {
        requestBox->SetCreatorBundleName(request->GetBundleName());
    }
    if (requestPoint->GetBigIcon() != nullptr) {
        requestBox->SetBigIcon(requestPoint->GetBigIcon());
    }
    if (requestPoint->GetOverlayIcon() != nullptr) {
        requestBox->SetOverlayIcon(requestPoint->GetOverlayIcon());
    }
    if (requestPoint->IsCommonLiveView()) {
        std::vector<uint8_t> buffer;
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewEncodeContent(requestPoint, buffer);
        requestBox->SetCommonLiveView(buffer);
    }
    SetNotificationButtons(requestPoint, requestPoint->GetSlotType(), requestBox);
    SetNotificationContent(request->GetNotificationRequestPoint()->GetContent(),
        requestPoint->GetNotificationType(), requestBox);
    if (!requestBox->Serialize()) {
        ANS_LOGW("Dans OnConsumed serialize failed.");
        AnalyticsUtil::GetInstance().SendHaReport(PUBLISH_ERROR_EVENT_CODE, -1, BRANCH3_ID,
            "serialization failed");
        return;
    }
    DistributedClient::GetInstance().SendMessage(requestBox, TransDataType::DATA_TYPE_BYTES,
        peerDevice.deviceId_, PUBLISH_ERROR_EVENT_CODE);
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
    NotificationConstant::SlotType slotType, std::shared_ptr<NotificationRequestBox>& requestBox)
{
    if (slotType == NotificationConstant::SlotType::SOCIAL_COMMUNICATION) {
        auto actionButtons = notificationRequest->GetActionButtons();
        if (actionButtons.empty()) {
            ANS_LOGE("Check actionButtons is null.");
            return;
        }

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
#else
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
    bool isCommonLiveView = false;
    if (requestBox.GetSlotType(slotType) && requestBox.GetContentType(contentType)) {
        isCommonLiveView =
            (static_cast<NotificationContent::Type>(contentType) == NotificationContent::Type::LIVE_VIEW) &&
            (static_cast<NotificationConstant::SlotType>(slotType) == NotificationConstant::SlotType::LIVE_VIEW);
    }
    MakeNotificationButtons(requestBox, static_cast<NotificationConstant::SlotType>(slotType), request);
    MakeNotificationContent(requestBox, request, isCommonLiveView, contentType);
    MakeNotificationIcon(requestBox, request, isCommonLiveView);
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

    ANS_LOGI("Dans handle sync notification %{public}d %{public}d.", (int32_t)(notificationList.size()),
        (int32_t)(notifications.size()));
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
    if (request != nullptr && slotType == NotificationConstant::SlotType::SOCIAL_COMMUNICATION) {
        std::string actionName;
        std::string userInputKey;
        box.GetNotificationActionName(actionName);
        box.GetNotificationUserInput(userInputKey);
        std::shared_ptr<NotificationUserInput> userInput  = NotificationUserInput::Create(userInputKey);
        std::shared_ptr<NotificationActionButton> actionButton =
            NotificationActionButton::Create(nullptr, actionName, nullptr);
        actionButton->AddNotificationUserInput(userInput);
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
    if (box.GetCreatorBundleName(context)) {
        request->SetOwnerBundleName(context);
        request->SetCreatorBundleName(context);
    }
    if (box.GetNotificationHashCode(context)) {
        request->SetDistributedHashCode(context);
    }
    request->SetDistributedCollaborate(true);
    request->SetLabel(DISTRIBUTED_LABEL);
}

void DistributedPublishService::MakeNotificationIcon(const NotificationRequestBox& box,
    sptr<NotificationRequest>& request, bool isCommonLiveView)
{
    std::shared_ptr<Media::PixelMap> icon;
    if (box.GetBigIcon(icon)) {
        request->SetBigIcon(icon);
    }
    if (box.GetOverlayIcon(icon)) {
        request->SetOverlayIcon(icon);
    }

    if (isCommonLiveView) {
        std::string bundleName;
        if (!box.GetCreatorBundleName(bundleName)) {
            return;
        }
        std::string icon;
        DistributedPreferences::GetInstance().GetIconByBundleName(bundleName, icon);
        if (!icon.empty()) {
            auto iconPixelMap = AnsImageUtil::UnPackImage(icon);
            request->SetLittleIcon(iconPixelMap);
        }
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
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewDecodeContent(request, buffer);
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
