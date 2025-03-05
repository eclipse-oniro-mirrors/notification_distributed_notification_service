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

#include <sstream>

#include "distributed_service.h"

#include "ability_manager_client.h"
#include "notification_helper.h"
#include "distributed_client.h"
#include "request_box.h"
#include "state_box.h"
#include "ans_image_util.h"
#include "in_process_call_wrapper.h"
#include "distributed_observer_service.h"
#include "distributed_preference.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "response_box.h"
#include "power_mgr_client.h"
#include "distributed_local_config.h"
#include "distributed_operation_service.h"
#include "notification_sync_box.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {

namespace {
const std::string DISTRIBUTED_LABEL = "ans_distributed";
constexpr const int32_t ANS_CUSTOMIZE_CODE = 7;
constexpr const int32_t MODIFY_ERROR_EVENT_CODE = 6;
constexpr const int32_t DELETE_ERROR_EVENT_CODE = 5;
constexpr const int32_t OPERATION_DELETE_BRANCH = 2;
constexpr const int32_t BRANCH3_ID = 3;
constexpr const int32_t BRANCH4_ID = 4;
constexpr const int32_t BRANCH6_ID = 6;
constexpr const int32_t BRANCH9_ID = 9;
}

int64_t GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

struct TransferNotification {
    std::string title;
    std::string context;
    std::string additionalText;
    std::string briefText;
    std::string expandedTitle;
};

void ConvertBoxToLongContent(const TransferNotification& notificationItem, const NotifticationRequestBox& box,
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

void ConvertBoxToMultileContent(const TransferNotification& notificationItem, const NotifticationRequestBox& box,
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

void ConvertBoxToPictureContent(const TransferNotification& notificationItem, const NotifticationRequestBox& box,
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

void DistributedService::SetNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    int32_t contentType)
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

void DistributedService::MakeNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    bool isCommonLiveView, int32_t contentType)
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
    SetNotifictaionContent(box, request, contentType);
}

void DistributedService::MakeNotifictaionIcon(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    bool isCommonLiveView)
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

void DistributedService::MakeNotifictaionReminderFlag(const NotifticationRequestBox& box,
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

void DistributedService::MakeNotificationButtons(const NotifticationRequestBox& box,
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

void DistributedService::PublishNotifictaion(const std::shared_ptr<TlvBox>& boxMessage)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    if (request == nullptr) {
        ANS_LOGE("NotificationRequest is nullptr");
        return;
    }
    int32_t slotType = 0;
    int32_t contentType = 0;
    NotifticationRequestBox requestBox = NotifticationRequestBox(boxMessage);
    bool isCommonLiveView = false;
    if (requestBox.GetSlotType(slotType) && requestBox.GetContentType(contentType)) {
        isCommonLiveView =
            (static_cast<NotificationContent::Type>(contentType) == NotificationContent::Type::LIVE_VIEW) &&
            (static_cast<NotificationConstant::SlotType>(slotType) == NotificationConstant::SlotType::LIVE_VIEW);
    }
    MakeNotificationButtons(requestBox, static_cast<NotificationConstant::SlotType>(slotType), request);
    MakeNotifictaionContent(requestBox, request, isCommonLiveView, contentType);
    MakeNotifictaionIcon(requestBox, request, isCommonLiveView);
    MakeNotifictaionReminderFlag(requestBox, request);
    int result = IN_PROCESS_CALL(NotificationHelper::PublishNotification(*request));
    ANS_LOGI("Dans publish message %{public}s %{public}d.", request->Dump().c_str(), result);
}

void DistributedService::RemoveNotification(const std::shared_ptr<TlvBox>& boxMessage)
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
    code_ = DELETE_ERROR_EVENT_CODE;
    if (result == 0) {
        errorReason = "delete message success";
        AbnormalReporting(result, BRANCH4_ID, errorReason);
        OperationalReporting(OPERATION_DELETE_BRANCH, slotType);
    } else {
        AbnormalReporting(result, BRANCH3_ID, errorReason);
    }
    ANS_LOGI("dans remove message %{public}d.", result);
}

void DistributedService::RemoveNotifications(const std::shared_ptr<TlvBox>& boxMessage)
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
    std::string errorReason = "delete message failed";
    code_ = DELETE_ERROR_EVENT_CODE;
    if (result == 0) {
        errorReason = "delete message success";
        AbnormalReporting(result, BRANCH4_ID, errorReason);
        std::string slotTypesString;
        if (!boxMessage->GetStringValue(BATCH_REMOVE_SLOT_TYPE, slotTypesString)) {
            ANS_LOGE("failed GetStringValue from boxMessage");
            return;
        }
        std::istringstream slotTypesStream(slotTypesString);
        std::string slotTypeString;
        while (slotTypesStream >> slotTypeString) {
            if (!slotTypeString.empty()) {
                OperationalReporting(OPERATION_DELETE_BRANCH, std::stoi(slotTypeString));
            }
        }
    } else {
        AbnormalReporting(result, BRANCH3_ID, errorReason);
    }
}

void DistributedService::AbnormalReporting(int result, uint32_t branchId, const std::string &errorReason)
{
    if (localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }
    if (result != 0) {
        SendEventReport(0, result, errorReason);
    }
    if (haCallback_ == nullptr) {
        return;
    }
    haCallback_(code_, result, branchId, errorReason);
}

void DistributedService::OperationalReporting(int branchId, int32_t slotType)
{
    if (haCallback_ == nullptr ||
        localDevice_.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        return;
    }
    std::string reason;
    haCallback_(ANS_CUSTOMIZE_CODE, slotType, branchId, reason);
}

void DistributedService::HandleNotificationSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    std::unordered_set<std::string> notificationList;
    NotificationSyncBox notificationSyncBox = NotificationSyncBox(boxMessage);
    if (!notificationSyncBox.GetNotificationList(notificationList)) {
        ANS_LOGW("Dans get sync notification failed.");
        return;
    }
    std::vector<sptr<Notification>> notifications;
    auto result = NotificationHelper::GetAllNotificationsBySlotType(notifications,
        NotificationConstant::SlotType::LIVE_VIEW);
    if (result != ERR_OK || notifications.empty() || notificationList.empty()) {
        ANS_LOGI("Dans get all active %{public}d %{public}d.", result, notifications.empty());
        return;
    }

    ANS_LOGI("Dans handle sync notification %{public}u %{public}u.", notificationList.size(),
        notifications.size());
    std::vector<std::string> removeList;
    for (auto& notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr ||
            !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            ANS_LOGI("Dans no need sync remove notification.");
            continue;
        }
        std::string hashCode = notification->GetKey();
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
        int result = IN_PROCESS_CALL(
            NotificationHelper::RemoveNotifications(removeList,
            NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE));
        ANS_LOGI("Dans sync remove message %{public}d.", result);
    }
}

std::shared_ptr<AAFwk::Want> GetNotificationWantPtr(const std::string& hashCode)
{
    sptr<NotificationRequest> notificationRequest = new (std::nothrow) NotificationRequest();
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return nullptr;
    }

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = notificationRequest->GetWantAgent();
    if (wantAgentPtr == nullptr) {
        ANS_LOGE("Check wantAgentPtr is null.");
        return nullptr;
    }

    std::shared_ptr<AbilityRuntime::WantAgent::PendingWant> pendingWantPtr = wantAgentPtr->GetPendingWant();
    if (pendingWantPtr == nullptr) {
        ANS_LOGE("Check pendingWantPtr is null.");
        return nullptr;
    }

    return pendingWantPtr->GetWant(pendingWantPtr->GetTarget());
}

void DistributedService::TriggerJumpApplication(const std::string& hashCode)
{
    auto wantPtr = GetNotificationWantPtr(hashCode);
    if (wantPtr == nullptr) {
        ANS_LOGE("Get pendingWantPtr is null.");
        return;
    }

    if (!PowerMgr::PowerMgrClient::GetInstance().IsScreenOn()) {
        auto ret = PowerMgr::PowerMgrClient::GetInstance().WakeupDevice();
        if (ret != PowerMgr::PowerErrors::ERR_OK) {
            ANS_LOGW("Wake up device %{public}d", ret);
            return;
        }
    }

    code_ = MODIFY_ERROR_EVENT_CODE;
    if (ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()) {
        OperationInfo info;
        info.type = OperationType::DISTRIBUTE_OPERATION_JUMP;
        info.eventId = std::to_string(GetCurrentTime());
        sptr<UnlockScreenCallback> listener = new (std::nothrow) UnlockScreenCallback(info.eventId);
        int32_t unlockResult =
            ScreenLock::ScreenLockManager::GetInstance()->Unlock(ScreenLock::Action::UNLOCKSCREEN, listener);
        ANS_LOGI("unlock result:%{public}d", unlockResult);
        if (unlockResult != ERR_OK) {
            std::string errorReason = "unlock failed";
            AbnormalReporting(unlockResult, BRANCH6_ID, errorReason);
        }
        info.want = *wantPtr;
        OperationService::GetInstance().AddOperation(info);
    } else {
        auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(*wantPtr);
        ANS_LOGI("StartAbility result:%{public}d", ret);
        std::string errorReason = "pull up success";
        if (ret == ERR_OK) {
            OperationalReporting(BRANCH3_ID, NotificationConstant::SlotType::LIVE_VIEW);
        } else {
            errorReason = "pull up failed";
            int32_t messageType = 0;
            AbnormalReporting(messageType, ret, errorReason);
        }
        AbnormalReporting(ret, BRANCH9_ID, errorReason);
    }
}

ErrCode GetNotificationButtonWantPtr(const std::string& hashCode, const std::string& actionName,
    std::shared_ptr<AAFwk::Want>& wantPtr)
{
    sptr<NotificationRequest> notificationRequest = new (std::nothrow) NotificationRequest();
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }

    auto actionButtons = notificationRequest->GetActionButtons();
    if (actionButtons.empty()) {
        ANS_LOGE("Check actionButtons is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::shared_ptr<NotificationActionButton> button = nullptr;
    for (std::shared_ptr<NotificationActionButton> buttonItem : actionButtons) {
        if (buttonItem != nullptr && buttonItem->GetUserInput() != nullptr &&
            buttonItem->GetTitle() == actionName) {
            button = buttonItem;
            break;
        }
    }

    if (button == nullptr) {
        ANS_LOGE("Check user input is null %{public}s.", actionName.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = button->GetWantAgent();
    if (wantAgentPtr == nullptr) {
        ANS_LOGE("Check wantAgentPtr is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::shared_ptr<AbilityRuntime::WantAgent::PendingWant> pendingWantPtr = wantAgentPtr->GetPendingWant();
    if (pendingWantPtr == nullptr) {
        ANS_LOGE("Check pendingWantPtr is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    wantPtr = pendingWantPtr->GetWant(pendingWantPtr->GetTarget());
    if (wantPtr == nullptr) {
        ANS_LOGE("Check wantPtr is null.");
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

ErrCode DistributedService::TriggerReplyApplication(const std::string& hashCode,
    const NotificationResponseBox& responseBox)
{
    std::string actionName;
    std::string userInput;
    responseBox.GetActionName(actionName);
    responseBox.GetUserInput(userInput);

    std::shared_ptr<AAFwk::Want> wantPtr = nullptr;
    auto result = GetNotificationButtonWantPtr(hashCode, actionName, wantPtr);
    if (result != ERR_OK || wantPtr == nullptr) {
        return result;
    }

    auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(*wantPtr);
    ANS_LOGI("StartAbility result:%{public}d", ret);
    if (ret == ERR_OK) {
        OperationalReporting(BRANCH3_ID, NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    } else {
        AbnormalReporting(0, ret, "reply up failed");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}

void DistributedService::HandleOperationResponse(const std::string& hashCode,
    const NotificationResponseBox& responseBox)
{
    int32_t result = 0;
    std::string eventId;
    responseBox.GetOperationEventId(eventId);
    responseBox.GetResponseResult(result);
    auto ret = NotificationHelper::ReplyDistributeOperation(DISTRIBUTED_LABEL + hashCode + eventId, result);
    ANS_LOGI("HandleOperationResponse hashcode %{public}s, result:%{public}d %{public}d",
        hashCode.c_str(), result, ret);
}

void DistributedService::ReplyOperationResponse(const std::string& hashCode,
    const NotificationResponseBox& responseBox, OperationType operationType, uint32_t result)
{
    std::string eventId;
    std::string deviceId;
    responseBox.GetOperationEventId(eventId);
    responseBox.GetLocalDeviceId(deviceId);

    auto iter = peerDevice_.find(deviceId);
    if (iter == peerDevice_.end()) {
        ANS_LOGI("Dans get deviceId unknonw %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }

    NotificationResponseBox replyBox;
    replyBox.SetResponseResult(result);
    replyBox.SetNotificationHashCode(hashCode);
    replyBox.SetOperationEventId(eventId);
    replyBox.SetMatchType(MatchType::MATCH_ACK);
    replyBox.SetOperationType(operationType);

    if (!replyBox.Serialize()) {
        ANS_LOGW("dans OnResponse reply serialize failed");
        return;
    }
    auto ret = DistributedClient::GetInstance().SendMessage(replyBox.GetByteBuffer(), replyBox.GetByteLength(),
        TransDataType::DATA_TYPE_MESSAGE, iter->second.deviceId_, iter->second.deviceType_);
    if (ret != ERR_OK) {
        ANS_LOGE("dans OnResponse send message failed result: %{public}d", ret);
        return;
    }
    ANS_LOGI("Dans reply operation %{public}s %{public}d.", StringAnonymous(iter->second.deviceId_).c_str(), result);
    return;
}

void DistributedService::HandleResponseSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t operationType = 0;
    int32_t matchType = 0;
    std::string hashCode;
    NotificationResponseBox responseBox = NotificationResponseBox(boxMessage);
    responseBox.GetOperationType(operationType);
    responseBox.GetMatchType(matchType);
    responseBox.GetNotificationHashCode(hashCode);
    ANS_LOGI("handle response, hashCode: %{public}s type: %{public}d %{public}d.",
        hashCode.c_str(), operationType, matchType);

    if (matchType == MatchType::MATCH_SYN) {
        if (static_cast<OperationType>(operationType) == OperationType::DISTRIBUTE_OPERATION_JUMP) {
            TriggerJumpApplication(hashCode);
        } else if (static_cast<OperationType>(operationType) == OperationType::DISTRIBUTE_OPERATION_REPLY) {
            ErrCode result = TriggerReplyApplication(hashCode, responseBox);
            ReplyOperationResponse(hashCode, responseBox, OperationType::DISTRIBUTE_OPERATION_REPLY, result);
        }
    } else if (matchType == MatchType::MATCH_ACK) {
        HandleOperationResponse(hashCode, responseBox);
    }
}
}
}
