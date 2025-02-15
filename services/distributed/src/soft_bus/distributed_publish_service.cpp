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

namespace OHOS {
namespace Notification {

namespace {
constexpr char const DISTRIBUTED_LABEL[] = "ans_distributed";
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

void DistributedService::SetNotifictaionContent(const NotifticationRequestBox& box, sptr<NotificationRequest>& request,
    int32_t contentType)
{
    std::string title;
    std::string context;
    box.GetNotificationText(context);
    box.GetNotificationTitle(title);
    std::shared_ptr<NotificationContent> content;
    NotificationContent::Type type = static_cast<NotificationContent::Type>(contentType);
    switch (type) {
        case NotificationContent::Type::BASIC_TEXT: {
            auto pContent = std::make_shared<NotificationNormalContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::CONVERSATION: {
            auto pContent = std::make_shared<NotificationConversationalContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::LONG_TEXT: {
            auto pContent = std::make_shared<NotificationLongTextContent>();
            pContent->SetLongText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::MULTILINE: {
            auto pContent = std::make_shared<NotificationMultiLineContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        case NotificationContent::Type::PICTURE: {
            auto pContent = std::make_shared<NotificationPictureContent>();
            pContent->SetText(context);
            pContent->SetTitle(title);
            content = std::make_shared<NotificationContent>(pContent);
            break;
        }
        default:
            break;
    }
    request->SetContent(content);
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
        uint32_t controlFlags = 0;
        if (!(type & NotificationConstant::ReminderFlag::SOUND_FLAG)) {
            controlFlags |= NotificationConstant::ReminderFlag::SOUND_FLAG;
        }
        if (!(type & NotificationConstant::ReminderFlag::VIBRATION_FLAG)) {
            controlFlags |= NotificationConstant::ReminderFlag::VIBRATION_FLAG;
        }
        request->SetNotificationControlFlags(controlFlags);
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

void DistributedService::HandleResponseSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    NotificationResponseBox responseBox = NotificationResponseBox(boxMessage);
    std::string hashCode;
    responseBox.GetNotificationHashCode(hashCode);
    ANS_LOGI("handle response, hashCode: %{public}s.", hashCode.c_str());

    sptr<NotificationRequest> notificationRequest = new (std::nothrow) NotificationRequest();
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return;
    }

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = notificationRequest->GetWantAgent();
    if (wantAgentPtr == nullptr) {
        ANS_LOGE("Check wantAgentPtr is null.");
        return;
    }

    std::shared_ptr<AbilityRuntime::WantAgent::PendingWant> pendingWantPtr = wantAgentPtr->GetPendingWant();
    if (pendingWantPtr == nullptr) {
        ANS_LOGE("Check pendingWantPtr is null.");
        return;
    }

    std::shared_ptr<AAFwk::Want> wantPtr = pendingWantPtr->GetWant(pendingWantPtr->GetTarget());
    if (wantPtr == nullptr) {
        ANS_LOGE("Check wantPtr is null.");
        return;
    }
    ANS_LOGI("want uri:%{public}s", wantPtr->GetElement().GetURI().c_str());
    bool isScreenOn = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    ANS_LOGI("isScreenOn: %{public}d", isScreenOn);
    if (!isScreenOn) {
        auto ret = PowerMgr::PowerMgrClient::GetInstance().WakeupDevice();
        if (ret != PowerMgr::PowerErrors::ERR_OK) {
            ANS_LOGW("Wake up device %{public}d", ret);
            return;
        }
    }

    code_ = MODIFY_ERROR_EVENT_CODE;
    bool isScreenLocked = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
    ANS_LOGI("Screen locked status, isScreenLocked: %{public}d.", isScreenLocked);
    if (isScreenLocked) {
        OperationInfo info;
        info.type = OperationType::OPERATION_CLICK_JUMP;
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
}
}
