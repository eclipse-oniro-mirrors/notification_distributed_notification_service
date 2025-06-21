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

#include "distributed_operation_service.h"

#include "response_box.h"
#include "match_box.h"
#include "ans_inner_errors.h"
#include "notification_helper.h"
#include "distributed_data_define.h"
#include "distributed_device_service.h"
#include "distributed_unlock_listener_oper_service.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "analytics_util.h"
#include "distributed_client.h"
#include "power_mgr_client.h"
#include "ans_inner_errors.h"
#include "distributed_operation_helper.h"
#include "ability_manager_helper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "screenlock_manager.h"

namespace OHOS {
namespace Notification {

static const std::string DISTRIBUTED_LABEL = "ans_distributed";

DistributedOperationService& DistributedOperationService::GetInstance()
{
    static DistributedOperationService distributedOperationService;
    return distributedOperationService;
}

void DistributedOperationService::HandleNotificationOperation(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t operationType = 0;
    int32_t matchType = 0;
    int32_t peerDeviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH;
    std::string hashCode;
    NotificationResponseBox responseBox = NotificationResponseBox(boxMessage);
    responseBox.GetOperationType(operationType);
    responseBox.GetMatchType(matchType);
    responseBox.GetNotificationHashCode(hashCode);
    responseBox.GetLocalDeviceType(peerDeviceType);
    ANS_LOGI("handle response, hashCode: %{public}s, operationType: %{public}d, matchType: %{public}d \
        peerDeviceType: %{public}d.", hashCode.c_str(), operationType, matchType, peerDeviceType);
#ifdef DISTRIBUTED_FEATURE_MASTER
    if (peerDeviceType != DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD &&
        peerDeviceType != DistributedHardware::DmDeviceType::DEVICE_TYPE_PC) {
        DealNonMultiScreenSyncOper(hashCode, operationType, matchType, responseBox);
        return;
    }
    DealMultiScreenSyncOper(hashCode, operationType, matchType, responseBox);
#else
    if (matchType == MatchType::MATCH_ACK) {
        ResponseOperationResult(hashCode, responseBox);
    }
#endif
}

#ifdef DISTRIBUTED_FEATURE_MASTER
static int64_t GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

static void TriggerReplyWantAgent(const sptr<NotificationRequest> request,
    std::string actionName, int32_t errorCode, std::string desc)
{
    AAFwk::WantParams extraInfo;
    extraInfo.SetParam("desc", AAFwk::String::Box(desc));
    extraInfo.SetParam("errorCode", AAFwk::Integer::Box(errorCode));
    extraInfo.SetParam("actionName", AAFwk::String::Box(actionName));
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->TriggerPushWantAgent(request,
        OperationType::DISTRIBUTE_OPERATION_REPLY, extraInfo);
}

static ErrCode GetNotificationButtonWantPtr(const std::string& hashCode, const std::string& actionName,
    std::shared_ptr<AAFwk::Want>& wantPtr, sptr<NotificationRequest>& request, std::string& userInputKey)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }

    request = notificationRequest;
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
    if (button->GetUserInput() != nullptr) {
        userInputKey = button->GetUserInput()->GetInputKey();
    }
    if (userInputKey.empty()) {
        ANS_LOGE("Check userInputKey is null.");
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

static ErrCode GetNotificationButtonWantAgentPtr(const std::string& hashCode,
    const int32_t btnIndex, std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>& wantAgentPtr)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }

    auto actionButtons = notificationRequest->GetActionButtons();
    if (actionButtons.empty() || actionButtons.size() <= static_cast<unsigned long>(btnIndex)) {
        ANS_LOGE("Check actionButtons is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    auto clickedBtn = actionButtons[btnIndex];
    if (clickedBtn == nullptr) {
        ANS_LOGE("NotificationRequest button is invalid, btnIndex: %{public}d.", btnIndex);
        return ERR_ANS_INVALID_PARAM;
    }

    wantAgentPtr = clickedBtn->GetWantAgent();
    if (wantAgentPtr == nullptr) {
        ANS_LOGE("Check wantAgentPtr is null.");
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

static std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetNotificationWantAgentPtr(const std::string& hashCode)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return nullptr;
    }
    return notificationRequest->GetWantAgent();
}

static std::shared_ptr<AAFwk::Want> GetNotificationWantPtr(const std::string& hashCode)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
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

void DistributedOperationService::ReplyOperationResponse(const std::string& hashCode,
    const NotificationResponseBox& responseBox, OperationType operationType, uint32_t result)
{
    std::string eventId;
    std::string deviceId;
    responseBox.GetOperationEventId(eventId);
    responseBox.GetLocalDeviceId(deviceId);

    if (!DistributedDeviceService::GetInstance().CheckDeviceExist(deviceId)) {
        ANS_LOGI("Dans get deviceId unknonw %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }

    std::shared_ptr<NotificationResponseBox> replyBox = std::make_shared<NotificationResponseBox>();
    replyBox->SetResponseResult(result);
    replyBox->SetNotificationHashCode(hashCode);
    replyBox->SetOperationEventId(eventId);
    replyBox->SetMatchType(MatchType::MATCH_ACK);
    replyBox->SetOperationType(operationType);

    if (!replyBox->Serialize()) {
        ANS_LOGW("dans OnResponse reply serialize failed");
        return;
    }
    auto ret = DistributedClient::GetInstance().SendMessage(replyBox, TransDataType::DATA_TYPE_MESSAGE,
        deviceId, MODIFY_ERROR_EVENT_CODE);
    if (ret != ERR_OK) {
        ANS_LOGE("dans OnResponse send message failed result: %{public}d", ret);
        return;
    }
    ANS_LOGI("Dans reply operation %{public}s %{public}d.", StringAnonymous(deviceId).c_str(), result);
    return;
}

int32_t DistributedOperationService::TriggerReplyApplication(const std::string& hashCode,
    const NotificationResponseBox& responseBox)
{
    std::string actionName;
    std::string userInput;
    std::string userInputKey;
    responseBox.GetActionName(actionName);
    responseBox.GetUserInput(userInput);

    std::shared_ptr<AAFwk::Want> wantPtr = nullptr;
    sptr<NotificationRequest> request = nullptr;
    auto result = GetNotificationButtonWantPtr(hashCode, actionName, wantPtr, request, userInputKey);
    if (result != ERR_OK || wantPtr == nullptr) {
        AnalyticsUtil::GetInstance().AbnormalReporting(MODIFY_ERROR_EVENT_CODE, result,
            BRANCH4_ID, "reply get button failed");
        TriggerReplyWantAgent(request, actionName, result, "reply get button failed");
        return result;
    }

    if (wantPtr->GetBoolParam(AAFwk::Want::PARAM_RESV_CALL_TO_FOREGROUND, false)) {
        ANS_LOGE("Not support foreground.");
        AnalyticsUtil::GetInstance().AbnormalReporting(MODIFY_ERROR_EVENT_CODE, ERR_ANS_DISTRIBUTED_OPERATION_FAILED,
            BRANCH4_ID, "reply foreground failed");
        TriggerReplyWantAgent(request, actionName, ERR_ANS_DISTRIBUTED_OPERATION_FAILED, "reply foreground failed");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    auto ret = AbilityManagerHelper::GetInstance().ConnectAbility(hashCode, *wantPtr, userInputKey, userInput);
    ANS_LOGI("StartAbility result:%{public}d", ret);
    if (ret == ERR_OK) {
        TriggerReplyWantAgent(request, actionName, ERR_OK, "");
        AnalyticsUtil::GetInstance().OperationalReporting(BRANCH4_ID,
            NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    } else {
        TriggerReplyWantAgent(request, actionName, ret, "ability reply failed");
        AnalyticsUtil::GetInstance().AbnormalReporting(MODIFY_ERROR_EVENT_CODE, ret,
            BRANCH4_ID, "ability reply failed");
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return ERR_OK;
}

void DistributedOperationService::TriggerJumpApplication(const std::string& hashCode)
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

    if (ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked()) {
        OperationInfo info;
        info.type = OperationType::DISTRIBUTE_OPERATION_JUMP;
        info.eventId = std::to_string(GetCurrentTime());
        sptr<UnlockScreenCallback> listener = new (std::nothrow) UnlockScreenCallback(info.eventId);
        int32_t unlockResult =
            ScreenLock::ScreenLockManager::GetInstance()->Unlock(ScreenLock::Action::UNLOCKSCREEN, listener);
        ANS_LOGI("unlock result:%{public}d", unlockResult);
        if (unlockResult != ERR_OK) {
            AnalyticsUtil::GetInstance().AbnormalReporting(MODIFY_ERROR_EVENT_CODE, unlockResult,
                BRANCH6_ID, "unlock failed");
        }
        info.want = *wantPtr;
        OperationService::GetInstance().AddOperation(info);
    } else {
        auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(*wantPtr);
        ANS_LOGI("StartAbility result:%{public}d", ret);
        if (ret == ERR_OK) {
            AnalyticsUtil::GetInstance().OperationalReporting(BRANCH3_ID, NotificationConstant::SlotType::LIVE_VIEW);
        } else {
             AnalyticsUtil::GetInstance().AbnormalReporting(MODIFY_ERROR_EVENT_CODE, 0, ret, "pull up failed");
        }
        AnalyticsUtil::GetInstance().AbnormalReporting(MODIFY_ERROR_EVENT_CODE, ret, BRANCH9_ID, "pull up success");
    }
}

void DistributedOperationService::DealNonMultiScreenSyncOper(const std::string& hashCode,
    const int32_t operationType, const int32_t matchType, const NotificationResponseBox &responseBox)
{
    if (matchType != MatchType::MATCH_SYN) {
        return;
    }
    if (static_cast<OperationType>(operationType) == OperationType::DISTRIBUTE_OPERATION_JUMP) {
        TriggerJumpApplication(hashCode);
    } else if (static_cast<OperationType>(operationType) == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        ErrCode result = TriggerReplyApplication(hashCode, responseBox);
        ReplyOperationResponse(hashCode, responseBox, OperationType::DISTRIBUTE_OPERATION_REPLY, result);
    }
}

void DistributedOperationService::DealMultiScreenSyncOper(const std::string& hashCode,
    const int32_t operationType, const int32_t matchType, const NotificationResponseBox &responseBox)
{
    if (matchType != MatchType::MATCH_SYN) {
        return;
    }
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = nullptr;
    if (operationType >= static_cast<int32_t>(OperationType::DISTRIBUTE_OPERATION_FOR_LIVE_VIEW)) {
        sptr<NotificationRequest> notificationRequest = nullptr;
        auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
        if (result != ERR_OK || notificationRequest == nullptr) {
            ANS_LOGE("Check notificationRequest is null.");
            return;
        }
        if (!notificationRequest->IsCommonLiveView()) {
            ANS_LOGE("operationType for liveView but notification not liveView.");
            return;
        }
        int32_t btnIndex;
        responseBox.GetOperationBtnIndex(btnIndex);
        ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->LiveViewMultiScreenSyncOper(
            notificationRequest, operationType, btnIndex);
        ANS_LOGI("LiveViewMultiScreenSyncOper res: %{public}d.", static_cast<int32_t>(res));
        return;
    } else if (static_cast<OperationType>(operationType) == OperationType::DISTRIBUTE_OPERATION_JUMP) {
        wantAgentPtr = GetNotificationWantAgentPtr(hashCode);
    } else if (static_cast<OperationType>(operationType) == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        int32_t btnIndex;
        responseBox.GetOperationBtnIndex(btnIndex);
        GetNotificationButtonWantAgentPtr(hashCode, btnIndex, wantAgentPtr);
    }

    if (wantAgentPtr == nullptr) {
        ANS_LOGE("DealMultiScreenSyncOper fail cause wantAgentPtr is null.");
        return;
    }
    if (!ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked() &&
        UnlockListenerOperService::GetInstance().LaunchWantAgent(wantAgentPtr) == ERR_OK) {
        std::vector<std::string> hashcodes;
        hashcodes.push_back(hashCode);
        NotificationHelper::RemoveNotifications(
            hashcodes, NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE);
        return;
    }
    UnlockListenerOperService::GetInstance().AddWantAgent(hashCode, wantAgentPtr);
}
#else

int32_t DistributedOperationService::OnOperationResponse(
    const std::shared_ptr<NotificationOperationInfo>& operationInfo, const DistributedDeviceInfo& device)
{
    std::shared_ptr<NotificationResponseBox> responseBox = std::make_shared<NotificationResponseBox>();
    ANS_LOGI("dans OnResponse %{public}s", operationInfo->Dump().c_str());
    if (operationInfo == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }
    auto hashCode = operationInfo->GetHashCode();
    if (hashCode.find(DISTRIBUTED_LABEL) == 0) {
        hashCode.erase(0, DISTRIBUTED_LABEL.length());
    }

    OperationType type = operationInfo->GetOperationType();
    if (type == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        if (!responseBox->SetMessageType(NOTIFICATION_RESPONSE_REPLY_SYNC)) {
            ANS_LOGW("dans OnResponse SetMessageType failed");
            return ERR_ANS_TASK_ERR;
        }
        ANS_LOGI("dans OnResponse clicked btnIndex: %{public}d", operationInfo->GetBtnIndex());
        if (0 <= operationInfo->GetBtnIndex() && operationInfo->GetBtnIndex() < NotificationConstant::MAX_BTN_NUM) {
            responseBox->SetOperationBtnIndex(operationInfo->GetBtnIndex());
        }
        responseBox->SetActionName(operationInfo->GetActionName());
        responseBox->SetUserInput(operationInfo->GetUserInput());
    }

    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    responseBox->SetMatchType(MatchType::MATCH_SYN);
    responseBox->SetOperationType(static_cast<int32_t>(type));
    responseBox->SetNotificationHashCode(hashCode);
    responseBox->SetOperationEventId(operationInfo->GetEventId());
    responseBox->SetLocalDeviceId(localDevice.deviceId_);
    responseBox->SetLocalDeviceType(localDevice.deviceType_);
    if (!responseBox->Serialize()) {
        ANS_LOGW("dans OnResponse serialize failed");
        return ERR_ANS_TASK_ERR;
    }

    LaunchProjectionApp(device, localDevice);
    auto result = DistributedClient::GetInstance().SendMessage(responseBox, TransDataType::DATA_TYPE_MESSAGE,
        device.deviceId_, MODIFY_ERROR_EVENT_CODE);
    if (result != ERR_OK) {
        ANS_LOGE("dans OnResponse send message failed result: %{public}d", result);
        result = ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return result;
}

void DistributedOperationService::ResponseOperationResult(const std::string& hashCode,
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

void DistributedOperationService::LaunchProjectionApp(
    const DistributedDeviceInfo& device, const DistributedDeviceInfo& localDevice)
{
    if ((localDevice.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD &&
        localDevice.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PC) ||
        device.deviceType_ != DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
        ANS_LOGI("Can not launch projectionApp");
        return;
    }
    int32_t result =
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->RestoreCollaborationWindow(device.networkId_);
    ANS_LOGI("RestoreCollaborationWindow result: %{public}d, networkId: %{public}s",
        result, device.networkId_.c_str());
}
#endif
}
}
