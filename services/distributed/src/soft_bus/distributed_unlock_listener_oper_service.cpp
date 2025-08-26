/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifdef DISTRIBUTED_FEATURE_MASTER
#include "distributed_unlock_listener_oper_service.h"

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#include "notification_helper.h"
#include "time_service_client.h"
#include "analytics_util.h"
#include "distributed_data_define.h"

namespace OHOS {
namespace Notification {
namespace {
    static const int64_t OPERATION_TIMEOUT = 30 * 1000;
}
void UnlockListenerTimerInfo::OnTrigger()
{
    UnlockListenerOperService::GetInstance().HandleOperationTimeOut(timerHashCode_);
}

UnlockListenerOperService& UnlockListenerOperService::GetInstance()
{
    static UnlockListenerOperService unlockListenerOperService;
    return unlockListenerOperService;
}

UnlockListenerOperService::UnlockListenerOperService()
{
    operationQueue_ = std::make_shared<ffrt::queue>("ans_operation");
    if (operationQueue_ == nullptr) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
    ANS_LOGI("Operation service init successfully.");
}

void UnlockListenerOperService::AddDelayTask(const std::string& hashCode, const int32_t jumpType,
    const int32_t deviceType, const int32_t btnIndex)
{
    int32_t timeout = OPERATION_TIMEOUT;
    int64_t expiredTime = GetCurrentTime() + timeout;
    std::shared_ptr<UnlockListenerTimerInfo> timerInfo = std::make_shared<UnlockListenerTimerInfo>(hashCode);
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    uint64_t timerId = timer->CreateTimer(timerInfo);
    timer->StartTimer(timerId, expiredTime);
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto iterDelayTask = delayTaskMap_.find(hashCode);
    if (iterDelayTask != delayTaskMap_.end()) {
        ANS_LOGW("Operation delayTask has same key %{public}s.", hashCode.c_str());
        delayTaskMap_.erase(iterDelayTask);
    }
    NotifictionJumpInfo jumpInfo = NotifictionJumpInfo(jumpType, btnIndex, deviceType, GetCurrentTime());
    delayTaskMap_.insert_or_assign(hashCode, jumpInfo);

    auto iterTimer = timerMap_.find(hashCode);
    if (iterTimer != timerMap_.end()) {
        ANS_LOGW("Operation timer has same key %{public}s.", hashCode.c_str());
        if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
            return;
        }
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
        timerMap_.erase(iterTimer);
    }
    timerMap_.insert_or_assign(hashCode, timerId);
    auto iterOder = std::find(hashCodeOrder_.begin(), hashCodeOrder_.end(), hashCode);
    if (iterOder != hashCodeOrder_.end()) {
        hashCodeOrder_.erase(iterOder);
    }
    hashCodeOrder_.push_back(hashCode);
    ANS_LOGI("Operation add key %{public}s.", hashCode.c_str());
}

void UnlockListenerOperService::RemoveOperationResponse(const std::string& hashCode)
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    auto iterDelayTask = delayTaskMap_.find(hashCode);
    if (iterDelayTask != delayTaskMap_.end()) {
        delayTaskMap_.erase(iterDelayTask);
        ANS_LOGI("Operation wantAgent erase %{public}s", hashCode.c_str());
    }

    auto iterTimer = timerMap_.find(hashCode);
    if (iterTimer != timerMap_.end()) {
        if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
            return;
        }
        ANS_LOGI("Operation timer erase %{public}s %{public}" PRIu64, hashCode.c_str(), iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
        timerMap_.erase(iterTimer);
    }
    auto iterOder = std::find(hashCodeOrder_.begin(), hashCodeOrder_.end(), hashCode);
    if (iterOder != hashCodeOrder_.end()) {
        hashCodeOrder_.erase(iterOder);
    }
}

void UnlockListenerOperService::ReplyOperationResponse()
{
    std::lock_guard<ffrt::mutex> lock(mapLock_);
    ANS_LOGI("hashCodeOrder size %{public}zu", hashCodeOrder_.size());
    for (std::string hashCode : hashCodeOrder_) {
        auto iterDelayTask = delayTaskMap_.find(hashCode);
        if (iterDelayTask != delayTaskMap_.end()) {
            if (iterDelayTask->second.timeStamp + OPERATION_TIMEOUT > GetCurrentTime()) {
                TriggerByJumpType(hashCode, iterDelayTask->second.jumpType,
                    iterDelayTask->second.deviceTypeId, iterDelayTask->second.btnIndex);
            }
            delayTaskMap_.erase(iterDelayTask);
        }

        auto iterTimer = timerMap_.find(hashCode);
        if (iterTimer != timerMap_.end()) {
            if (iterTimer->second == NotificationConstant::INVALID_TIMER_ID) {
                return;
            }
            MiscServices::TimeServiceClient::GetInstance()->StopTimer(iterTimer->second);
            MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(iterTimer->second);
            timerMap_.erase(iterTimer);
        }
    }
    hashCodeOrder_.clear();
}

void UnlockListenerOperService::HandleOperationTimeOut(const std::string& hashCode)
{
    if (operationQueue_ == nullptr) {
        ANS_LOGE("Operation queue is invalid.");
        return;
    }

    ANS_LOGI("HandleOperationTimeOut hashCode: %{public}s", hashCode.c_str());
    operationQueue_->submit_h([&, hashCode]() {
        RemoveOperationResponse(hashCode);
    });
}

void UnlockListenerOperService::TriggerByJumpType(const std::string& hashCode, const int32_t jumpType,
    const int32_t deviceType, const int32_t btnIndex)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return;
    }
    NotificationConstant::SlotType slotType = notificationRequest->GetSlotType();
    if (jumpType >= NotificationConstant::DISTRIBUTE_JUMP_BY_LIVE_VIEW) {
        TriggerLiveViewNotification(notificationRequest, slotType, jumpType, deviceType, btnIndex);
        return;
    }
    if (notificationRequest->IsCommonLiveView()) {
        ANS_LOGE("jumpType not for liveView but notification is liveView.");
        return;
    }
    bool triggerWantInner = TriggerAncoNotification(notificationRequest, hashCode, deviceType, slotType);
    if (triggerWantInner) {
        return;
    }
    TriggerNotification(hashCode, jumpType, deviceType, btnIndex, slotType);
}

void UnlockListenerOperService::TriggerLiveViewNotification(
    sptr<NotificationRequest>& notificationRequest,
    const NotificationConstant::SlotType& slotType,
    const int32_t jumpType, const int32_t deviceType, const int32_t btnIndex)
{
    if (!notificationRequest->IsCommonLiveView()) {
        ANS_LOGE("jumpType for liveView but notification not liveView.");
        return;
    }
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->DistributedLiveViewOperation(
        notificationRequest, jumpType, btnIndex);
    AnalyticsUtil::GetInstance().OperationalReporting(deviceType, HaOperationType::COLLABORATE_JUMP, slotType);
    ANS_LOGI("DistributedLiveViewOperation res: %{public}d.", static_cast<int32_t>(res));
}

bool UnlockListenerOperService::TriggerAncoNotification(const sptr<NotificationRequest>& notificationRequest,
    const std::string& hashCode, const int32_t deviceType, const NotificationConstant::SlotType& slotType)
{
    bool triggerWantInner;
    if (DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->DistributedAncoNotificationClick(
        notificationRequest, triggerWantInner) != ERR_OK) {
        return triggerWantInner;
    }
    if (triggerWantInner) {
        ANS_LOGI("TriggerAncoNotification success.");
        std::vector<std::string> hashcodes;
        hashcodes.push_back(hashCode);
        NotificationHelper::RemoveNotifications(
            hashcodes, NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE);
        AnalyticsUtil::GetInstance().OperationalReporting(deviceType, HaOperationType::COLLABORATE_JUMP, slotType);
    }
    return triggerWantInner;
}

void UnlockListenerOperService::TriggerNotification(const std::string& hashCode, const int32_t jumpType,
    const int32_t deviceType, const int32_t btnIndex, const NotificationConstant::SlotType& slotType)
{
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr = nullptr;
    if (jumpType == NotificationConstant::DISTRIBUTE_JUMP_BY_NTF) {
        wantAgentPtr = GetNtfWantAgentPtr(hashCode);
    } else if (jumpType == NotificationConstant::DISTRIBUTE_JUMP_BY_BTN) {
        GetNtfBtnWantAgentPtr(hashCode, btnIndex, wantAgentPtr);
    }

    if (wantAgentPtr == nullptr) {
        ANS_LOGE("DealMultiScreenSyncOper fail cause wantAgentPtr is null.");
        return;
    }
    if (LaunchWantAgent(wantAgentPtr) == ERR_OK) {
        AnalyticsUtil::GetInstance().OperationalReporting(deviceType, HaOperationType::COLLABORATE_JUMP, slotType);
        std::vector<std::string> hashcodes;
        hashcodes.push_back(hashCode);
        NotificationHelper::RemoveNotifications(
            hashcodes, NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE);
    }
}

ErrCode UnlockListenerOperService::GetNtfBtnWantAgentPtr(const std::string& hashCode,
    const int32_t btnIndex, std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>& wantAgentPtr)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }

    auto actionButtons = notificationRequest->GetActionButtons();
    if (actionButtons.empty() || actionButtons.size() <= static_cast<unsigned long>(btnIndex) || btnIndex < 0) {
        ANS_LOGE("Check actionButtons is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::shared_ptr<NotificationActionButton> clickedBtn;
    int32_t replyBtnNum = 0;
    for (int i = 0; i < static_cast<int32_t>(actionButtons.size()) &&
        btnIndex + replyBtnNum < static_cast<int32_t>(actionButtons.size()); i++) {
        if (actionButtons[i] == nullptr) {
            ANS_LOGE("NotificationRequest button is invalid, button index: %{public}d.", i);
            return ERR_ANS_INVALID_PARAM;
        }
        if (actionButtons[i]->GetUserInput() != nullptr) {
            replyBtnNum++;
            continue;
        }
        if (btnIndex + replyBtnNum == i) {
            clickedBtn = actionButtons[i];
        }
    }
    if (clickedBtn == nullptr) {
        ANS_LOGE("NotificationRequest btnIndex is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    wantAgentPtr = clickedBtn->GetWantAgent();
    if (wantAgentPtr == nullptr) {
        ANS_LOGE("Check wantAgentPtr is null.");
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> UnlockListenerOperService::GetNtfWantAgentPtr(
    const std::string& hashCode)
{
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    if (result != ERR_OK || notificationRequest == nullptr) {
        ANS_LOGE("Check notificationRequest is null.");
        return nullptr;
    }
    return notificationRequest->GetWantAgent();
}

ErrCode UnlockListenerOperService::LaunchWantAgent(
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgentPtr)
{
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    OHOS::AbilityRuntime::WantAgent::TriggerInfo triggerInfo("", nullptr, want, 0);
    sptr<AbilityRuntime::WantAgent::CompletedDispatcher> data;
    ErrCode res =
        AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(wantAgentPtr, nullptr, triggerInfo, data, nullptr);
    ANS_LOGI("LaunchWantAgent result: %{public}d.", static_cast<int32_t>(res));
    return res;
}

int64_t UnlockListenerOperService::GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}
}
}
#endif
