/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "advanced_notification_service.h"

#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "ans_service_errors.h"
#include "ipc_skeleton.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
#include "priority_notification_degrade_manager.h"
#endif

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::SetNotificationSwitch(const std::string &switchName, bool enable, int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    // Validate switchName parameter
    if (!NotificationConstant::NotificationSwitch::IsValidNotificationSwitch(switchName)) {
        ANS_LOGE("Set invalid switchName: %{public}s", switchName.c_str());
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Non-system app calling SetNotificationSwitch");
        return ERR_ANS_INNER_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied for SetNotificationSwitch");
        return ERR_ANS_INNER_PERMISSION_DENIED;
    }

    // Validate userId parameter
    if (!OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        ANS_LOGE("Check user exists failed.");
        return ERR_ANS_INNER_GET_ACTIVE_USER_FAILED;
    }
    ErrCode result = ERR_OK;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        NotificationConstant::SWITCH_STATE oldState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
        NotificationPreferences::GetInstance()->GetNotificationSwitch(switchName, userId, oldState);
        NotificationConstant::SWITCH_STATE switchState = enable ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
        result = NotificationPreferences::GetInstance()->SetNotificationSwitch(switchName, switchState, userId);
        if (result == ERR_OK && oldState != switchState) {
            // Notify subscribers about the switch change
            sptr<NotificationSwitchChangedCallbackData> callbackData =
                new (std::nothrow) NotificationSwitchChangedCallbackData(switchName, userId, switchState);
            if (callbackData == nullptr) {
                ANS_LOGE("Failed to create EnabledAggregationSwitchCallbackData");
                result = ERR_NO_MEMORY;
            } else {
                NotificationSubscriberManager::GetInstance()->NotifyNotificationSwitchChanged(callbackData);
            }
        }
    }));
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_25);
    message.Message(
        "switchName:" + switchName + ", en:" + std::to_string(enable) + ", userId:" + std::to_string(userId));
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetNotificationSwitch success: switchName=%{public}s, state=%{public}d, userId=%{public}d",
        switchName.c_str(), enable, userId);
    return result;
}

ErrCode AdvancedNotificationService::GetNotificationSwitch(
    const std::string &switchName, int32_t userId, int32_t &state)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    // Validate switchName parameter
    if (!NotificationConstant::NotificationSwitch::IsValidNotificationSwitch(switchName)) {
        ANS_LOGE("Get invalid switchName: %{public}s", switchName.c_str());
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Non-system app calling GetNotificationSwitch");
        return ERR_ANS_INNER_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied for GetNotificationSwitch");
        return ERR_ANS_INNER_PERMISSION_DENIED;
    }

    // Validate userId parameter
    if (!OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        ANS_LOGE("Check user exists failed.");
        return ERR_ANS_INNER_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
        result = NotificationPreferences::GetInstance()->GetNotificationSwitch(switchName, userId, switchState);
        if (result == ERR_OK) {
            state = static_cast<int32_t>(switchState);
            ANS_LOGI("GetNtfSwitch: name=%{public}s, sta=%{public}d, userId=%{public}d",
                switchName.c_str(), state, userId);
        }
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Get aggregation switch.");
    return result;
}

ErrCode AdvancedNotificationService::TriggerUpdateAiExtNotification(const sptr<NotificationRequest> &request,
    const sptr<NotificationClassification> &notificationClassification)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (request == nullptr) {
        ANS_LOGE("Invalid request");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }

    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        auto record = GetFromNotificationList(request->GetBaseKey(""));
        if (record == nullptr || record->notification == nullptr) {
            ANS_LOGE("Notification not found for key: %{public}s", request->GetBaseKey("").c_str());
            return;
        }

        auto cacheRequest = record->notification->GetNotificationRequestPoint();
        if (cacheRequest == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, cache request not exist");
            result = ERR_ANS_INNER_INVALID_PARAM;
            return;
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        ProcessDelayedUpdateOnQueue(record, cacheRequest, request, notificationClassification, result);
#else
        cacheRequest->SetInnerPriorityNotificationType(request->GetPriorityNotificationType());
        sptr<Notification> notification = new (std::nothrow) Notification(request);
        if (notification == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, null notification");
            result = ERR_NO_MEMORY;
            return;
        }

        // Notify subscribers about the updated notification
        NotificationSubscriberManager::GetInstance()->NotifySystemUpdate(notification, notificationClassification);
#endif
    }));

    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Trigger update AI extension notification.");
    ANS_LOGI("TriggerUpdateAiExtNotification key: %{public}s, result: %{public}d", request->GetKey().c_str(), result);
    return ERR_OK;
}

#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
void AdvancedNotificationService::ProcessDelayedUpdateOnQueue(const std::shared_ptr<NotificationRecord> &record,
    const sptr<NotificationRequest> &cacheRequest, const sptr<NotificationRequest> &request,
    const sptr<NotificationClassification> &notificationClassification, ErrCode &result)
{
    std::string notificationKey = record->notification->GetKey();
    sptr<NotificationClassification> effectiveClassification = nullptr;
    auto arbitrate = PriorityNotificationDegradeManager::GetInstance()->ApplyTaggingResult(
        notificationKey, cacheRequest, notificationClassification, effectiveClassification);
    if (arbitrate == PriorityNotificationDegradeManager::ArbitrateResult::DROP_IMMUTABLE
        || arbitrate == PriorityNotificationDegradeManager::ArbitrateResult::DROP_DEGRADED
        || arbitrate == PriorityNotificationDegradeManager::ArbitrateResult::CLEARED) {
        HandleDroppedDelayedUpdate(notificationKey, request, notificationClassification,
            effectiveClassification, result);
        return;
    }

    HandleAcceptedDelayedUpdate(request, cacheRequest, effectiveClassification, result);
}

void AdvancedNotificationService::HandleDroppedDelayedUpdate(const std::string &notificationKey,
    const sptr<NotificationRequest> &request,
    const sptr<NotificationClassification> &notificationClassification,
    const sptr<NotificationClassification> &effectiveClassification, ErrCode &result)
{
    if (notificationClassification == nullptr) {
        return;
    }
    std::string effectiveType = NotificationConstant::PriorityNotificationType::OTHER;
    if (effectiveClassification != nullptr) {
        effectiveType = effectiveClassification->GetPriorityInfo().GetPriorityNotificationType();
    }
    sptr<NotificationRequest> payloadRequest = new (std::nothrow) NotificationRequest(*request);
    if (payloadRequest == nullptr) {
        ANS_LOGE("TriggerUpdateAiExtNotification fail, null payload request, key: %{public}s",
            notificationKey.c_str());
        result = ERR_NO_MEMORY;
        return;
    }
    payloadRequest->SetInnerPriorityNotificationType(effectiveType);
    sptr<Notification> dropNotification = new (std::nothrow) Notification(payloadRequest);
    if (dropNotification == nullptr) {
        ANS_LOGE("TriggerUpdateAiExtNotification fail, null notification, key: %{public}s",
            notificationKey.c_str());
        result = ERR_NO_MEMORY;
        return;
    }

    NotificationSubscriberManager::GetInstance()->NotifySystemUpdate(
        dropNotification, effectiveClassification);
}

void AdvancedNotificationService::HandleAcceptedDelayedUpdate(const sptr<NotificationRequest> &request,
    const sptr<NotificationRequest> &cacheRequest,
    const sptr<NotificationClassification> &effectiveClassification, ErrCode &result)
{
    std::string effectiveType = NotificationConstant::PriorityNotificationType::OTHER;
    if (effectiveClassification != nullptr) {
        effectiveType = effectiveClassification->GetPriorityInfo().GetPriorityNotificationType();
    }
    cacheRequest->SetInnerPriorityNotificationType(effectiveType);
    sptr<NotificationRequest> payloadRequest = new (std::nothrow) NotificationRequest(*request);
    if (payloadRequest == nullptr) {
        ANS_LOGE("TriggerUpdateAiExtNotification fail, null payload request, key: %{public}s",
            request->GetKey().c_str());
        result = ERR_NO_MEMORY;
        return;
    }
    payloadRequest->SetInnerPriorityNotificationType(effectiveType);
    sptr<Notification> notification = new (std::nothrow) Notification(payloadRequest);
    if (notification == nullptr) {
        ANS_LOGE("TriggerUpdateAiExtNotification fail, null notification, key: %{public}s",
            request->GetKey().c_str());
        result = ERR_NO_MEMORY;
        return;
    }

    NotificationSubscriberManager::GetInstance()->NotifySystemUpdate(
        notification, effectiveClassification);
}
#endif
}
}
