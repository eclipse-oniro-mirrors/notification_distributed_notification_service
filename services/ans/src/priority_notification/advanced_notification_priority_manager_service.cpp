/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "advanced_notification_priority_helper.h"
#include "ans_permission_def.h"
#include "common_event_manager.h"
#include "common_event_publish_info.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_preferences.h"
#include "notification_subscriber_manager.h"

namespace OHOS {
namespace Notification {
const int32_t MAP_SIZE_ONE = 1;
ErrCode AdvancedNotificationService::SetPriorityEnabled(const bool enabled)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    return SetPriorityEnabledInner(enabled);
}

ErrCode AdvancedNotificationService::SetPriorityEnabledInner(const bool enabled)
{
    ErrCode result = ERR_OK;
    int32_t refreshResult = 0;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->SetPriorityEnabled(
            enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
            : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
        sptr<EnabledNotificationCallbackData> bundleData =
            new (std::nothrow) EnabledNotificationCallbackData("", DEFAULT_UID, enabled);
        if (bundleData == nullptr) {
            ANS_LOGE("Failed to create EnabledNotificationCallbackData instance");
            result = ERR_NO_MEMORY;
        } else {
            NotificationSubscriberManager::GetInstance()->NotifyEnabledPriorityChanged(bundleData);
        }
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority enable.");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_25);
    message.Message("en:" + std::to_string(enabled) + ", refreshResult:" + std::to_string(refreshResult));
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityEnabled enabled: %{public}d, result: %{public}d, refreshResult: %{public}d",
        enabled, result, refreshResult);
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_26);
        message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " +
            std::to_string(bundleOption->GetUid()) + ", en:" + std::to_string(enableStatusInt));
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
    if (enableStatusInt < static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::DISABLE) ||
        enableStatusInt > static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE)) {
        ANS_LOGE("EnableStatus out of range %{public}d.", enableStatusInt);
        return ERR_ANS_INVALID_PARAM;
    }
    return SetPriorityEnabledByBundleInner(bundle, enableStatusInt);
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundleInner(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t enableStatusInt)
{
    ErrCode result = ERR_OK;
    int32_t refreshResult = 0;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->SetPriorityEnabledByBundle(bundleOption,
            static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt));
        sptr<EnabledPriorityNotificationByBundleCallbackData> bundleData =
            new (std::nothrow) EnabledPriorityNotificationByBundleCallbackData(bundleOption->GetBundleName(),
            bundleOption->GetUid(), static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt));
        if (bundleData == nullptr) {
            ANS_LOGE("Failed to create EnabledPriorityNotificationByBundleCallbackData instance");
            result = ERR_NO_MEMORY;
        } else {
            NotificationSubscriberManager::GetInstance()->NotifyEnabledPriorityByBundleChanged(bundleData);
        }
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set bundle priority enable.");
    ANS_LOGI("SetPriorityEnabledByBundle %{public}s_%{public}d, "
        "enableStatus: %{public}d, result: %{public}d, refreshResult: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), enableStatusInt, result, refreshResult);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_26);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()) +
        ", en:" + std::to_string(enableStatusInt) + ", refreshResult:" + std::to_string(refreshResult));
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityEnabled(bool &enabled)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    result = NotificationPreferences::GetInstance()->IsPriorityEnabled(enableStatus);
    enabled = (enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ANS_LOGI("IsPriorityEnabled enabled: %{public}d, result: %{public}d", enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityEnabledByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t &enableStatusInt)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    result = NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundle, enableStatus);
    enableStatusInt = static_cast<int32_t>(enableStatus);
    ANS_LOGI("IsPriorityEnabledByBundle %{public}s_%{public}d, enableStatus: %{public}d, result: %{public}d",
        bundle->GetBundleName().c_str(), bundle->GetUid(), enableStatusInt, result);
    return result;
}

ErrCode AdvancedNotificationService::TriggerUpdatePriorityType(const sptr<NotificationRequest> &request)
{
    auto result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        auto record = GetFromNotificationList(request->GetBaseKey(""));
        if (record == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, notification not exist");
            result = ERR_ANS_INVALID_PARAM;
            return;
        }
        auto cacheRequest = record->notification->GetNotificationRequestPoint();
        if (cacheRequest == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, cache request not exist");
            result = ERR_ANS_INVALID_PARAM;
            return;
        }
        cacheRequest->SetInnerPriorityNotificationType(request->GetPriorityNotificationType());
        sptr<Notification> notification = new (std::nothrow) Notification(request);
        if (notification == nullptr) {
            ANS_LOGE("TriggerUpdatePriorityType fail, null notification");
            result = ERR_NO_MEMORY;
            return;
        }
        NotificationSubscriberManager::GetInstance()->NotifySystemUpdate(notification);
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Trigger update priority.");
    ANS_LOGI("TriggerUpdatePriorityType key: %{public}s, result: %{public}d", request->GetKey().c_str(), result);
    return result;
}

ErrCode AdvancedNotificationService::SetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_28);
        message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()));
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" bundle name is empty");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }
    return SetBundlePriorityConfigInner(bundle, value);
}

ErrCode AdvancedNotificationService::SetBundlePriorityConfigInner(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &value)
{
    ErrCode result = ERR_OK;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_28);
    message.Message("bundle: " + bundleOption->GetBundleName() + ", id: " + std::to_string(bundleOption->GetUid()));
    int32_t refreshResult = 0;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        int32_t aiResult = NOTIFICATION_AI_EXTENSION_WRAPPER->SyncBundleKeywords(bundleOption, value);
        ANS_LOGI("SyncBundleKeywords %{public}s_%{public}d result: %{public}d",
            bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), aiResult);
        if (aiResult == NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL) {
            result = ERR_ANS_SERVICE_NOT_READY;
            return;
        }
        result = NotificationPreferences::GetInstance()->SetBundlePriorityConfig(bundleOption, value);
        if (result != ERR_OK) {
            return;
        }
        std::vector<sptr<NotificationRequest>> requests;
        GetRequestsFromNotification(GetNotificationsByBundle(bundleOption), requests);
        std::vector<int32_t> results;
        refreshResult = AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            NotificationAiExtensionWrapper::REFRESH_KEYWORD_PRIORITY_TYPE, requests, results);
#endif
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority config.");
    message.ErrorCode(result).Append(", refreshResult:" + std::to_string(refreshResult));
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetBundlePriorityConfig %{public}s_%{public}d, result: %{public}d, refreshResult: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), result, refreshResult);
    return result;
}

ErrCode AdvancedNotificationService::GetBundlePriorityConfig(
    const sptr<NotificationBundleOption> &bundleOption, std::string &value)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return NotificationPreferences::GetInstance()->GetBundlePriorityConfig(bundle, value);
}

void AdvancedNotificationService::GetRequestsFromNotification(
    const std::vector<sptr<Notification>> &notifications, std::vector<sptr<NotificationRequest>> &requests)
{
    for (const sptr<Notification> &notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            continue;
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        if (AdvancedNotificationPriorityHelper::GetInstance()->IsCollaborationNotification(
            notification->GetNotificationRequestPoint())) {
            continue;
        }
        if (notification->GetNotificationRequestPoint()->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
            continue;
        }
#endif
        MessageParcel parcel;
        if (!parcel.WriteParcelable(notification)) {
            ANS_LOGE("GetRequestsFromNotification writeParcelable failed.");
            continue;
        }
        sptr<Notification> newNotification = parcel.ReadParcelable<Notification>();
        if (newNotification == nullptr) {
            ANS_LOGE("GetRequestsFromNotification null notification");
            continue;
        }
        requests.push_back(newNotification->GetNotificationRequestPoint());
    }
}

template <typename T>
ErrCode AdvancedNotificationService::GetValidMapByBundle(const EventBranchId branchId,
    const std::map<sptr<NotificationBundleOption>, T> &originMap, std::map<sptr<NotificationBundleOption>, T> &validMap)
{
    for (auto &iter : originMap) {
        sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(iter.first);
        if (bundle == nullptr) {
            ANS_LOGW("GetValidMapByBundle invalid bundleOption name: %{public}s, uid: %{public}d.",
                iter.first->GetBundleName().c_str(), iter.first->GetUid());
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, branchId);
            message.Message("bundle:" + iter.first->GetBundleName() + ", id:" + std::to_string(iter.first->GetUid()));
            message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append(" bundle name is empty");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            continue;
        }
        validMap[bundle] = iter.second;
    }
    if (validMap.size() == 0) {
        ANS_LOGE("OriginMap is invalid.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetValidBundles(
    const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
    std::vector<sptr<NotificationBundleOption>> &validBundleOptions)
{
    for (auto &bundleOption : bundleOptions) {
        sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
        if (bundle == nullptr) {
            ANS_LOGW("GetValidBundles invalid bundleOption name: %{public}s, uid: %{public}d.",
                bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
            continue;
        }
        validBundleOptions.emplace_back(bundle);
    }
    if (validBundleOptions.size() == 0) {
        ANS_LOGE("BundleOptions is invalid.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundles(
    const std::map<sptr<NotificationBundleOption>, bool> &priorityEnable)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    std::map<sptr<NotificationBundleOption>, bool> validPriorityEnable;
    result = GetValidMapByBundle(EventBranchId::BRANCH_29, priorityEnable, validPriorityEnable);
    if (result != ERR_OK) {
        return result;
    }
    std::map<sptr<NotificationBundleOption>, NotificationConstant::SWITCH_STATE> innerPriorityEnable;
    for (auto &iter : validPriorityEnable) {
        innerPriorityEnable[iter.first] = iter.second ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    }
    return SetPriorityEnabledByBundlesInner(innerPriorityEnable);
}

ErrCode AdvancedNotificationService::SetPriorityEnabledByBundlesInner(
    const std::map<sptr<NotificationBundleOption>, NotificationConstant::SWITCH_STATE> &priorityEnable)
{
    ErrCode result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        std::vector<sptr<NotificationRequest>> requests;
        std::map<sptr<NotificationBundleOption>, bool> effectPriorityEnable;
        for (auto &iter : priorityEnable) {
            bool enable = (iter.second == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
                iter.second == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
            ErrCode dbResult =
                NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(iter.first, iter.second);
            if (dbResult != ERR_OK) {
                continue;
            }
            result = ERR_OK;
            effectPriorityEnable[iter.first] = enable;
            if (enable) {
                GetRequestsFromNotification(GetNotificationsByBundle(iter.first), requests);
            }
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        std::vector<int32_t> results;
        AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results);
#endif
        SendCommonEvent(NotificationConstant::TYPE_PRIORITY_SWITCH_BY_BUNDLE, effectPriorityEnable, 0);
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority bundles enable.");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_29);
    message.ErrorCode(result);
    if (priorityEnable.size() == MAP_SIZE_ONE) {
        message.Message("bundle:" + priorityEnable.begin()->first->GetBundleName() +
            ", id:" + std::to_string(priorityEnable.begin()->first->GetUid()) +
            ", en:" + std::to_string(static_cast<int32_t>(priorityEnable.begin()->second)));
    }
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityEnabledByBundles result: %{public}d", result);
    return result;
}

ErrCode AdvancedNotificationService::GetPriorityEnabledByBundles(
    const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, bool> &priorityEnable)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    std::vector<sptr<NotificationBundleOption>> validBundleOptions;
    result = GetValidBundles(bundleOptions, validBundleOptions);
    if (result != ERR_OK) {
        return result;
    }
    priorityEnable.clear();
    result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    for (auto &bundleOption : validBundleOptions) {
        NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
        ErrCode dbResult =
            NotificationPreferences::GetInstance()->GetPriorityEnabledByBundleV2(bundleOption, priorityStatus);
        if (dbResult != ERR_OK) {
            continue;
        }
        result = ERR_OK;
        priorityEnable[bundleOption] = (priorityStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
            priorityStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    }
    ANS_LOGI("GetPriorityEnabledByBundles result %{public}d, priorityEnable size: %{public}d.",
        result, static_cast<int32_t>(priorityEnable.size()));
    return result;
}

ErrCode AdvancedNotificationService::IsPriorityIntelligentEnabled(bool &enabled)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    result = NotificationPreferences::GetInstance()->GetPriorityIntelligentEnabled(enableStatus);
    enabled = (enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ANS_LOGI("IsPriorityIntelligentEnabled enabled: %{public}d, result: %{public}d", enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityIntelligentEnabled(const bool enabled)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    return SetPriorityIntelligentEnabledInner(enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
}

ErrCode AdvancedNotificationService::SetPriorityIntelligentEnabledInner(
    const NotificationConstant::SWITCH_STATE enableStatus)
{
    ErrCode result = ERR_OK;
    bool enabled = (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        result = NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(enableStatus);
        if (result != ERR_OK) {
            return;
        }
        std::map<sptr<NotificationBundleOption>, bool> params;
        SendCommonEvent(NotificationConstant::TYPE_PRIORITY_INTELLIGENT_SWITCH, params, enabled);
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        std::vector<sptr<NotificationRequest>> requests;
        GetRequestsFromNotification(GetAllNotification(), requests);
        std::vector<int32_t> results;
        AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results);
#endif
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority intelligent enable.");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_30);
    message.Message("en:" + std::to_string(static_cast<int32_t>(enableStatus))).ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityIntelligentEnabled enabled: %{public}d, result: %{public}d, ", enableStatus, result);
    return result;
}

ErrCode AdvancedNotificationService::GetPriorityStrategyByBundles(
    const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    std::vector<sptr<NotificationBundleOption>> validBundleOptions;
    result = GetValidBundles(bundleOptions, validBundleOptions);
    if (result != ERR_OK) {
        return result;
    }
    strategies.clear();
    result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    for (auto &bundleOption : validBundleOptions) {
        int64_t strategy = PRIORITY_STRATEGY_DEFAULT;
        ErrCode dbResult = NotificationPreferences::GetInstance()->GetPriorityStrategyByBundle(bundleOption, strategy);
        if (dbResult != ERR_OK) {
            continue;
        }
        result = ERR_OK;
        strategies[bundleOption] = strategy;
    }
    ANS_LOGI("GetPriorityStrategyByBundles result %{public}d, strategies size: %{public}d.",
        result, static_cast<int32_t>(strategies.size()));
    return result;
}

ErrCode AdvancedNotificationService::SetPriorityStrategyByBundles(
    const std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    ErrCode result = SystemPermissionCheck();
    if (result != ERR_OK) {
        return result;
    }
    std::map<sptr<NotificationBundleOption>, int64_t> validStrategies;
    result = GetValidMapByBundle(EventBranchId::BRANCH_31, strategies, validStrategies);
    if (result != ERR_OK) {
        return result;
    }
    return SetPriorityStrategyByBundlesInner(validStrategies);
}

ErrCode AdvancedNotificationService::SetPriorityStrategyByBundlesInner(
    const std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    ErrCode result = ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED;
    auto submitResult = notificationSvrQueue_.SyncSubmit(std::bind([&]() {
        std::vector<sptr<NotificationRequest>> requests;
        std::map<sptr<NotificationBundleOption>, int64_t> effectStrategies;
        for (auto &iter : strategies) {
            if (iter.second < 0 || iter.second > PRIORITY_STRATEGY_MAX) {
                ANS_LOGW("Invalid strategy %{public}d, %{public}s_%{public}d",
                    static_cast<int32_t>(iter.second), iter.first->GetBundleName().c_str(), iter.first->GetUid());
                result = ERR_ANS_INVALID_PARAM;
                continue;
            }
            ErrCode dbResult =
                NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(iter.first, iter.second);
            if (dbResult != ERR_OK) {
                continue;
            }
            result = ERR_OK;
            effectStrategies[iter.first] = iter.second;
            GetRequestsFromNotification(GetNotificationsByBundle(iter.first), requests);
        }
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        std::vector<int32_t> results;
        AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
            NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results);
#endif
        SendCommonEvent(NotificationConstant::TYPE_PRIORITY_STRATEGY_BY_BUNDLE, effectStrategies, 0);
    }));
    ANS_COND_DO_ERR(submitResult != ERR_OK, return submitResult, "Set priority bundles enable.");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_30, EventBranchId::BRANCH_31);
    message.ErrorCode(result);
    if (strategies.size() == MAP_SIZE_ONE) {
        message.Message("bundle:" + strategies.begin()->first->GetBundleName() +
            ", id:" + std::to_string(strategies.begin()->first->GetUid()) +
            ", value:" + std::to_string(strategies.begin()->second));
    }
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("SetPriorityStrategyByBundles result: %{public}d", result);
    return result;
}

template <typename T>
void AdvancedNotificationService::SendCommonEvent(
    const uint32_t eventType, const std::map<sptr<NotificationBundleOption>, T> &params, int32_t code)
{
    EventFwk::Want want;
    EventFwk::CommonEventData commonData;
    if (eventType != NotificationConstant::TYPE_PRIORITY_INTELLIGENT_SWITCH && params.size() <= 0) {
        return;
    }
    switch (eventType) {
        case NotificationConstant::TYPE_PRIORITY_INTELLIGENT_SWITCH:
            want.SetAction(NotificationConstant::EVENT_PRIORITY_INTELLIGENT_SWITCH);
            commonData.SetCode(code);
            break;
        case NotificationConstant::TYPE_PRIORITY_SWITCH_BY_BUNDLE: {
                nlohmann::json jsonObject = nlohmann::json::array();
                for (auto &param : params) {
                    bool enabled = param.second;
                    nlohmann::json jsonNode = {{"bundle", param.first->GetBundleName()},
                        {"uid", param.first->GetUid()}, {"enable", enabled}};
                    jsonObject.emplace_back(jsonNode);
                }
                want.SetParam("switches", jsonObject.dump());
                want.SetAction(NotificationConstant::EVENT_PRIORITY_SWITCH_BY_BUNDLE);
            }
            break;
        case NotificationConstant::TYPE_PRIORITY_STRATEGY_BY_BUNDLE: {
                nlohmann::json jsonObject = nlohmann::json::array();
                for (auto &param : params) {
                    nlohmann::json jsonNode = {{"bundle", param.first->GetBundleName()},
                        {"uid", param.first->GetUid()}, {"strategy", param.second}};
                    jsonObject.emplace_back(jsonNode);
                }
                want.SetParam("strategies", jsonObject.dump());
                want.SetAction(NotificationConstant::EVENT_PRIORITY_STRATEGY_BY_BUNDLE);
            }
            break;
        default:
            break;
    }
    commonData.SetWant(want);
    std::vector<std::string> permission { OHOS_PERMISSION_NOTIFICATION_CONTROLLER };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions(permission);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo);
}
}  // namespace Notification
}  // namespa OHOS