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

#include <functional>
#include <iomanip>
#include <sstream>

#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"
#include "errors.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "os_account_manager_helper.h"
#include "ipc_skeleton.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "smart_reminder_center.h"
#endif

#include "notification_liveview_utils.h"
#include "os_account_manager_helper.h"
#include "advanced_notification_inline.h"
#include "notification_config_parse.h"
#include "notification_extension_wrapper.h"
#include "notification_analytics_util.h"
#include "liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
    constexpr char KEY_NAME[] = "AGGREGATE_CONFIG";
    constexpr char CTRL_LIST_KEY_NAME[] = "NOTIFICATION_CTL_LIST_PKG";
    constexpr char CALL_UI_BUNDLE[] = "com.ohos.callui";
    constexpr char LIVEVIEW_CONFIG_KEY[] = "APP_LIVEVIEW_CONFIG";
    constexpr uint32_t NOTIFICATION_SETTING_FLAG_BASE = 0x11;
    constexpr int32_t MAX_LIVEVIEW_CONFIG_SIZE = 60;
    constexpr int32_t MAX_CHECK_RETRY_TIME = 3;
    constexpr int32_t PUSH_CHECK_ERR_DEVICE = 6;
    constexpr int32_t PUSH_CHECK_ERR_EXPIRED = 10;
    constexpr int32_t PUSH_CHECK_ERR_AUTH = 11;
    constexpr int32_t MAX_CHECK_NUM = 20;
    constexpr uint64_t DELAY_TIME_CHECK_LIVEVIEW = 10 * 1000 * 1000;
    constexpr uint64_t DELAY_TIME_TRIGGER_LIVEVIEW = 10 * 60 * 1000 * 1000;
    constexpr uint64_t INTERVAL_CHECK_LIVEVIEW = 1000 * 1000;
    const std::set<std::string> unAffectDevices = {
        NotificationConstant::LITEWEARABLE_DEVICE_TYPE,
        NotificationConstant::WEARABLE_DEVICE_TYPE
    };
}

ErrCode AdvancedNotificationService::AddSlots(const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("called");

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (slots.size() == 0) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        std::vector<sptr<NotificationSlot>> addSlots;
        for (auto slot : slots) {
            sptr<NotificationSlot> originalSlot;
            result =NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption,
                slot->GetType(), originalSlot);
            if ((result == ERR_OK) && (originalSlot != nullptr)) {
                continue;
            }

            GenerateSlotReminderMode(slot, bundleOption, true);
            addSlots.push_back(slot);
        }

        if (addSlots.size() == 0) {
            result = ERR_OK;
        } else {
            result = NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption, addSlots);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("called");

    std::vector<sptr<NotificationSlot>> slots_temp;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationAllSlots(bundleOption, slots);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            slots.clear();
        }
        NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        result = NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundleOption, enableStatus);
        if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
            for (auto slot : slots) {
                sptr<NotificationSlot> value(new NotificationSlot(*slot));
                value->SetReminderMode(value->GetSilentReminderMode());
                slots_temp.emplace_back(value);
                ANS_LOGD("GetSlotsByBundle ReminderMode:%{public}d", value->GetReminderMode());
            }
            slots =  slots_temp;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetSlotsByBundle(
    const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("called");

    std::vector<sptr<NotificationSlot>> slots_temp;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("GenerateValidBundleOption failed.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationAllSlots(bundle, slots);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            slots.clear();
        }
        NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        result = NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundle, enableStatus);
        if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
            for (auto slot : slots) {
                sptr<NotificationSlot> value(new NotificationSlot(*slot));
                value->SetReminderMode(value->GetSilentReminderMode());
                slots_temp.emplace_back(value);
                ANS_LOGD("GetSlotsByBundle ReminderMode:%{public}d", slot->GetReminderMode());
            }
            slots =  slots_temp;
        }
    }));

    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetSlotByBundle(
    const sptr<NotificationBundleOption> &bundleOption, int32_t slotTypeInt,
    sptr<NotificationSlot> &slot)
{
    ANS_LOGD("called");
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundleOption == nullptr) {
        ANS_LOGD("Failed to generateBundleOption.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    sptr<NotificationSlot> slotFromDb = nullptr;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundle, slotType, slotFromDb);
        if (slotFromDb != nullptr) {
            slot = new (std::nothrow) NotificationSlot(*slotFromDb);
        }
        NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundle, enableStatus);
        if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON && slot != nullptr) {
            slot->SetReminderMode(slot->GetSilentReminderMode());
        }
    }));
    notificationSvrQueue_->wait(handler);
    if (slot != nullptr) {
        ANS_LOGD("GetSlotByBundle, authStatus: %{public}d), authHintCnt: %{public}d",
            slot->GetAuthorizedStatus(), slot->GetAuthHintCnt());
    }
    return result;
}

ErrCode AdvancedNotificationService::UpdateSlots(
    const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("called");

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_6, EventBranchId::BRANCH_6);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Message("Not system app.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Message("CheckPermission is false.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->UpdateNotificationSlots(bundle, slots);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
            message.ErrorCode(result).Message("Slot type not exist.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            ANS_LOGE("Slot type not exist.");
        }
    }));
    notificationSvrQueue_->wait(handler);

    if (result == ERR_OK) {
        PublishSlotChangeCommonEvent(bundle);
    }

    return result;
}

ErrCode AdvancedNotificationService::RemoveAllSlots()
{
    ANS_LOGD("called");

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("GenerateBundleOption defeat.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationSlot> liveViewSlot;

        bool isLiveViewSlotExist = true;
        // retain liveview slot before removeNotificationAllSlots
        if (NotificationPreferences::GetInstance()->GetNotificationSlot(
            bundleOption, NotificationConstant::SlotType::LIVE_VIEW, liveViewSlot) != ERR_OK) {
            isLiveViewSlotExist = false;
        }

        result = NotificationPreferences::GetInstance()->RemoveNotificationAllSlots(bundleOption);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
        }

        if (!isLiveViewSlotExist) {
            return;
        }
        // retain liveview slot when caller is not sa or systemapp
        if ((result == ERR_OK) &&
            (IsAllowedRemoveSlot(bundleOption, NotificationConstant::SlotType::LIVE_VIEW) != ERR_OK)) {
            std::vector<sptr<NotificationSlot>> slots;

            slots.push_back(liveViewSlot);
            (void)NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption, slots);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::AddSlotByType(int32_t slotTypeInt)
{
    ANS_LOGD("called");
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);

    if (!AccessTokenHelper::IsSystemApp() && slotType == NotificationConstant::SlotType::EMERGENCY_INFORMATION) {
        ANS_LOGE("Non system app used illegal slot type.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot);
        if ((result == ERR_OK) && (slot != nullptr)) {
            return;
        }

        slot = new (std::nothrow) NotificationSlot(slotType);
        if (slot == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot instance");
            return;
        }

        GenerateSlotReminderMode(slot, bundleOption);
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption, slots);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetEnabledForBundleSlotSelf(int32_t slotTypeInt, bool &enabled)
{
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    ANS_LOGD("slotType: %{public}d", slotType);

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_15, EventBranchId::BRANCH_0);
    message.Message("st:" + std::to_string(slotType) + "en:" + std::to_string(enabled));
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot);
        if (result != ERR_OK) {
            ANS_LOGE("Get enable slot self: GetNotificationSlot failed");
            return;
        }
        if (slot == nullptr) {
            ANS_LOGW("Get enable slot: object is null, enabled default true");
            enabled = true;
            result = ERR_OK;
            return;
        }
        enabled = slot->GetEnable();
    }));
    notificationSvrQueue_->wait(handler);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::GetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,
    uint32_t &slotFlags)
{
    ANS_LOGD("called");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationSlotFlagsForBundle(bundle, slotFlags);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            slotFlags = DEFAULT_SLOT_FLAGS;
        }
        NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundle, enableStatus);
        if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
            slotFlags = SILENT_REMINDER__SLOT_FLAGS;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetNotificationSettings(uint32_t &slotFlags)
{
    ANS_LOGD("called");
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("Failed to generateBundleOption.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationSlotFlagsForBundle(bundleOption, slotFlags);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            slotFlags = DEFAULT_SLOT_FLAGS;
        }
        slotFlags = slotFlags & NOTIFICATION_SETTING_FLAG_BASE;
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,
    uint32_t slotFlags)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_2);
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
            " slotFlags:" + std::to_string(slotFlags));
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append(" Permission denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            result = NotificationPreferences::GetInstance()->SetNotificationSlotFlagsForBundle(bundle, slotFlags);
            if (result != ERR_OK) {
                return;
            }
            ANS_LOGI("Set slotflags %{public}d to %{public}s.", slotFlags, bundle->GetBundleName().c_str());
            result = UpdateSlotReminderModeBySlotFlags(bundle, slotFlags);
        }));
    notificationSvrQueue_->wait(handler);
    ANS_LOGI("%{public}s_%{public}d, slotFlags: %{public}d, SetSlotFlagsAsBundle result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), slotFlags, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::AssignValidNotificationSlot(const std::shared_ptr<NotificationRecord> &record,
    const sptr<NotificationBundleOption> &bundleOption)
{
    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = record->request->GetSlotType();
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_3).SlotType(slotType);
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot);
    if ((result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) ||
        (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST)) {
        slot = new (std::nothrow) NotificationSlot(slotType);
        if (slot == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot instance");
            return ERR_NO_MEMORY;
        }

        GenerateSlotReminderMode(slot, bundleOption);
        if (record->request->IsSystemLiveView() || record->isAtomicService) {
            ANS_LOGI("System live view or atomicService no need add sloty.");
            result = ERR_OK;
        } else {
            std::vector<sptr<NotificationSlot>> slots;
            slots.push_back(slot);
            result = NotificationPreferences::GetInstance()->AddNotificationSlots(bundleOption, slots);
        }
    }
    if (result == ERR_OK) {
        std::string bundleName = bundleOption->GetBundleName();
        if (slot != nullptr &&
            (bundleName == CALL_UI_BUNDLE || slot->GetEnable() || record->request->IsSystemLiveView() ||
            (slot->GetType() == NotificationConstant::SlotType::LIVE_VIEW &&
            DelayedSingleton<NotificationConfigParse>::GetInstance()->IsLiveViewEnabled(bundleName)))) {
            record->slot = slot;
        } else {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED;
            ANS_LOGE("Type[%{public}d] slot enable closed", slotType);
        }
    }
    if (result != ERR_OK) {
        message.ErrorCode(result).Message("assign slot failed");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(record->request, message);
    }
    return result;
}

ErrCode AdvancedNotificationService::UpdateSlotReminderModeBySlotFlags(
    const sptr<NotificationBundleOption> &bundle, uint32_t slotFlags)
{
    std::vector<sptr<NotificationSlot>> slots;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_3, EventBranchId::BRANCH_1);
    ErrCode ret = NotificationPreferences::GetInstance()->GetNotificationAllSlots(bundle, slots);
    if (ret != ERR_OK) {
        message.Message("Failed to get slots by bundle, ret:" + std::to_string(ret), true);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ret;
    }

    message.BundleName((bundle == nullptr) ? "" : bundle->GetBundleName());
    if (slots.empty()) {
        message.Message("The bundle has no slots.", true);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_OK;
    }

    for (auto slot : slots) {
        auto configSlotReminderMode =
            DelayedSingleton<NotificationConfigParse>::GetInstance()->GetConfigSlotReminderModeByType(slot->GetType());
        slot->SetReminderMode(slotFlags & configSlotReminderMode);
        std::string bundleName = (bundle == nullptr) ? "" : bundle->GetBundleName();
        ANS_LOGD("Update reminderMode of %{public}d in %{public}s, value is %{public}d.",
            slot->GetType(), bundleName.c_str(), slot->GetReminderMode());
    }

    ret = NotificationPreferences::GetInstance()->UpdateNotificationSlots(bundle, slots);
    if (ret == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        ret = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
        message.ErrorCode(ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST).Message("Slot type not exist.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
    return ret;
}

void AdvancedNotificationService::GenerateSlotReminderMode(const sptr<NotificationSlot> &slot,
    const sptr<NotificationBundleOption> &bundle, bool isSpecifiedSlot, uint32_t defaultSlotFlags)
{
    uint32_t slotFlags = defaultSlotFlags;
    auto ret = NotificationPreferences::GetInstance()->GetNotificationSlotFlagsForBundle(bundle, slotFlags);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to get slotflags for bundle, use default slotflags");
    }

    auto configSlotReminderMode =
        DelayedSingleton<NotificationConfigParse>::GetInstance()->GetConfigSlotReminderModeByType(slot->GetType());
    if (isSpecifiedSlot) {
        slot->SetReminderMode(configSlotReminderMode & slotFlags & slot->GetReminderMode());
    } else {
        slot->SetReminderMode(configSlotReminderMode & slotFlags);
    }

    std::string bundleName = (bundle == nullptr) ? "" : bundle->GetBundleName();
    ANS_LOGI("The reminder mode of %{public}d is %{public}d in %{public}s,specifiedSlot:%{public}d default:%{public}u",
        slot->GetType(), slot->GetReminderMode(), bundleName.c_str(), isSpecifiedSlot, defaultSlotFlags);
}

uint32_t AdvancedNotificationService::GetDefaultSlotFlags(const sptr<NotificationRequest> &request)
{
    auto flags = DEFAULT_SLOT_FLAGS;
    uint32_t notificationControlFlags = request->GetNotificationControlFlags();
    // SA publish own's notification with banner
    if ((notificationControlFlags & NotificationConstant::ReminderFlag::SA_SELF_BANNER_FLAG) != 0) {
        ANS_LOGI("Creator:%{public}s %{public}d,Owner: %{public}s %{public}d, controlFlags:%{public}d",
            request->GetCreatorBundleName().c_str(), request->GetCreatorUid(), request->GetOwnerBundleName().c_str(),
            request->GetOwnerUid(), request->GetNotificationControlFlags());
    }
    if (((notificationControlFlags & NotificationConstant::ReminderFlag::SA_SELF_BANNER_FLAG) != 0) &&
        (request->GetCreatorUid() == IPCSkeleton::GetCallingUid() && request->GetCreatorBundleName().empty() &&
        request->GetOwnerBundleName().empty())) {
        return (flags |= NotificationConstant::ReminderFlag::BANNER_FLAG);
    }

    return flags;
}

void AdvancedNotificationService::SetRequestBySlotType(const sptr<NotificationRequest> &request,
    const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    auto flags = std::make_shared<NotificationFlags>();
    request->SetFlags(flags);
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    bool systemVoip = (request->GetClassification() == NotificationConstant::ANS_VOIP &&
        request->GetSlotType() == NotificationConstant::LIVE_VIEW);
    if (!systemVoip) {
        DelayedSingleton<SmartReminderCenter>::GetInstance()->ReminderDecisionProcess(request);
    } else {
        ANS_LOGI("systemVoip");
    }
#endif
    NotificationConstant::SlotType type = request->GetSlotType();

    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = request->GetSlotType();
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot);
    if (slot == nullptr) {
        slot = new (std::nothrow) NotificationSlot(slotType);
        if (slot == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot instance");
            return;
        }
        uint32_t slotFlags = GetDefaultSlotFlags(request);
        GenerateSlotReminderMode(slot, bundleOption, false, slotFlags);
    }

    auto slotReminderMode = slot->GetReminderMode();
    if ((slotReminderMode & NotificationConstant::ReminderFlag::SOUND_FLAG) != 0) {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::SOUND_FLAG, true);
    } else {
        request->SetDistributedFlagBit(
            NotificationConstant::ReminderFlag::SOUND_FLAG, false, unAffectDevices);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG) != 0) {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG, true);
    } else {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG, false);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::BANNER_FLAG) != 0) {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::BANNER_FLAG, true);
    } else {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::BANNER_FLAG, false);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG) != 0) {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG, true);
    } else {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG, false);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::VIBRATION_FLAG) != 0) {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::VIBRATION_FLAG, true);
    } else {
        request->SetDistributedFlagBit(
            NotificationConstant::ReminderFlag::VIBRATION_FLAG, false, unAffectDevices);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG) != 0) {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG, true);
    } else {
        request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG, false);
    }
    ANS_LOGI("SetFlags-init,Key = %{public}s flags = %{public}d",
        request->GetKey().c_str(), request->GetFlags()->GetReminderFlags());
    HandleFlagsWithRequest(request, bundleOption);
}

void AdvancedNotificationService::HandleFlagsWithRequest(const sptr<NotificationRequest> &request,
    const sptr<NotificationBundleOption> &bundleOption)
{
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    if (request->IsCommonLiveView()) {
        LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewReminderFlags(request);
        LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewVoiceContent(request);
    } else if (!request->IsSystemLiveView()) {
        NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundleOption, enableStatus);
        if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
            request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::SOUND_FLAG, false, unAffectDevices);
            request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG, false);
            request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::BANNER_FLAG, false);
            request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG, false);
            request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::VIBRATION_FLAG, false, unAffectDevices);
        }
    }
    ANS_LOGI("SetFlags- HandleFlag Key = %{public}s flags = %{public}d class = %{public}s silent = %{public}d",
        request->GetKey().c_str(), request->GetFlags()->GetReminderFlags(),
        request->GetClassification().c_str(), enableStatus);
    if (request->GetClassification() == NotificationConstant::ANS_VOIP &&
        request->GetSlotType() == NotificationConstant::LIVE_VIEW) {
        return;
    }
}

ErrCode AdvancedNotificationService::GetSlotByType(int32_t slotTypeInt, sptr<NotificationSlot> &slot)
{
    ANS_LOGD("called");
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("Failed to generateBundleOption.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<NotificationSlot> slotFromDb = nullptr;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGI("ffrt enter!");
        NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slotFromDb);
        if (slotFromDb != nullptr) {
            ANS_LOGI("slotFromDb != nullptr");
            slot = new (std::nothrow) NotificationSlot(*slotFromDb);
        }
        NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        NotificationPreferences::GetInstance()->IsSilentReminderEnabled(bundleOption, enableStatus);
        if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON && slot != nullptr) {
            slot->SetReminderMode(slot->GetSilentReminderMode());
        }
    }));
    notificationSvrQueue_->wait(handler);
    // if get slot failed, it still return ok.
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveSlotByType(int32_t slotTypeInt)
{
    ANS_LOGD("called");

    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = IsAllowedRemoveSlot(bundleOption, slotType);
        if (result != ERR_OK) {
            ANS_LOGE("Liveview slot cann't remove.");
            return;
        }

        NotificationPreferences::GetInstance()->RemoveNotificationSlot(bundleOption, slotType);
    }));
    notificationSvrQueue_->wait(handler);
    // if remove slot failed, it still return ok.
    return result;
}

ErrCode AdvancedNotificationService::GetSlotNumAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, uint64_t &num)
{
    ANS_LOGD("called");

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationSlotsNumForBundle(bundle, num);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            num = 0;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::AddSlotThenPublishEvent(
    const sptr<NotificationSlot> &slot,
    const sptr<NotificationBundleOption> &bundle,
    bool enabled, bool isForceControl, int32_t authStatus)
{
    bool allowed = false;
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, state);
    if (result == ERR_OK) {
        allowed = (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
            state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    }
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        result = ERR_OK;
        allowed = CheckApiCompatibility(bundle);
        SetDefaultNotificationEnabled(bundle, allowed);
    }

    slot->SetEnable(enabled);
    slot->SetForceControl(isForceControl);
    slot->SetAuthorizedStatus(authStatus);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    result = NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);
    if (result != ERR_OK) {
        ANS_LOGE("Set enable slot: AddNotificationSlot failed");
        return result;
    }

    if (!slot->GetEnable()) {
        RemoveNotificationBySlot(bundle, slot, NotificationConstant::DISABLE_SLOT_REASON_DELETE);
    } else {
        if (!slot->GetForceControl() && !allowed) {
            RemoveNotificationBySlot(bundle, slot, NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE);
        }
    }

    PublishSlotChangeCommonEvent(bundle);
    return result;
}

ErrCode AdvancedNotificationService::SetEnabledForBundleSlotInner(
    const sptr<NotificationBundleOption> &bundleOption,
    const sptr<NotificationBundleOption> &bundle,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    sptr<NotificationSlot> slot;
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundle, slotType, slot);
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST ||
        result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        slot = new (std::nothrow) NotificationSlot(slotType);
        if (slot == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot ptr.");
            return ERR_ANS_NO_MEMORY;
        }
        GenerateSlotReminderMode(slot, bundleOption);
        return AddSlotThenPublishEvent(slot, bundle, enabled, isForceControl);
    } else if ((result == ERR_OK) && (slot != nullptr)) {
        if (slot->GetEnable() == enabled && slot->GetForceControl() == isForceControl) {
            slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
            std::vector<sptr<NotificationSlot>> slots;
            slots.push_back(slot);
            return NotificationPreferences::GetInstance()->AddNotificationSlots(bundle, slots);
        }
        NotificationPreferences::GetInstance()->RemoveNotificationSlot(bundle, slotType);
        return AddSlotThenPublishEvent(slot, bundle, enabled, isForceControl);
    }
    ANS_LOGE("Set enable slot: GetNotificationSlot failed");
    return result;
}

ErrCode AdvancedNotificationService::SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
    int32_t slotTypeInt, bool enabled, bool isForceControl)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    ANS_LOGD("slotType: %{public}d, enabled: %{public}d, isForceControl: %{public}d",
        slotType, enabled, isForceControl);
    ErrCode result = CheckCommonParams();
    if (result != ERR_OK) {
        return result;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_4);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " slotType: " + std::to_string(static_cast<uint32_t>(slotType)) +
        " enabled: " +std::to_string(enabled) + "isForceControl" + std::to_string(isForceControl));
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        result = SetEnabledForBundleSlotInner(bundleOption, bundle, slotType, enabled, isForceControl);
    }));
    notificationSvrQueue_->wait(handler);

    SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("%{public}s_%{public}d, SetEnabledForBundleSlot successful.",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    return result;
}

ErrCode AdvancedNotificationService::GetEnabledForBundleSlot(
    const sptr<NotificationBundleOption> &bundleOption, int32_t slotTypeInt, bool &enabled)
{
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    ANS_LOGD("slotType: %{public}d", slotType);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and isSystemApp failed.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundle, slotType, slot);
        if (result != ERR_OK) {
            ANS_LOGE("Get slot failed %{public}d", result);
            return;
        }
        if (slot == nullptr) {
            ANS_LOGW("null slot, default true");
            enabled = true;
            result = ERR_OK;
            return;
        }
        enabled = slot->GetEnable();
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetDefaultSlotForBundle(const sptr<NotificationBundleOption> &bundleOption,
    int32_t slotTypeInt, bool enabled, bool isForceControl)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    ANS_LOGD("slotType: %{public}d, enabled: %{public}d, isForceControl: %{public}d",
        slotType, enabled, isForceControl);
    ErrCode result = CheckCommonParams();
    if (result != ERR_OK) {
        return result;
    }

    if (bundleOption == nullptr || bundleOption->GetBundleName().empty() || bundleOption->GetUid() <= 0) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_5);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " slotType: " + std::to_string(static_cast<uint32_t>(slotType)) +
        " enabled: " +std::to_string(enabled) + "isForceControl" + std::to_string(isForceControl));
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST ||
            result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            slot = new (std::nothrow) NotificationSlot(slotType);
            if (slot == nullptr) {
                ANS_LOGE("Failed to create NotificationSlot ptr.");
                result = ERR_ANS_NO_MEMORY;
                return;
            }
            GenerateSlotReminderMode(slot, bundleOption);
            result = AddSlotThenPublishEvent(slot, bundleOption, enabled, isForceControl,
                NotificationSlot::AuthorizedStatus::NOT_AUTHORIZED);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("%{public}s_%{public}d, SetDefaultSlotForBundle successful.",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    return result;
}


void AdvancedNotificationService::InvokeCheckConfig(const std::string& requestId)
{
    std::shared_ptr<LiveViewCheckParam> checkParam = nullptr;
    if (!NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(requestId, checkParam)) {
        ANS_LOGW("Unknow request %{public}s.", requestId.c_str());
        return;
    }
    if (checkParam == nullptr) {
        ANS_LOGW("Invalid data request %{public}s.", requestId.c_str());
        return;
    }

    sptr<IPushCallBack> pushCallBack = nullptr;
    {
        std::lock_guard<ffrt::mutex> lock(pushMutex_);
        if (pushCallBacks_.find(NotificationConstant::SlotType::LIVE_VIEW) == pushCallBacks_.end()) {
            ANS_LOGW("No push check function.");
            NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
            return;
        }
        pushCallBack = pushCallBacks_[NotificationConstant::SlotType::LIVE_VIEW];
    }
    if (pushCallBack == nullptr) {
        ANS_LOGW("Invalid push check function.");
        NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
        return;
    }

    int32_t res = pushCallBack->OnCheckLiveView(requestId, checkParam->bundlesName);
    if (res != ERR_OK) {
        ANS_LOGW("Push check failed %{public}d %{public}zu.", res, checkParam->bundlesName.size());
        NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
    }
}

void AdvancedNotificationService::InvockLiveViewSwitchCheck(
    const std::vector<sptr<NotificationBundleOption>>& bundles, int32_t userId, uint32_t index)
{
    ANS_LOGI("Invock switch start %{public}zu %{public}u %{public}d.", bundles.size(), index, userId);
    int count = 0;
    std::vector<std::string> handleBundles;
    for (; index < bundles.size() && count < MAX_CHECK_NUM; index++) {
        count++;
        if (DelayedSingleton<NotificationConfigParse>::GetInstance()->IsLiveViewEnabled(
            bundles[index]->GetBundleName())) {
            continue;
        }

        if (NotificationLiveViewUtils::GetInstance().CheckLiveViewConfigByBundle(
            bundles[index]->GetBundleName(), NotificationLiveViewUtils::ALL_EVENT)) {
            continue;
        }

        sptr<NotificationSlot> slot;
        if (NotificationPreferences::GetInstance()->GetNotificationSlot(bundles[index],
            NotificationConstant::SlotType::LIVE_VIEW, slot) != ERR_OK) {
            continue;
        }

        NotificationPreferences::GetInstance()->RemoveNotificationSlot(bundles[index],
            NotificationConstant::SlotType::LIVE_VIEW);
        handleBundles.push_back(bundles[index]->GetBundleName());
    }

    ANS_LOGI("Invock switch %{public}zu %{public}u %{public}zu.", bundles.size(), index, handleBundles.size());
    if (!handleBundles.empty()) {
        NotificationAnalyticsUtil::ReportTriggerLiveView(handleBundles);
    }

    if (index >= bundles.size()) {
        NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(userId,
            NotificationLiveViewUtils::ERASE_FLAG_FINISHED);
        return;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(userId,
            NotificationLiveViewUtils::ERASE_FLAG_INIT);
        return;
    }

    notificationSvrQueue_->submit_h(std::bind([&, bundles, userId, index]() {
        InvockLiveViewSwitchCheck(bundles, userId, index);
    }),
        ffrt::task_attr().delay(INTERVAL_CHECK_LIVEVIEW).name("doTriggerLiveView"));
}

void AdvancedNotificationService::TriggerLiveViewSwitchCheck(int32_t userId)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }

    if (!NotificationLiveViewUtils::GetInstance().CheckLiveViewRebuild(userId)) {
        return;
    }

    ANS_LOGE("Trigger live view start.");
    notificationSvrQueue_->submit_h(std::bind([&, userId]() {
        std::map<std::string, sptr<NotificationBundleOption>> bundleOptions;
        if (BundleManagerHelper::GetInstance()->GetAllBundleInfo(bundleOptions, userId) != ERR_OK) {
            NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(userId,
                NotificationLiveViewUtils::ERASE_FLAG_INIT);
            NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(userId,
                NotificationLiveViewUtils::ERASE_FLAG_INIT);
            return;
        }
        std::vector<sptr<NotificationBundleOption>> checkBundles;
        std::unordered_map<std::string, std::string> bundlesMap;
        if (NotificationPreferences::GetInstance()->InitBundlesInfo(userId, bundlesMap) != ERR_OK) {
            NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(userId,
                NotificationLiveViewUtils::ERASE_FLAG_INIT);
            return;
        }

        for (auto item : bundlesMap) {
            if (bundleOptions.count(item.second)) {
                checkBundles.push_back(bundleOptions[item.second]);
            }
        }
        ANS_LOGI("Get data %{public}zu %{public}zu %{public}zu.", bundleOptions.size(), checkBundles.size(),
            bundlesMap.size());
        InvockLiveViewSwitchCheck(checkBundles, userId, 0);
    }),
        ffrt::task_attr().name("triggerLiveView").delay(DELAY_TIME_TRIGGER_LIVEVIEW));
}

ErrCode AdvancedNotificationService::SetCheckConfig(int32_t response, const std::string& requestId,
    const std::string& key, const std::string& value)
{
    if (key != LIVEVIEW_CONFIG_KEY) {
        ANS_LOGE("Invalid key %{public}s.", key.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    notificationSvrQueue_->submit_h(std::bind([&, response, requestId, value]() {
        if (response == ERR_OK) {
            LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveViewConfig(value);
            return;
        }

        ANS_LOGW("Push request failed %{public}s %{public}d.", requestId.c_str(), response);
        if (response == PUSH_CHECK_ERR_DEVICE || response == PUSH_CHECK_ERR_EXPIRED ||
            response == PUSH_CHECK_ERR_AUTH) {
            NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
            return;
        }

        std::shared_ptr<LiveViewCheckParam> checkParam = nullptr;
        if (!NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(requestId, checkParam)) {
            ANS_LOGE("Unknow request %{public}s.", requestId.c_str());
            return;
        }
        if (checkParam == nullptr) {
            ANS_LOGE("Invalid data request %{public}s.", requestId.c_str());
            return;
        }

        checkParam->retryTime++;
        if (checkParam->retryTime >= MAX_CHECK_RETRY_TIME) {
            NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
            ANS_LOGE("Check failed request %{public}s.", requestId.c_str());
            return;
        }

        if (notificationSvrQueue_ == nullptr) {
            ANS_LOGE("Check handler is null.");
            return;
        }
        notificationSvrQueue_->submit_h([&, requestId]() { InvokeCheckConfig(requestId); },
            ffrt::task_attr().name("checkLiveView").delay(DELAY_TIME_CHECK_LIVEVIEW));
    }));

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetLiveViewConfig(const std::vector<std::string>& bundleList)
{
    if (bundleList.empty() || bundleList.size() > MAX_LIVEVIEW_CONFIG_SIZE) {
        ANS_LOGE("Invalid param %{public}zu.", bundleList.size());
        return ERR_ANS_INVALID_PARAM;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    int32_t result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        sptr<IPushCallBack> pushCallBack = nullptr;
        {
            std::lock_guard<ffrt::mutex> lock(pushMutex_);
            if (pushCallBacks_.find(NotificationConstant::SlotType::LIVE_VIEW) == pushCallBacks_.end()) {
                ANS_LOGE("No push check.");
                result = ERR_ANS_PUSH_CHECK_UNREGISTERED;
                return;
            }
            pushCallBack = pushCallBacks_[NotificationConstant::SlotType::LIVE_VIEW];
        }
        if (pushCallBack == nullptr) {
            ANS_LOGE("Invalid push check function.");
            result = ERR_ANS_PUSH_CHECK_UNREGISTERED;
            return;
        }
        auto param = std::make_shared<LiveViewCheckParam>(bundleList);
        auto requestId = NotificationLiveViewUtils::GetInstance().AddLiveViewCheckData(param);
        int32_t res = pushCallBack->OnCheckLiveView(requestId, bundleList);
        if (res != ERR_OK) {
            result = ERR_ANS_PUSH_CHECK_FAILED;
            ANS_LOGE("Push check failed %{public}d %{public}zu.", res, bundleList.size());
            NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetAllLiveViewEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    int32_t userId = 100;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&, userId]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetAllLiveViewEnabledBundles(userId, bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Get all notification enable status failed");
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

bool AdvancedNotificationService::PublishSlotChangeCommonEvent(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        return false;
    }
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("bundle [%{public}s : %{public}d]", bundleOption->GetBundleName().c_str(), bundleOption->GetUid());

    EventFwk::Want want;
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleOption->GetBundleName());
    want.SetElement(element);
    want.SetParam(AppExecFwk::Constants::UID, bundleOption->GetUid());
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SLOT_CHANGE);
    EventFwk::CommonEventData commonData {want};
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData)) {
        ANS_LOGE("PublishCommonEvent failed");
        return false;
    }

    return true;
}

ErrCode AdvancedNotificationService::SetAdditionConfig(const std::string &key, const std::string &value)
{
    ANS_LOGD("SetAdditionConfig called (%{public}s, %{public}s).", key.c_str(), value.c_str());
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_1);
    message.Message(" key:" + key + " value" + value);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER) &&
        !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_MANAGE_EDM_POLICY)) {
        ANS_LOGE("Permission denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append(" Permission denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (key == RING_TRUST_PKG_KEY) {
        std::lock_guard<ffrt::mutex> lock(soundPermissionInfo_->dbMutex_);
        soundPermissionInfo_->needUpdateCache_ = true;
    }

    bool isSyncConfig = (strcmp(key.c_str(), KEY_NAME) == 0 ||
        strcmp(key.c_str(), CTRL_LIST_KEY_NAME) == 0);
    if (isSyncConfig) {
#ifdef ENABLE_ANS_EXT_WRAPPER
    ErrCode sync_result = EXTENTION_WRAPPER->SyncAdditionConfig(key, value);
    if (sync_result != ERR_OK) {
        ANS_LOGE("Sync addition config result: %{public}d, key: %{public}s, value: %{public}s",
            sync_result, key.c_str(), value.c_str());
        message.ErrorCode(sync_result).Append(" Sync failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return sync_result;
    }
#endif
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->SetKvToDb(key, value, SUBSCRIBE_USER_INIT);
    }));
    notificationSvrQueue_->wait(handler);
    ANS_LOGI("Set addition config result: %{public}d, key: %{public}s, value: %{public}s",
        result, key.c_str(), value.c_str());
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

bool AdvancedNotificationService::IsAgentRelationship(const std::string &agentBundleName,
    const std::string &sourceBundleName)
{
    return NotificationPreferences::GetInstance()->IsAgentRelationship(agentBundleName, sourceBundleName);
}
}  // namespace Notification
}  // namespace OHOS
