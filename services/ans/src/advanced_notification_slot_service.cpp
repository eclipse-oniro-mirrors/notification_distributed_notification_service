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
#include "ans_permission_def.h"
#include "errors.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "hitrace_meter_adapter.h"
#include "os_account_manager_helper.h"
#include "ipc_skeleton.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "smart_reminder_center.h"
#endif

#include "advanced_notification_inline.cpp"
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
}

ErrCode AdvancedNotificationService::AddSlots(const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

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
    ANS_LOGD("%{public}s", __FUNCTION__);

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
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetSlotsByBundle(
    const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

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
    }));

    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetSlotByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

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
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundle, slotType, slot);
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
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
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
    ANS_LOGD("%{public}s", __FUNCTION__);

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

ErrCode AdvancedNotificationService::AddSlotByType(NotificationConstant::SlotType slotType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

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

ErrCode AdvancedNotificationService::GetEnabledForBundleSlotSelf(
    const NotificationConstant::SlotType &slotType, bool &enabled)
{
    ANS_LOGD("slotType: %{public}d", slotType);

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

    return result;
}

ErrCode AdvancedNotificationService::GetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,
    uint32_t &slotFlags)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
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
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,
    uint32_t slotFlags)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
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
        if (record->request->IsSystemLiveView()) {
            ANS_LOGI("System live view no need add sloty.");
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
            (bundleName == CALL_UI_BUNDLE || slot->GetEnable() ||
            (record->request->GetAgentBundle() != nullptr && record->request->IsSystemLiveView()) ||
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
    }
    return ret;
}

void AdvancedNotificationService::GenerateSlotReminderMode(const sptr<NotificationSlot> &slot,
    const sptr<NotificationBundleOption> &bundle, bool isSpecifiedSlot, uint32_t defaultSlotFlags)
{
    uint32_t slotFlags = defaultSlotFlags;
    auto ret = NotificationPreferences::GetInstance()->GetNotificationSlotFlagsForBundle(bundle, slotFlags);
    if (ret != ERR_OK) {
        ANS_LOGI("Failed to get slotflags for bundle, use default slotflags.");
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
    NotificationConstant::SlotType type = request->GetSlotType();
    auto flags = std::make_shared<NotificationFlags>();

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
        flags->SetSoundEnabled(NotificationConstant::FlagStatus::OPEN);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG) != 0) {
        flags->SetLockScreenVisblenessEnabled(true);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::BANNER_FLAG) != 0) {
        flags->SetBannerEnabled(true);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG) != 0) {
        flags->SetLightScreenEnabled(true);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::VIBRATION_FLAG) != 0) {
        flags->SetVibrationEnabled(NotificationConstant::FlagStatus::OPEN);
    }

    if ((slotReminderMode & NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG) != 0) {
        flags->SetStatusIconEnabled(true);
    }

    request->SetFlags(flags);
    if (request->IsCommonLiveView()) {
        LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewReminderFlags(request);
        LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewVoiceContent(request);
    }
    ANS_LOGI("SetFlags-GetRemindMode, notificationKey = %{public}s flags = %{public}d",
        request->GetKey().c_str(), flags->GetReminderFlags());
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    DelayedSingleton<SmartReminderCenter>::GetInstance()->ReminderDecisionProcess(request);
#endif
    ANS_LOGI("classification:%{public}s", request->GetClassification().c_str());
}

ErrCode AdvancedNotificationService::GetSlotByType(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("Failed to generateBundleOption.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption, slotType, slot);
    }));
    notificationSvrQueue_->wait(handler);
    // if get slot failed, it still return ok.
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveSlotByType(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

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
    ANS_LOGD("%{public}s", __FUNCTION__);

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
    bool enabled, bool isForceControl)
{
    bool allowed = false;
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, allowed);
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        result = ERR_OK;
        allowed = CheckApiCompatibility(bundle);
        SetDefaultNotificationEnabled(bundle, allowed);
    }

    slot->SetEnable(enabled);
    slot->SetForceControl(isForceControl);
    slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
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
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
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
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
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
            ANS_LOGE("Get enable slot: GetNotificationSlot failed");
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

    return result;
}

ErrCode AdvancedNotificationService::GetAllNotificationEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    if (!AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Is not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetAllNotificationEnabledBundles(bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Get all notification enable status failed");
            return;
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

ErrCode AdvancedNotificationService::GetAllDistribuedEnabledBundles(
    const std::string& deviceType, std::vector<NotificationBundleOption> &bundleOption)
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
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&, userId, deviceType]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetAllDistribuedEnabledBundles(userId,
            deviceType, bundleOption);
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
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
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
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
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
        std::lock_guard<std::mutex> lock(soundPermissionInfo_->dbMutex_);
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
