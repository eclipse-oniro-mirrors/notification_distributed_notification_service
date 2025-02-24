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

#include "slot_manager.h"

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

#include "../advanced_notification_inline.cpp"
#include "notification_extension_wrapper.h"
#include "notification_analytics_util.h"
#include "event_report.h"

namespace OHOS {
namespace Notification {
ErrCode SlotManager::SetEnabledForBundleSlot(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<NotificationBundleOption> bundleOption = data.ReadStrongParcelable<NotificationBundleOption>();
    if (bundleOption == nullptr) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read slot type failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(type);

    bool enabled = false;
    if (!data.ReadBool(enabled)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read enabled failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    bool isForceControl = false;
    if (!data.ReadBool(isForceControl)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: read isForceControl failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ANS_LOGD("slotType: %{public}d, enabled: %{public}d, isForceControl: %{public}d",
        slotType, enabled, isForceControl);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_5, EventBranchId::BRANCH_4);
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()) +
        " slotType: " + std::to_string(static_cast<uint32_t>(slotType)) +
        " enabled: " +std::to_string(enabled) + "isForceControl" + std::to_string(isForceControl));

    ErrCode result = SetEnabledForBundleSlotSyncQue(bundleOption, slotType, enabled, isForceControl);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetEnabledForBundleSlot] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    ANS_LOGI("%{public}s_%{public}d, SetEnabledForBundleSlot successful.",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid());
    return result;
}

ErrCode SlotManager::SetEnabledForBundleSlotSyncQue(
    const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    sptr<NotificationBundleOption> bundle = AdvancedNotificationService::GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    auto excuteQueue = AdvancedNotificationService::GetInstance()->GetNotificationSvrQueue();
    if (excuteQueue == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result;
    ffrt::task_handle handler = excuteQueue->submit_h(std::bind([&]() {
        result = SetEnabledForBundleSlotInner(bundleOption, bundle, slotType, enabled, isForceControl);
    }));
    excuteQueue->wait(handler);
    return result;
}

ErrCode SlotManager::SetEnabledForBundleSlotInner(
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

void SlotManager::SendEnableNotificationSlotHiSysEvent(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
    bool enabled, ErrCode errCode)
{
    if (bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    eventInfo.slotType = slotType;
    eventInfo.enable = enabled;
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT, eventInfo);
    }
}

ErrCode SlotManager::AddSlotThenPublishEvent(
    const sptr<NotificationSlot> &slot,
    const sptr<NotificationBundleOption> &bundle,
    bool enabled, bool isForceControl)
{
    bool allowed = false;
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundle, allowed);
    if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
        result = ERR_OK;
        allowed = AdvancedNotificationService::GetInstance()->CheckApiCompatibility(bundle);
        AdvancedNotificationService::GetInstance()->SetDefaultNotificationEnabled(bundle, allowed);
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
        AdvancedNotificationService::GetInstance()->RemoveNotificationBySlot(
            bundle, slot, NotificationConstant::DISABLE_SLOT_REASON_DELETE);
    } else {
        if (!slot->GetForceControl() && !allowed) {
            AdvancedNotificationService::GetInstance()->RemoveNotificationBySlot(
                bundle, slot, NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE);
        }
    }

    AdvancedNotificationService::GetInstance()->PublishSlotChangeCommonEvent(bundle);
    return result;
}
}  // namespace Notification
}  // namespace OHOS
