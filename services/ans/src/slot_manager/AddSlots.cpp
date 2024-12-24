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

namespace OHOS {
namespace Notification {
ErrCode SlotManager::AddSlots(MessageParcel &data, MessageParcel &reply)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::vector<sptr<NotificationSlot>> slots;
    if (!ReadParcelableVector(slots, data)) {
        ANS_LOGE("[HandleAddSlots] fail: read slotsSize failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = AddSlotsSyncQue(slots);

    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleAddSlots] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode SlotManager::AddSlotsSyncQue(const std::vector<sptr<NotificationSlot>> &slots)
{
    sptr<NotificationBundleOption> bundleOption = AdvancedNotificationService::GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    auto excuteQueue = AdvancedNotificationService::GetInstance()->GetNotificationSvrQueue();
    if (excuteQueue == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result;
    ffrt::task_handle handler = excuteQueue->submit_h(std::bind([&]() {
        result = AddSlotsInner(slots, bundleOption);
    }));
    excuteQueue->wait(handler);
    return result;
}

ErrCode SlotManager::AddSlotsInner(const std::vector<sptr<NotificationSlot>> &slots, sptr<NotificationBundleOption> bundleOption)
{
    if (slots.size() == 0) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    std::vector<sptr<NotificationSlot>> addSlots;
    for (auto slot : slots) {
        sptr<NotificationSlot> originalSlot;
        result = NotificationPreferences::GetInstance()->GetNotificationSlot(bundleOption,
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
    return result;
}

}  // namespace Notification
}  // namespace OHOS
