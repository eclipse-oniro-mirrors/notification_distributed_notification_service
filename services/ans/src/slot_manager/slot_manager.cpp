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
SlotManager::SlotManager() = default;
SlotManager::~SlotManager() = default;
int32_t SlotManager::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = CheckInterfacePermission(code);
    if (result != ERR_OK) {
        return result;
    }
    
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ADD_SLOTS): {
            result = AddSlots(data, reply);
            break;
        }
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_ENABLED_FOR_BUNDLE_SLOT): {
            result = SetEnabledForBundleSlot(data, reply);
            break;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return ERR_ANS_INVALID_PARAM;
        }
    }
    if (SUCCEEDED(result)) {
        return NO_ERROR;
    }

    return result;
}

int32_t SlotManager::CheckInterfacePermission(uint32_t code)
{
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ADD_SLOTS):
        case static_cast<uint32_t>(NotificationInterfaceCode::SET_ENABLED_FOR_BUNDLE_SLOT): {
            bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
            if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
                return ERR_ANS_NON_SYSTEM_APP;
            }

            if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
                return ERR_ANS_PERMISSION_DENIED;
            }

            return ERR_OK;
        }
        default: {
            ANS_LOGE("[OnRemoteRequest] fail: unknown code!");
            return ERR_ANS_INVALID_PARAM;
        }
    }
}

void SlotManager::GenerateSlotReminderMode(const sptr<NotificationSlot> &slot,
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
}  // namespace Notification
}  // namespace OHOS
