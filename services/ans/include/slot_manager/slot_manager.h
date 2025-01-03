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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_SLOT_MANAGER_H
#define BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_SLOT_MANAGER_H

#include <functional>
#include <map>

#include "ans_manager_interface.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "base_manager.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "iremote_stub.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
class SlotManager final : protected BaseManager {
public:
    DECLARE_DELAYED_SINGLETON(SlotManager);
public:
    static const uint32_t DEFAULT_SLOT_FLAGS = 59; // 0b111011
    /**
     * @brief Handle remote request.
     *
     * @param data Indicates the input parcel.
     * @param reply Indicates the output parcel.
     * @param option Indicates the message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
private:
    ErrCode AddSlots(MessageParcel &data, MessageParcel &reply);
    ErrCode AddSlotsSyncQue(const std::vector<sptr<NotificationSlot>> &slots);
    ErrCode AddSlotsInner(const std::vector<sptr<NotificationSlot>> &slots, sptr<NotificationBundleOption> bundleOption);

    ErrCode SetEnabledForBundleSlot(MessageParcel &data, MessageParcel &reply);
    ErrCode SetEnabledForBundleSlotSyncQue(
        const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl);
    ErrCode SetEnabledForBundleSlotInner(
        const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationBundleOption> &bundle,
        const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl);
private:
    int32_t CheckInterfacePermission(uint32_t code);
    void GenerateSlotReminderMode(const sptr<NotificationSlot> &slot, const sptr<NotificationBundleOption> &bundle,
        bool isSpecifiedSlot = false, uint32_t defaultSlotFlags = DEFAULT_SLOT_FLAGS);
    void SendEnableNotificationSlotHiSysEvent(
        const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
        bool enabled, ErrCode errCode);
    ErrCode AddSlotThenPublishEvent(
        const sptr<NotificationSlot> &slot,
        const sptr<NotificationBundleOption> &bundle,
        bool enabled, bool isForceControl);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_SLOT_MANAGER_H
