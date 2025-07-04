/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_NOTIFICATION_SLOT_H
#define MOCK_NOTIFICATION_SLOT_H

#include "mock_fuzz_object.h"
#include "notification_slot.h"
namespace OHOS {
namespace Notification {

constexpr uint32_t MAX_SLOT_TYPE = 5;
constexpr uint32_t MAX_STR_LENGTH = 20;
constexpr uint32_t MAX_FLAGS = 63;

template <>
NotificationSlot* ObjectBuilder<NotificationSlot>::Build(FuzzedDataProvider *fdp)
{
    NotificationSlot* slot = new NotificationSlot(static_cast<OHOS::Notification::NotificationConstant::SlotType>(
        fdp->ConsumeIntegralInRange<int>(0, MAX_SLOT_TYPE)));
    slot->SetEnableLight(fdp->ConsumeBool());
    slot->SetEnableVibration(fdp->ConsumeBool());
    slot->SetDescription(fdp->ConsumeRandomLengthString(MAX_STR_LENGTH));
    slot->SetLedLightColor(fdp->ConsumeIntegral<int32_t>());
    slot->SetLevel(static_cast<OHOS::Notification::NotificationSlot::NotificationLevel>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_SLOT_TYPE)));
    slot->SetSlotFlags(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FLAGS));
    slot->EnableBypassDnd(fdp->ConsumeBool());
    slot->EnableBadge(fdp->ConsumeBool());
    slot->SetEnable(fdp->ConsumeBool());
    slot->SetForceControl(fdp->ConsumeBool());
    slot->SetAuthorizedStatus(fdp->ConsumeIntegralInRange<int32_t>(0, 1));
    slot->SetAuthHintCnt(fdp->ConsumeIntegralInRange<int32_t>(0, 1));
    slot->SetReminderMode(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FLAGS));
    
    ANS_LOGE("Build mock veriables");
    return slot;
}

}  // namespace Notification
}  // namespace OHOS
#endif  // MOCK_NOTIFICATION_SLOT_H