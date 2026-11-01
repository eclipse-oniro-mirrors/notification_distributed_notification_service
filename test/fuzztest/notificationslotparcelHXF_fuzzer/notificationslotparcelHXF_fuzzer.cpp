/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "notificationslotparcelHXF_fuzzer.h"
#include "notification_constant.h"
#include "notification_slot.h"
#include "parcel.h"
#include "uri.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
    namespace {
        constexpr uint8_t NOTIFICATION_LEVEL_NUM = 6;   // LEVEL_NONE..LEVEL_UNDEFINED
        constexpr uint8_t SLOT_TYPE_NUM = 8;            // SOCIAL_COMMUNICATION..EMERGENCY_INFORMATION
        constexpr uint8_t VISIBLENESS_TYPE_NUM = 5;     // NO_OVERRIDE..ILLEGAL_TYPE
        constexpr uint8_t MAX_VIBRATION_ELEMENTS = 16;  // probe small, mid, large patterns
        constexpr size_t DESCRIPTION_PROBE_LEN = 1100;  // probe above the 1000-char truncation limit
        constexpr size_t SOUND_URI_LEN_FACTOR = 16;
        constexpr size_t SOUND_URI_LEN = MAX_VIBRATION_ELEMENTS * SOUND_URI_LEN_FACTOR;
        constexpr size_t SLOT_TYPE_STRING_LEN = 32;
        template <typename ValueType, typename DivisorType>
        DivisorType ModuloByNonZero(ValueType value, DivisorType divisor)
        {
            if (divisor == 0) {
                return 0;
            }
            return static_cast<DivisorType>(value % divisor);
        }
    }

    void FuzzSlotDescription(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        std::string description = fdp->ConsumeRandomLengthString(DESCRIPTION_PROBE_LEN);
        slot.SetDescription(description);
        slot.GetDescription();
    }

    void FuzzSlotLight(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        slot.SetEnableLight(fdp->ConsumeBool());
        slot.CanEnableLight();
        slot.SetLedLightColor(fdp->ConsumeIntegral<int32_t>());
        slot.GetLedLightColor();
    }

    void FuzzSlotLevel(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        uint8_t levelRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), NOTIFICATION_LEVEL_NUM);
        slot.SetLevel(static_cast<Notification::NotificationSlot::NotificationLevel>(levelRaw));
        slot.GetLevel();
    }

    void FuzzSlotVisibleness(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        uint8_t visiblenessRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), VISIBLENESS_TYPE_NUM);
        slot.SetLockscreenVisibleness(
            static_cast<Notification::NotificationConstant::VisiblenessType>(visiblenessRaw));
        slot.GetLockScreenVisibleness();
    }

    void FuzzSlotVibration(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        uint8_t vibrationCount = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), MAX_VIBRATION_ELEMENTS);
        std::vector<int64_t> vibrationPattern;
        for (uint8_t i = 0; i < vibrationCount; ++i) {
            vibrationPattern.push_back(fdp->ConsumeIntegral<int64_t>());
        }
        slot.SetVibrationStyle(vibrationPattern);
        slot.GetVibrationStyle();
        slot.CanVibrate();
    }

    void FuzzSlotSound(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        std::string soundUriStr = fdp->ConsumeRandomLengthString(SOUND_URI_LEN);
        Uri soundUri(soundUriStr);
        slot.SetSound(soundUri);
        slot.GetSound();
    }

    void FuzzSlotFlags(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        slot.EnableBypassDnd(fdp->ConsumeBool());
        slot.IsEnableBypassDnd();
        slot.EnableBadge(fdp->ConsumeBool());
        slot.IsShowBadge();

        slot.SetEnable(fdp->ConsumeBool());
        slot.GetEnable();
        slot.SetForceControl(fdp->ConsumeBool());
        slot.GetForceControl();

        slot.SetSlotFlags(fdp->ConsumeIntegral<uint32_t>());
        slot.GetSlotFlags();

        slot.SetReminderMode(fdp->ConsumeIntegral<uint32_t>());
        slot.GetReminderMode();
    }

    void FuzzSlotAuthorization(FuzzedDataProvider *fdp, Notification::NotificationSlot &slot)
    {
        slot.SetAuthorizedStatus(fdp->ConsumeIntegral<int32_t>());
        slot.GetAuthorizedStatus();
        slot.SetAuthHintCnt(fdp->ConsumeIntegral<int32_t>());
        slot.GetAuthHintCnt();
        slot.AddAuthHintCnt();
    }

    void FuzzSlotParcel(Notification::NotificationSlot &slot)
    {
        slot.Dump();

        Parcel parcel;
        if (slot.Marshalling(parcel)) {
            Notification::NotificationSlot *restored =
                Notification::NotificationSlot::Unmarshalling(parcel);
            delete restored;
        }
    }

    void FuzzSlotTypeString(FuzzedDataProvider *fdp)
    {
        std::string slotTypeStr = fdp->ConsumeRandomLengthString(SLOT_TYPE_STRING_LEN);
        Notification::NotificationConstant::SlotType parsedType;
        Notification::NotificationSlot::GetSlotTypeByString(slotTypeStr, parsedType);
    }

    bool test(FuzzedDataProvider *fdp)
    {
        uint8_t slotTypeRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), SLOT_TYPE_NUM);
        Notification::NotificationSlot slot(
            static_cast<Notification::NotificationConstant::SlotType>(slotTypeRaw));

        FuzzSlotDescription(fdp, slot);
        FuzzSlotLight(fdp, slot);
        FuzzSlotLevel(fdp, slot);
        FuzzSlotVisibleness(fdp, slot);
        FuzzSlotVibration(fdp, slot);
        FuzzSlotSound(fdp, slot);
        FuzzSlotFlags(fdp, slot);
        FuzzSlotAuthorization(fdp, slot);
        FuzzSlotParcel(slot);
        FuzzSlotTypeString(fdp);

        return true;
    }
} // namespace OHOS
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::test(&fdp);
    return 0;
}
