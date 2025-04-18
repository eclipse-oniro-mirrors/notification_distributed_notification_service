/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "addnotificationslot_fuzzer.h"

#include "base/accesscontrol/sandbox_manager/test/fuzztest/common/alloc_token.h"
#include "notification_helper.h"
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    namespace {
        constexpr uint8_t SLOT_LEVEL_NUM = 6;
        constexpr uint8_t SLOT_VISIBLENESS_TYPE_NUM = 4;
        constexpr uint8_t SLOT_TYPE_NUM = 5;
    }
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider* fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        Notification::NotificationSlot slot;
        slot.SetDescription(stringData);
        slot.SetEnableLight(fdp->ConsumeBool());
        slot.SetEnableVibration(fdp->ConsumeBool());
        slot.SetLedLightColor(fdp->ConsumeIntegral<uint32_t>());

        uint8_t level = fdp->ConsumeIntegral<uint8_t>() % SLOT_LEVEL_NUM;
        Notification::NotificationSlot::NotificationLevel notificatoinLevel =
            Notification::NotificationSlot::NotificationLevel(level);
        slot.SetLevel(notificatoinLevel);

        uint8_t visibleness = fdp->ConsumeIntegral<uint8_t>() % SLOT_VISIBLENESS_TYPE_NUM;
        Notification::NotificationConstant::VisiblenessType visiblenessType =
            Notification::NotificationConstant::VisiblenessType(visibleness);
        slot.SetLockscreenVisibleness(visiblenessType);

        uint8_t type = fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        slot.SetType(slotType);

        return Notification::NotificationHelper::AddNotificationSlot(slot) == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    std::vector<std::string> permissions;
    NativeTokenGet(permissions);
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
