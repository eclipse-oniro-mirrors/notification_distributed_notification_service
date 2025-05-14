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

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_permission_def.h"
#include "ansmanagerstubannextwo_fuzzer.h"


constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<Notification::AdvancedNotificationService>();
        service->InitPublishProcess();
        service->CreateDialogManager();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        bool enabled = fuzzData->ConsumeBool();
        service->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
