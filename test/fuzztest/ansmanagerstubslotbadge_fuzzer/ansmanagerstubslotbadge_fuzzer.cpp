/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_dialog_callback_proxy.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "ansmanagerstubslotbadge_fuzzer.h"
#include "notification_record.h"
#include "notification_request.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_call_back_proxy.h"
#endif

constexpr uint8_t SLOT_TYPE_NUM = 5;

namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<Notification::AdvancedNotificationService>();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        sptr<Notification::AnsResultDataSynchronizerImpl> synchronizer =
            new (std::nothrow) Notification::AnsResultDataSynchronizerImpl();
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();

        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        service->AddSlotByType(slotType);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        service->AddSlots(slots);
        service->RemoveSlotByType(slotType);
        service->RemoveAllSlots();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        service->GetSlotByType(slotType, slot);
        service->GetSlots(slots);
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        service->GetSlotNumAsBundle(bundleOption, num);
        service->GetSlotsByBundle(bundleOption, slots);
        service->UpdateSlots(bundleOption, slots);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        service->GetActiveNotifications(notifications, fuzzData->ConsumeRandomLengthString());
        if (service->GetActiveNotifications(fuzzData->ConsumeRandomLengthString(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        service->GetAllActiveNotifications(notificationss);
        if (service->GetAllActiveNotifications(
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        std::vector<std::string> key;
        service->GetSpecialActiveNotifications(key, notificationss);
        service->SetNotificationBadgeNum(num);
        int importance = fuzzData->ConsumeIntegral<int32_t>();
        service->GetBundleImportance(importance);
        bool granted = fuzzData->ConsumeBool();
        service->HasNotificationPolicyAccessPermission(granted);
        bool enabled = fuzzData->ConsumeBool();
        service->SetNotificationsEnabledForBundle(stringData, enabled);
        service->SetNotificationsEnabledForAllBundles(stringData, enabled);
        service->SetNotificationsEnabledForSpecialBundle(stringData, bundleOption, enabled);
        service->SetShowBadgeEnabledForBundle(bundleOption, enabled);
        service->GetShowBadgeEnabledForBundle(bundleOption, enabled);
        if (service->GetShowBadgeEnabledForBundle(bundleOption,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->GetShowBadgeEnabled(enabled);
        if (service->GetShowBadgeEnabled(
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        service->SetBadgeNumber(badgeNum, fuzzData->ConsumeRandomLengthString());
        service->SetBadgeNumberByBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        service->HandleBadgeEnabledChanged(bundleOption, enabled);
        service->SetBadgeNumberForDhByBundle(bundleOption, badgeNum);
        bool allowed = fuzzData->ConsumeBool();
        service->IsAllowedNotify(allowed);
        service->IsAllowedNotifySelf(allowed);
        service->IsAllowedNotifySelf(bundleOption, allowed);
        service->IsAllowedNotifyForBundle(bundleOption, allowed);
        service->IsSpecialBundleAllowedNotify(bundleOption, allowed);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        service->SetDoNotDisturbDateByUser(userId, date);
        service->GetDoNotDisturbDateByUser(userId, date);
        bool doesSupport = fuzzData->ConsumeBool();
        service->DoesSupportDoNotDisturbMode(doesSupport);
        service->IsDistributedEnabled(enabled);
        service->EnableDistributedByBundle(bundleOption, enabled);
        service->EnableDistributedSelf(enabled);
        service->EnableDistributed(enabled);
        service->IsDistributedEnableByBundle(bundleOption, enabled);
        int32_t remindType;
        service->GetDeviceRemindType(remindType);
        service->SelfClean();
        constexpr int sleepMs = 1000;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
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
