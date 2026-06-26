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
#include "ansmanagerstubannexfour_fuzzer.h"
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
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        std::string key1 = fuzzData->ConsumeRandomLengthString();
        bool allowed = fuzzData->ConsumeBool();
        bool enabled = fuzzData->ConsumeBool();
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        sptr<Notification::AnsResultDataSynchronizerImpl> synchronizer =
            new (std::nothrow) Notification::AnsResultDataSynchronizerImpl();
        sptr<Notification::NotificationButtonOption> buttonOption = new Notification::NotificationButtonOption();

        bool support = fuzzData->ConsumeBool();
        service->IsSupportTemplate(stringData, support);
        service->IsSpecialUserAllowedNotify(userId, allowed);
        int32_t deviceIds = fuzzData->ConsumeIntegral<int32_t>();
        service->SetNotificationsEnabledByUser(deviceIds, enabled);
        service->DeleteAllByUser(userId);
        service->SetDoNotDisturbDate(date);
        service->GetDoNotDisturbDate(date);
        service->SetEnabledForBundleSlot(bundleOption, slotType, enabled, false);
        service->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
        std::vector<std::string> dumpInfo;
#ifdef ANM_SUPPORT_DUMP
        service->ShellDump(stringData, stringData, userId, userId, dumpInfo);
#endif
        service->SetSyncNotificationEnabledWithoutApp(userId, enabled);
        service->GetSyncNotificationEnabledWithoutApp(userId, enabled);
        std::shared_ptr<Notification::NotificationUnifiedGroupInfo> groupInfo;
        bool enable = fuzzData->ConsumeBool();
        std::string bundleName = fuzzData->ConsumeRandomLengthString();
        std::string phoneNumber = fuzzData->ConsumeRandomLengthString();
        std::string groupName = fuzzData->ConsumeRandomLengthString();
        std::string deviceType = fuzzData->ConsumeRandomLengthString();
        std::vector<std::shared_ptr<Notification::NotificationRecord>> recordList;
        service->CanPopEnableNotificationDialog(nullptr, enable, bundleName);
        service->RemoveEnableNotificationDialog();
        service->RemoveEnableNotificationDialog(bundleOption);
        service->SetDistributedEnabledByBundle(bundleOption, fuzzData->ConsumeRandomLengthString(),
            fuzzData->ConsumeBool(), fuzzData->ConsumeBool());
        service->IsDistributedEnableByBundle(bundleOption, enable);
        service->SetDefaultNotificationEnabled(bundleOption, enabled);
        service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->ExcuteCancelAll(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->ExcuteDelete(stringData, fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveSystemLiveViewNotifications(bundleName,
            fuzzData->ConsumeIntegral<int32_t>(), fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveSystemLiveViewNotificationsOfSa(fuzzData->ConsumeIntegral<int32_t>());
        service->TriggerLocalLiveView(bundleOption, fuzzData->ConsumeIntegral<int32_t>(), buttonOption);
        service->IsNeedSilentInDoNotDisturbMode(phoneNumber, fuzzData->ConsumeIntegral<int32_t>());
        service->IsNeedSilentInDoNotDisturbMode(phoneNumber, fuzzData->ConsumeIntegral<int32_t>(), userId);
        service->CheckNeedSilent(phoneNumber, fuzzData->ConsumeIntegral<int32_t>(),
            fuzzData->ConsumeIntegral<int32_t>());
        service->ExcuteCancelGroupCancel(bundleOption, groupName, fuzzData->ConsumeIntegral<int32_t>());
        service->RemoveNotificationFromRecordList(recordList);
        service->UpdateUnifiedGroupInfo(key1, groupInfo);
        bool notifictaion = fuzzData->ConsumeBool();
        int32_t enabledType = fuzzData->ConsumeIntegral<int32_t>();
        service->IsDistributedEnabledByBundle(bundleOption, deviceType, notifictaion, enabledType);
        service->DuplicateMsgControl(request);
        service->DeleteDuplicateMsgs(bundleOption);
        service->RemoveExpiredUniqueKey();
        service->SetSmartReminderEnabled(deviceType, enabled);
        service->IsSmartReminderEnabled(deviceType, enabled);
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
