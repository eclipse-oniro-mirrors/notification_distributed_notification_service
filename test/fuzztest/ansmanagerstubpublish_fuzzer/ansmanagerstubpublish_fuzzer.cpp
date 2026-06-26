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
#include "ansmanagerstubpublish_fuzzer.h"
#include "notification_record.h"
#include "notification_request.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_call_back_proxy.h"
#endif

namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<Notification::AdvancedNotificationService>();
        service->InitPublishProcess();
        service->CreateDialogManager();
        std::string stringData = fuzzData->ConsumeRandomLengthString();
        sptr<Notification::NotificationRequest> notification = new Notification::NotificationRequest();
        notification->SetOwnerUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetCreatorUid(fuzzData->ConsumeIntegral<int32_t>());
        notification->SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification->SetContent(std::make_shared<Notification::NotificationContent>(content));
        service->Publish(stringData, notification);
        service->PublishWithMaxCapacity(stringData, notification);
        bool canPublish = fuzzData->ConsumeBool();
        service->CanPublishAsBundle(stringData, canPublish);
        service->PublishAsBundle(notification, stringData);
        service->PublishAsBundleWithMaxCapacity(notification, stringData);
        sptr<Notification::NotificationRequest> request = new Notification::NotificationRequest();
        service->PublishContinuousTaskNotification(request);
        service->PublishNotificationBySa(request);
        service->PublishNotificationForIndirectProxy(notification);
        service->PublishNotificationForIndirectProxyWithMaxCapacity(notification);
        int notificationId = fuzzData->ConsumeIntegral<int32_t>();
        int32_t userId = fuzzData->ConsumeIntegral<int32_t>();
        sptr<Notification::AnsResultDataSynchronizerImpl> synchronizer =
            new (std::nothrow) Notification::AnsResultDataSynchronizerImpl();
        service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString());
        if (service->Cancel(notificationId, stringData, fuzzData->ConsumeRandomLengthString(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAll(fuzzData->ConsumeRandomLengthString());
        if (service->CancelAll(fuzzData->ConsumeRandomLengthString(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundle(notificationId, stringData, userId);
        if (service->CancelAsBundle(notificationId, stringData, userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        sptr<Notification::NotificationBundleOption> bundleOption = new Notification::NotificationBundleOption();
        bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(), userId);
        if (service->CancelAsBundle(bundleOption, fuzzData->ConsumeIntegral<int32_t>(), userId,
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        if (service->CancelAsBundleWithAgent(bundleOption, fuzzData->ConsumeIntegral<int32_t>(),
            iface_cast<Notification::IAnsResultDataSynchronizer>(synchronizer->AsObject())) == ERR_OK) {
            synchronizer->Wait();
        }
        int32_t removeReason = fuzzData->ConsumeIntegral<int32_t>();
        service->RemoveNotification(bundleOption, notificationId, stringData, removeReason);
        service->RemoveAllNotifications(bundleOption);
        service->Delete(stringData, removeReason);
        service->DeleteByBundle(bundleOption);
        service->DeleteAll();
        service->CancelGroup(stringData, fuzzData->ConsumeRandomLengthString());
        service->RemoveGroupByBundle(bundleOption, stringData);
        service->CancelContinuousTaskNotification(stringData, notificationId);
        std::vector<std::string> keys;
        keys.emplace_back(fuzzData->ConsumeRandomLengthString());
        service->RemoveNotifications(keys, fuzzData->ConsumeIntegral<int32_t>());
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        service->RemoveNotificationBySlot(bundleOption, slot, fuzzData->ConsumeIntegral<int32_t>());
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
