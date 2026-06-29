/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "notification_live_view_content.h"
#include "notification_record.h"
#define private public
#define protected public
#include "advanced_notification_service.h"
#include "notification_trigger.h"
#include "notification_geofence.h"
#include "notification_ringtone_info.h"
#undef private
#undef protected
#include "service_private_service.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <chrono>
#include <thread>
#include "ans_dialog_callback_proxy.h"
#include "ans_subscriber_stub.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "mock_notification_bundle_option.h"
#include "mock_notification_request.h"
#include "mock_notification_slot.h"
#include "notification_button_option.h"
#include "notification_content.h"
#include "notification_do_not_disturb_date.h"
#include "notification.h"
#include "notification_request.h"
#include "notification_preferences.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        auto service = std::make_shared<AdvancedNotificationService>();
        sptr<AnsResultDataSynchronizerImpl> synchronizer = new AnsResultDataSynchronizerImpl();
        service->InitPublishProcess();
        service->CreateDialogManager();
        {
            // Service (L1053-L1077)
        std::string randomString = fuzzData->ConsumeRandomLengthString();
        int32_t randomInt32 = fuzzData->ConsumeIntegral<int32_t>();
        sptr<NotificationBundleOption> bundleOption = ObjectBuilder<NotificationBundleOption>::Build(fuzzData);
        sptr<NotificationBundleOption> targetBundleOption = nullptr;
        sptr<NotificationRequest> request = new NotificationRequest();
        request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<NotificationLiveViewContent>();
        request->SetContent(std::make_shared<NotificationContent>(content));
        request->SetOwnerUid(randomInt32);
        request->SetCreatorUid(randomInt32);
        auto flag = std::make_shared<NotificationFlags>();
        request->SetFlags(flag);
        std::shared_ptr<NotificationRecord> record =
            service->MakeNotificationRecord(request, bundleOption);
        record->slot = new NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
        service->QueryDoNotDisturbProfile(randomInt32, randomString, randomString);
        service->CheckDoNotDisturbProfile(record);
        service->DoNotDisturbUpdataReminderFlags(record);
        service->UpdateSlotAuthInfo(record);
        service->Filter(record, fuzzData->ConsumeBool());
        service->ChangeNotificationByControlFlags(record, fuzzData->ConsumeBool());
        service->CheckPublishPreparedNotification(record, fuzzData->ConsumeBool());
        service->UpdateInNotificationList(record);
        service->PublishInNotificationList(record);
        service->IsNeedPushCheck(request);
        }
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    constexpr int sleepMs = 1000;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
