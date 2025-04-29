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
#include "notification_helper.h"
#undef private
#undef protected
#include "notificationhelper_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        Notification::NotificationHelper notificationHelper;
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t intData = fdp->ConsumeIntegral<int32_t>();
        // test IsSoundEnabled function
        std::string representativeBundle = stringData;
        Notification::NotificationRequest notification;
        notification.SetOwnerUid(intData);
        notification.SetCreatorUid(intData);
        notification.SetSlotType(Notification::NotificationConstant::SlotType::LIVE_VIEW);
        auto content = std::make_shared<Notification::NotificationLiveViewContent>();
        notification.SetContent(std::make_shared<Notification::NotificationContent>(content));
        notificationHelper.PublishNotificationAsBundle(representativeBundle, notification);
        notificationHelper.RemoveNotifications();
        
        bool enabled = fdp->ConsumeBool();
        notificationHelper.SetNotificationsEnabledForAllBundles(stringData, enabled);
        Notification::NotificationBundleOption bundleOption;
        bundleOption.SetBundleName(stringData);
        bundleOption.SetUid(intData);
        uint32_t flag = 0;
        notificationHelper.GetNotificationSlotFlagsAsBundle(bundleOption, flag);
        notificationHelper.SetNotificationSlotFlagsAsBundle(bundleOption, intData);
        notificationHelper.CancelAsBundle(bundleOption, intData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
