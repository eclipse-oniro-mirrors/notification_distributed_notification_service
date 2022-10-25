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

#include "getallactivenotifications_fuzzer.h"

#include "notification_helper.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        // test IsAllowedNotify function
        std::string stringData(data);
        int32_t usingData = static_cast<int32_t>(GetU32Data(data));
        Notification::NotificationBundleOption bundleOption;
        bundleOption.SetBundleName(stringData);
        bundleOption.SetUid(usingData);
        bool allowed = *data % ENABLE;
        Notification::NotificationHelper::IsAllowedNotify(bundleOption, allowed);
        // test GetNotificationSlotsForBundle function and one parameter
        sptr<Notification::Notification> notification = nullptr;
        std::vector<sptr<Notification::Notification>> notifications;
        notifications.emplace_back(notification);
        Notification::NotificationHelper::GetAllActiveNotifications(notifications);
        // test GetNotificationSlotsForBundle function and two parameter
        std::vector<std::string> keys;
        keys.emplace_back(stringData);
        return Notification::NotificationHelper::GetAllActiveNotifications(keys, notifications) == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size > GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
