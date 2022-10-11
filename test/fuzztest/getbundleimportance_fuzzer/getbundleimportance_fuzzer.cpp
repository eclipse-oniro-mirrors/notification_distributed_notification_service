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

#include "getbundleimportance_fuzzer.h"

#include "notification_helper.h"
namespace OHOS {
    namespace {
        constexpr uint8_t NOTIFICATION_LEVEL_NUM = 6;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        // test CanPublishNotificationAsBundle function
        std::string representativeBundle(data);
        bool canPublish = true;
        Notification::NotificationHelper::CanPublishNotificationAsBundle(representativeBundle, canPublish);
        // test SetNotificationBadgeNum function and no parameter
        Notification::NotificationHelper::SetNotificationBadgeNum();
        // test IsAllowedNotify function
        bool allowed = true;
        Notification::NotificationHelper::IsAllowedNotify(allowed);
        // test IsAllowedNotifySelf function
        Notification::NotificationHelper::IsAllowedNotifySelf(allowed);
        // test GetBundleImportance function
        uint8_t levels = *data % NOTIFICATION_LEVEL_NUM;
        Notification::NotificationSlot::NotificationLevel level =
            Notification::NotificationSlot::NotificationLevel(levels);
        return Notification::NotificationHelper::GetBundleImportance(level) == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
