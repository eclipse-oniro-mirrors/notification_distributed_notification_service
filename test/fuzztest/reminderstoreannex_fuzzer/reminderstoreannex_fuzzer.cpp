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
#include "reminder_store.h"
#undef private
#undef protected
#include "reminderstoreannex_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        Notification::ReminderStore reminderStore;
        // test GetReminders function
        std::string queryCondition(data);
        reminderStore.GetReminders(queryCondition);
        // test GetAllValidReminders function
        reminderStore.GetAllValidReminders();
        // test Query function
        reminderStore.Query(queryCondition);
        // test GetBundleOption function
        sptr<Notification::NotificationBundleOption> bundleOption;
        int32_t reminderId = static_cast<int32_t>(GetU32Data(data));
        reminderStore.GetBundleOption(reminderId, bundleOption);
        // test GetInt32Val function
        std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = std::make_shared<NativeRdb::AbsSharedResultSet>();
        std::string name(data);
        int32_t value = static_cast<int32_t>(GetU32Data(data));
        reminderStore.GetInt32Val(resultSet, name, value);
        std::string value1(data);
        reminderStore.GetStringVal(resultSet, name, value1);
        // test BuildReminder function
        reminderStore.BuildReminder(resultSet);
        return true;
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
