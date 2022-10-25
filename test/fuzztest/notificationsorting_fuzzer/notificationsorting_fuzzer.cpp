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
#include "notification_sorting.h"
#undef private
#undef protected
#include "notificationsorting_fuzzer.h"

namespace OHOS {
    namespace {
        constexpr uint8_t ENABLE = 2;
    }
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        Notification::NotificationSorting notificationSorting;
        sptr<Notification::NotificationSlot> slot = nullptr;
        notificationSorting.SetSlot(slot);
        notificationSorting.SetGroupKeyOverride(stringData);
        notificationSorting.Dump();
        notificationSorting.SetKey(stringData);
        int32_t importance = static_cast<int32_t>(GetU32Data(data));
        notificationSorting.SetImportance(importance);
        uint64_t ranking = 1;
        notificationSorting.SetRanking(ranking);
        notificationSorting.SetVisiblenessOverride(importance);
        notificationSorting.SetDisplayBadge(*data % ENABLE);
        notificationSorting.SetHiddenNotification(*data % ENABLE);
        Parcel parcel;
        return notificationSorting.Marshalling(parcel);
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
