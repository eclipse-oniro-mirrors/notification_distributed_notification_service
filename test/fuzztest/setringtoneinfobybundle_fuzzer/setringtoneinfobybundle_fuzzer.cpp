/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "setringtoneinfobybundle_fuzzer.h"

#include "notification_helper.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t usingData = fdp->ConsumeIntegral<int32_t>();
        std::string stringTitle = fdp->ConsumeRandomLengthString();
        std::string stringName = fdp->ConsumeRandomLengthString();
        std::string stringUri = fdp->ConsumeRandomLengthString();
        Notification::NotificationBundleOption bundleOption;
        bundleOption.SetBundleName(stringData);
        bundleOption.SetUid(usingData);
        Notification::NotificationRingtoneInfo ringtoneInfo;
        ringtoneInfo.SetRingtoneType(Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
        ringtoneInfo.SetRingtoneTitle(stringTitle);
        ringtoneInfo.SetRingtoneFileName(stringName);
        ringtoneInfo.SetRingtoneUri(stringUri);
        // test SetRingtoneInfoByBundle function
        Notification::NotificationHelper::SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
        // test GetRingtoneInfoByBundle function
        return Notification::NotificationHelper::GetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
