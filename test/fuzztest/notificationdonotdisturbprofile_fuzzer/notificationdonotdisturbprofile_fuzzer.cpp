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

#define private public  // NOLINT
#define protected public  // NOLINT
#include "notification_do_not_disturb_profile.h"
#undef private
#undef protected
#include "notificationdonotdisturbprofile_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

static void TestNotificationDoNotDisturbProfile(FuzzedDataProvider *fuzzData)
{
    int64_t id = fuzzData->ConsumeIntegral<int64_t>();
    std::string name = fuzzData->ConsumeRandomLengthString();

    std::vector<NotificationBundleOption> trustList;
    std::string bundleName = fuzzData->ConsumeRandomLengthString();
    int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
    trustList.emplace_back(bundleName, uid);

    NotificationDoNotDisturbProfile profile(id, name, trustList);
    profile.GetProfileId();
    profile.GetProfileName();
    profile.GetProfileTrustList();

    NotificationDoNotDisturbProfile profile2;
    profile2.SetProfileId(fuzzData->ConsumeIntegral<int64_t>());
    profile2.SetProfileName(fuzzData->ConsumeRandomLengthString());

    std::vector<NotificationBundleOption> newTrustList;
    newTrustList.emplace_back(fuzzData->ConsumeRandomLengthString(), fuzzData->ConsumeIntegral<int32_t>());
    profile2.SetProfileTrustList(newTrustList);

    std::string jsonStr = profile2.ToJson();
    profile2.FromJson(jsonStr);

    nlohmann::json jsonObject;
    profile2.GetProfileJson(jsonObject);

    Parcel parcel;
    profile2.Marshalling(parcel);
    auto unmarshalledProfile = NotificationDoNotDisturbProfile::Unmarshalling(parcel);
    if (unmarshalledProfile != nullptr) {
        unmarshalledProfile->GetProfileId();
        unmarshalledProfile->GetProfileName();
        delete unmarshalledProfile;
        unmarshalledProfile = nullptr;
    }
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationDoNotDisturbProfile(fuzzData);
    return true;
}
}  // namespace Notification
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fuzzData(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fuzzData);
    return 0;
}
