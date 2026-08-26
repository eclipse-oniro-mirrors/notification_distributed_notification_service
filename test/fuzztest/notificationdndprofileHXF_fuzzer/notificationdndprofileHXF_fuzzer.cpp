/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "notificationdndprofileHXF_fuzzer.h"
#include "ans_const_define.h"
#include "ans_permission_def.h"
#include "fuzz_common_base.h"
#include "notification_bundle_option.h"
#include "notification_do_not_disturb_profile.h"
#include "notification_helper.h"
#include "parcel.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <limits>
#include <string>
#include <vector>

namespace OHOS {
namespace {
constexpr uint8_t MAX_TRUSTLIST_ENTRIES = 12;
constexpr uint8_t HIT_OVERSIZED_PARCEL_CASE = 0;
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 128;
constexpr int32_t MAX_SIZE_TYPE = 512;
constexpr int32_t MAX_TYPE = 64;

Notification::NotificationBundleOption BuildBundleOption(FuzzedDataProvider *fdp)
{
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_NUM);
    int32_t uid = fdp->ConsumeIntegral<int32_t>();
    return Notification::NotificationBundleOption(bundleName, uid);
}

std::vector<Notification::NotificationBundleOption> BuildTrustList(FuzzedDataProvider *fdp)
{
    std::vector<Notification::NotificationBundleOption> trustList;
    uint8_t count = fdp->ConsumeIntegralInRange<uint8_t>(0, MAX_TRUSTLIST_ENTRIES);
    for (uint8_t i = 0; i < count; ++i) {
        trustList.push_back(BuildBundleOption(fdp));
    }
    return trustList;
}

Notification::NotificationDoNotDisturbProfile BuildProfile(
    int64_t profileId, const std::string &name, const std::vector<Notification::NotificationBundleOption> &trustList)
{
    Notification::NotificationDoNotDisturbProfile profile(profileId, name, trustList);
    profile.SetProfileId(profileId);
    profile.GetProfileId();
    profile.SetProfileName(name);
    profile.GetProfileName();
    profile.SetProfileTrustList(trustList);
    profile.GetProfileTrustList();
    return profile;
}

void ExerciseParcelPaths(FuzzedDataProvider *fdp, Notification::NotificationDoNotDisturbProfile &profile)
{
    Parcel parcel;
    if (profile.Marshalling(parcel)) {
        Notification::NotificationDoNotDisturbProfile *result =
            Notification::NotificationDoNotDisturbProfile::Unmarshalling(parcel);
        delete result;
    }

    Parcel invalidSizeParcel;
    invalidSizeParcel.WriteInt64(profile.GetProfileId());
    invalidSizeParcel.WriteString(profile.GetProfileName());
    invalidSizeParcel.WriteUint32(
        static_cast<uint32_t>(Notification::MAX_PARCELABLE_VECTOR_NUM + 1));
    profile.ReadFromParcel(invalidSizeParcel);

    if (fdp->remaining_bytes() > 0 && fdp->ConsumeIntegral<uint8_t>() == HIT_OVERSIZED_PARCEL_CASE) {
        std::vector<Notification::NotificationBundleOption> oversizedTrustList(
            static_cast<size_t>(Notification::MAX_PARCELABLE_VECTOR_NUM + 1));
        Notification::NotificationDoNotDisturbProfile oversizedProfile(
            profile.GetProfileId(), profile.GetProfileName(), oversizedTrustList);
        Parcel oversizedParcel;
        oversizedProfile.Marshalling(oversizedParcel);
    }
}

void ExerciseJsonPaths(FuzzedDataProvider *fdp, Notification::NotificationDoNotDisturbProfile &profile)
{
    std::string jsonStr = profile.ToJson();
    profile.FromJson(jsonStr);
    profile.FromJson(fdp->ConsumeRandomLengthString(MAX_SIZE_TYPE));
    profile.FromJson("[]");
    profile.FromJson("{\"id\":\"bad\",\"name\":1,\"trustlist\":{}}");
}

void ExerciseFrameworkPaths(FuzzedDataProvider *fdp, int64_t profileId, int32_t userId,
    const std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> &profiles)
{
    std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> emptyProfiles;
    Notification::NotificationHelper::AddDoNotDisturbProfiles(emptyProfiles);
    Notification::NotificationHelper::AddDoNotDisturbProfiles(emptyProfiles, userId);
    Notification::NotificationHelper::RemoveDoNotDisturbProfiles(emptyProfiles);
    Notification::NotificationHelper::RemoveDoNotDisturbProfiles(emptyProfiles, userId);

    Notification::NotificationHelper::AddDoNotDisturbProfiles(profiles);
    Notification::NotificationHelper::AddDoNotDisturbProfiles(profiles, userId);
    Notification::NotificationHelper::RemoveDoNotDisturbProfiles(profiles);
    Notification::NotificationHelper::RemoveDoNotDisturbProfiles(profiles, userId);

    if (!profiles.empty()) {
        std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> oversizedProfiles(
            static_cast<size_t>(Notification::MAX_STATUS_VECTOR_NUM + 1), profiles.front());
        Notification::NotificationHelper::AddDoNotDisturbProfiles(oversizedProfiles);
        Notification::NotificationHelper::AddDoNotDisturbProfiles(oversizedProfiles, userId);
        Notification::NotificationHelper::RemoveDoNotDisturbProfiles(oversizedProfiles);
        Notification::NotificationHelper::RemoveDoNotDisturbProfiles(oversizedProfiles, userId);
    }

    sptr<Notification::NotificationDoNotDisturbProfile> queryProfile =
        new Notification::NotificationDoNotDisturbProfile();
    Notification::NotificationHelper::GetDoNotDisturbProfile(profileId, queryProfile);
    Notification::NotificationHelper::GetDoNotDisturbProfile(profileId, queryProfile, userId);
    Notification::NotificationHelper::GetDoNotDisturbProfile(Notification::INVALID_PROFILE_ID, queryProfile);
    Notification::NotificationHelper::GetDoNotDisturbProfile(
        std::numeric_limits<int64_t>::max(), queryProfile, userId);
    bool doesSupport = false;
    Notification::NotificationHelper::DoesSupportDoNotDisturbMode(doesSupport);
    std::string phoneNumber = fdp->ConsumeRandomLengthString(MAX_TYPE);
    int32_t callerType = fdp->ConsumeIntegral<int32_t>();
    Notification::NotificationHelper::IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    Notification::NotificationHelper::IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType, userId);
}
}

bool test(FuzzedDataProvider *fdp)
{
    int64_t profileId = fdp->ConsumeIntegral<int64_t>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    std::string name = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<Notification::NotificationBundleOption> trustList = BuildTrustList(fdp);

    Notification::NotificationDoNotDisturbProfile profile = BuildProfile(profileId, name, trustList);
    ExerciseParcelPaths(fdp, profile);
    ExerciseJsonPaths(fdp, profile);

    std::vector<sptr<Notification::NotificationDoNotDisturbProfile>> profiles;
    profiles.emplace_back(new Notification::NotificationDoNotDisturbProfile(profileId, name, trustList));
    size_t extraProfiles = fdp->ConsumeIntegralInRange<size_t>(0, 3);
    for (size_t i = 0; i < extraProfiles; ++i) {
        profiles.emplace_back(new Notification::NotificationDoNotDisturbProfile(
            fdp->ConsumeIntegral<int64_t>(), fdp->ConsumeRandomLengthString(MAX_NUM), BuildTrustList(fdp)));
    }
    ExerciseFrameworkPaths(fdp, profileId, userId, profiles);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    MockRandomToken(&fdp, requestPermission);
    OHOS::test(&fdp);
    return 0;
}
