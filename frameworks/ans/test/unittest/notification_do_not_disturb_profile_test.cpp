/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "ans_log_wrapper.h"

#define private public
#define protected public
#include "notification_do_not_disturb_profile.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationDoNotDisturbProfileTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetProfileId_0100
 * @tc.desc: test SetProfileId parameters.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, SetProfileId_0100, TestSize.Level1)
{
    int32_t id = 1;
    std::string name = "name";
    std::vector<NotificationBundleOption> trustlist;
    NotificationBundleOption bundleOption;
    trustlist.emplace_back(bundleOption);
    auto rrc = std::make_shared<NotificationDoNotDisturbProfile>(id, name, trustlist);
    rrc->SetProfileId(2);
    EXPECT_EQ(rrc->GetProfileId(), 2);
}

/**
 * @tc.name: SetProfileName_0100
 * @tc.desc: test SetProfileName parameters.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, SetProfileName_0100, TestSize.Level1)
{
    int32_t id = 1;
    std::string name = "name";
    std::vector<NotificationBundleOption> trustlist;
    NotificationBundleOption bundleOption;
    trustlist.emplace_back(bundleOption);
    auto rrc = std::make_shared<NotificationDoNotDisturbProfile>(id, name, trustlist);
    rrc->SetProfileName("newName");
    EXPECT_EQ(rrc->GetProfileName(), "newName");
}

/**
 * @tc.name: SetProfileTrustList_0100
 * @tc.desc: test SetProfileTrustList parameters.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, SetProfileTrustList_0100, TestSize.Level1)
{
    int32_t id = 1;
    std::string name = "name";
    std::vector<NotificationBundleOption> trustlist;
    NotificationBundleOption bundleOption;
    trustlist.emplace_back(bundleOption);
    auto rrc = std::make_shared<NotificationDoNotDisturbProfile>(id, name, trustlist);
    std::vector<NotificationBundleOption> myTrustlist;
    bundleOption.SetBundleName("bundleName");
    bundleOption.SetUid(1);
    myTrustlist.emplace_back(bundleOption);
    rrc->SetProfileTrustList(myTrustlist);
    auto getTrust = rrc->GetProfileTrustList();
    EXPECT_EQ(getTrust[0].GetUid(), myTrustlist[0].GetUid());
    EXPECT_EQ(getTrust[0].GetBundleName(), myTrustlist[0].GetBundleName());
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: test Marshalling when it can run to end.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, Marshalling_0100, TestSize.Level1)
{
    int32_t id = 1;
    std::string name = "name";
    std::vector<NotificationBundleOption> trustlist;
    NotificationBundleOption bundleOption;
    trustlist.emplace_back(bundleOption);
    auto rrc = std::make_shared<NotificationDoNotDisturbProfile>(id, name, trustlist);
    Parcel parcel;
    auto res = rrc->Marshalling(parcel);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: ReadFromParcel_0200
 * @tc.desc: test it when trustlist_ emplace success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, ReadFromParcel_0200, TestSize.Level1)
{
    int32_t id = 1;
    std::string name = "name";
    std::vector<NotificationBundleOption> trustlist;
    NotificationBundleOption bundleOption;
    trustlist.emplace_back(bundleOption);
    auto rrc = std::make_shared<NotificationDoNotDisturbProfile>(id, name, trustlist);

    Parcel parcel;
    parcel.WriteUint32(10);
    sptr<NotificationBundleOption> notification = new (std::nothrow) NotificationBundleOption();
    parcel.WriteParcelable(notification);
    auto res = rrc->ReadFromParcel(parcel);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Unmarshalling_0100
 * @tc.desc: test it when Unmarshalling success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, Unmarshalling_0100, TestSize.Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    int32_t id = 1;
    std::string name = "name";
    std::vector<NotificationBundleOption> trustlist;
    NotificationBundleOption bundleOption;
    trustlist.emplace_back(bundleOption);
    std::shared_ptr<NotificationDoNotDisturbProfile> result =
        std::make_shared<NotificationDoNotDisturbProfile>(id, name, trustlist);
    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ReadFromParcel_0300
 * @tc.desc: test it when Unmarshalling success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, ReadFromParcel_0300, TestSize.Level1)
{
    NotificationDoNotDisturbProfile notificationDoNotDisturbProfile;
    Parcel parcel;
    parcel.WriteInt64(1);
    parcel.WriteString("1");
    parcel.WriteUint32(1);

    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption());
    parcel.WriteParcelable(bundleOption);
    auto res = notificationDoNotDisturbProfile.ReadFromParcel(parcel);
    ASSERT_TRUE(res);
    ASSERT_EQ(notificationDoNotDisturbProfile.GetProfileTrustList().size(), 1);
}

/**
 * @tc.name: FromJson_0100
 * @tc.desc: test it when Unmarshalling success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDoNotDisturbProfileTest, FromJson_0100, TestSize.Level1)
{
    NotificationDoNotDisturbProfile notificationDoNotDisturbProfile;
    std::vector<NotificationBundleOption> trustList;
    NotificationBundleOption notificationBundleOption;
    trustList.push_back(notificationBundleOption);
    notificationDoNotDisturbProfile.SetProfileTrustList(trustList);

    auto jsonString = notificationDoNotDisturbProfile.ToJson();

    NotificationDoNotDisturbProfile temp;
    temp.FromJson(jsonString);

    ASSERT_EQ(temp.GetProfileTrustList().size(), 1);
}
}  // namespace Notification
}  // namespace OHOS
