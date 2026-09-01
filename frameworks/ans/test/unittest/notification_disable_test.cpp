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

#include <gtest/gtest.h>

#include "notification_disable.h"

namespace {
constexpr int32_t MAX_NOTIFICATION_DISABLE_NUM = 1000;
}

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationDisableTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetDisabled_0100
 * @tc.desc: Test GetDisabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetDisabled_0100, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    notificationDisable.SetDisabled(true);
    EXPECT_TRUE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: GetDisabled_0200
 * @tc.desc: Test GetDisabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetDisabled_0200, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    notificationDisable.SetDisabled(false);
    EXPECT_FALSE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: GetBundleList_0100
 * @tc.desc: Test GetBundleList.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetBundleList_0100, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::vector<std::string> bundleList = { "com.example.app" };
    notificationDisable.SetBundleList(bundleList);
    ASSERT_EQ(notificationDisable.GetBundleList(), bundleList);
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, Marshalling_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_TRUE(rrc->Marshalling(parcel));
}

/**
 * @tc.name: ReadFromParcel_0100
 * @tc.desc: Test ReadFromParcel with empty parcel (ReadBool fails).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, ReadFromParcel_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_FALSE(rrc->ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0200
 * @tc.desc: Test ReadFromParcel when ReadUint32 fails (only bool written).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, ReadFromParcel_0200, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteBool(false);
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_FALSE(rrc->ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0300
 * @tc.desc: Test ReadFromParcel when ReadString fails in bundle loop.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, ReadFromParcel_0300, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteBool(false);
    parcel.WriteUint32(1);
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_FALSE(rrc->ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0400
 * @tc.desc: Test ReadFromParcel when ReadInt32(userId) fails.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, ReadFromParcel_0400, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteBool(false);
    parcel.WriteUint32(0);
    auto rrc = std::make_shared<NotificationDisable>();
    EXPECT_FALSE(rrc->ReadFromParcel(parcel));
}

/**
 * @tc.name: Unmarshalling_0100
 * @tc.desc: Test Unmarshalling with empty parcel returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, Unmarshalling_0100, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationDisable>();
    ASSERT_NE(nullptr, rrc);
    EXPECT_EQ(nullptr, rrc->Unmarshalling(parcel));
}

/**
 * @tc.name: Marshalling_0200
 * @tc.desc: Test Marshalling_0200.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, Marshalling_0200, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::vector<std::string> bundleList;

    for (auto i = 0; i <= 1000; ++i) {
        bundleList.push_back("123");
    }
    notificationDisable.SetBundleList(bundleList);

    Parcel parcel;
    auto res = notificationDisable.Marshalling(parcel);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: Test Marshalling_0100.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, FromJson_0100, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::vector<std::string> bundleList;

    std::string jsonObjString = "";
    notificationDisable.FromJson(jsonObjString);
    ASSERT_FALSE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: GetUserId_0100
 * @tc.desc: Test GetUserId.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, GetUserId_0100, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    notificationDisable.SetUserId(1);
    EXPECT_EQ(notificationDisable.GetUserId(), 1);
}

/**
 * @tc.name: FromJson_0200
 * @tc.desc: Test FromJson with bundleList containing non-string elements (should skip them).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, FromJson_0200, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::string jsonObjString = R"({"disabled": true, "bundleList": [1, "com.test", true, "com.test2"]})";
    notificationDisable.FromJson(jsonObjString);
    EXPECT_TRUE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: FromJson_0300
 * @tc.desc: Test FromJson with invalid json string.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, FromJson_0300, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::string jsonObjString = "invalid json";
    notificationDisable.FromJson(jsonObjString);
    EXPECT_FALSE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: FromJson_0400
 * @tc.desc: Test FromJson with non-object json (array).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, FromJson_0400, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::string jsonObjString = "[1, 2, 3]";
    notificationDisable.FromJson(jsonObjString);
    EXPECT_FALSE(notificationDisable.GetDisabled());
}

/**
 * @tc.name: FromJson_0500
 * @tc.desc: Test FromJson with bundleList exceeding MAX_NOTIFICATION_DISABLE_NUM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, FromJson_0500, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::string bundleArray = "[";
    for (int32_t i = 0; i <= MAX_NOTIFICATION_DISABLE_NUM; ++i) {
        bundleArray += "\"bundle\",";
    }
    if (!bundleArray.empty()) {
        bundleArray.pop_back();
    }
    bundleArray += "]";
    std::string jsonObjString = "{\"disabled\": true, \"bundleList\": " + bundleArray + "}";
    notificationDisable.FromJson(jsonObjString);
    EXPECT_TRUE(notificationDisable.GetBundleList().empty());
}

/**
 * @tc.name: FromJson_0600
 * @tc.desc: Test FromJson with userId out of int32 range.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationDisableTest, FromJson_0600, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    std::string jsonObjString = "{\"userId\": 2147483648}";
    notificationDisable.FromJson(jsonObjString);
    EXPECT_EQ(notificationDisable.GetUserId(), -1);
}
}
}
