/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <string>

#define private public
#define protected public
#include "badge_number_callback_data.h"
#undef private
#undef protected
#include "parcel.h"
#include "string_ex.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class BadgeNumberCallbackDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: Test Marshalling round-trip success.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, Marshalling_0100, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data("com.test.bundle", "appInstanceKey", 100, 5, 1);
    Parcel parcel;
    EXPECT_TRUE(data.Marshalling(parcel));
    parcel.RewindRead(0);

    auto *result = BadgeNumberCallbackData::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetBundle(), "com.test.bundle");
    EXPECT_EQ(result->GetAppInstanceKey(), "appInstanceKey");
    EXPECT_EQ(result->GetUid(), 100);
    EXPECT_EQ(result->GetBadgeNumber(), 5);
    EXPECT_EQ(result->GetInstanceKey(), 1);
    delete result;
}

/**
 * @tc.name: ReadFromParcel_0100
 * @tc.desc: Test ReadFromParcel when ReadString16 fails (empty parcel).
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, ReadFromParcel_0100, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data;
    Parcel parcel;
    EXPECT_FALSE(data.ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0200
 * @tc.desc: Test ReadFromParcel when ReadString(appInstanceKey) fails.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, ReadFromParcel_0200, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("com.test.bundle"));
    parcel.RewindRead(0);
    EXPECT_FALSE(data.ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0300
 * @tc.desc: Test ReadFromParcel when ReadInt32(uid) fails.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, ReadFromParcel_0300, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("com.test.bundle"));
    parcel.WriteString("appInstanceKey");
    parcel.RewindRead(0);
    EXPECT_FALSE(data.ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0400
 * @tc.desc: Test ReadFromParcel when ReadInt32(badgeNumber) fails.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, ReadFromParcel_0400, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("com.test.bundle"));
    parcel.WriteString("appInstanceKey");
    parcel.WriteInt32(100);
    parcel.RewindRead(0);
    EXPECT_FALSE(data.ReadFromParcel(parcel));
}

/**
 * @tc.name: ReadFromParcel_0500
 * @tc.desc: Test ReadFromParcel when ReadInt32(instanceKey) fails.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, ReadFromParcel_0500, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("com.test.bundle"));
    parcel.WriteString("appInstanceKey");
    parcel.WriteInt32(100);
    parcel.WriteInt32(5);
    parcel.RewindRead(0);
    EXPECT_FALSE(data.ReadFromParcel(parcel));
}

/**
 * @tc.name: GetSet_0100
 * @tc.desc: Test getters and setters.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, GetSet_0100, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data;
    data.SetBundle("com.test");
    data.SetUid(200);
    data.SetBadgeNumber(10);
    data.SetInstanceKey(3);
    data.SetAppInstanceKey("key");
    EXPECT_EQ(data.GetBundle(), "com.test");
    EXPECT_EQ(data.GetUid(), 200);
    EXPECT_EQ(data.GetBadgeNumber(), 10);
    EXPECT_EQ(data.GetInstanceKey(), 3);
    EXPECT_EQ(data.GetAppInstanceKey(), "key");
}

/**
 * @tc.name: Dump_0100
 * @tc.desc: Test Dump output.
 * @tc.type: FUNC
 */
HWTEST_F(BadgeNumberCallbackDataTest, Dump_0100, Function | SmallTest | Level1)
{
    BadgeNumberCallbackData data("com.test", "key1", 100, 5, 1);
    std::string dump = data.Dump();
    EXPECT_NE(dump.find("com.test"), std::string::npos);
    EXPECT_NE(dump.find("100"), std::string::npos);
}
}
}
