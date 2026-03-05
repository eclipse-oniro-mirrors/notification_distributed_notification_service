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
#include <memory>
#include <string>
#include "int_wrapper.h"

#define private public
#define protected public
#include "notification_group_info.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationGroupInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetGroupInfo_00001
 * @tc.desc: Test set all info of GroupInfo.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, SetUnifiedGroupInfo_00001, Function | SmallTest | Level1)
{
    NotificationGroupInfo info;
    info.SetIsGroupIcon(true);
    EXPECT_EQ(info.GetIsGroupIcon(), true);

    info.SetGroupTitle("testtitle");
    EXPECT_EQ(info.GetGroupTitle(), "testtitle");

    std::string res = "NotificationGroupInfo{ isGroupIcon = true, groupTitle = testtitle }";
    EXPECT_EQ(info.Dump(), res);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, Marshalling_00001, Function | SmallTest | Level1)
{
    NotificationGroupInfo info;
    info.SetIsGroupIcon(true);
    info.SetGroupTitle("testtitle");

    Parcel parcel;
    EXPECT_EQ(info.Marshalling(parcel), true);
    auto ptr = NotificationGroupInfo::Unmarshalling(parcel);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->GetIsGroupIcon(), true);
    EXPECT_EQ(ptr->GetGroupTitle(), "testtitle");
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(rrc, nullptr);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ReadFromParcel_00002
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, ReadFromParcel_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteBool(true);
    auto rrc = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(rrc, nullptr);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: ReadFromParcel_00003
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, ReadFromParcel_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteBool(true);
    parcel.WriteString("testtitle");
    auto rrc = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(rrc, nullptr);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), true);
    EXPECT_EQ(rrc->GetIsGroupIcon(), true);
    EXPECT_EQ(rrc->GetGroupTitle(), "testtitle");
}

/**
 * @tc.name: JsonConvert_00001
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, JsonConvert_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(rrc, nullptr);
    rrc->SetIsGroupIcon(true);
    rrc->SetGroupTitle("testtitle");
    nlohmann::json jsonObject;
    EXPECT_TRUE(rrc->ToJson(jsonObject));
    auto *rrcNew = rrc->FromJson(jsonObject);
    EXPECT_EQ(rrcNew->GetIsGroupIcon(), rrc->GetIsGroupIcon());
    EXPECT_EQ(rrcNew->GetGroupTitle(), rrc->GetGroupTitle());
}

/**
 * @tc.name: JsonConvert_00002
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, JsonConvert_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["isGroupIcon"] = true;
    auto rrc = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(rrc, nullptr);
    auto *rrcNew = rrc->FromJson(jsonObject);
    EXPECT_EQ(rrcNew->GetIsGroupIcon(), true);
}

/**
 * @tc.name: JsonConvert_00003
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, JsonConvert_00003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["groupTitle"] = "testtitle";
    auto rrc = std::make_shared<NotificationGroupInfo>();
    ASSERT_NE(rrc, nullptr);
    auto *rrcNew = rrc->FromJson(jsonObject);
    EXPECT_EQ(rrcNew->GetGroupTitle(), "testtitle");
}
}
}
