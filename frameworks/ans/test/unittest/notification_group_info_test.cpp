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
#include <memory>
#include <string>
#include "int_wrapper.h"
#include "notification_group_info.h"

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
 * @tc.name: UnMarshalling_00001
 * @tc.desc: Test UnMarshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, UnMarshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto ptr = NotificationGroupInfo::Unmarshalling(parcel);
    EXPECT_EQ(ptr, nullptr);
}

/**
 * @tc.name: UnMarshalling_00002
 * @tc.desc: Test UnMarshalling.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, UnMarshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteBool(true);
    auto ptr = NotificationGroupInfo::Unmarshalling(parcel);
    EXPECT_EQ(ptr, nullptr);
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
    rrc->SetIsGroupIcon(true);
    rrc->SetGroupTitle("testtitle");
    nlohmann::json jsonObject;
    EXPECT_TRUE(rrc->ToJson(jsonObject));
    auto *rrcNew = NotificationGroupInfo::FromJson(jsonObject);
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
    auto *rrcNew = NotificationGroupInfo::FromJson(jsonObject);
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
    auto *rrcNew = NotificationGroupInfo::FromJson(jsonObject);
    EXPECT_EQ(rrcNew->GetGroupTitle(), "testtitle");
}

/**
 * @tc.name: JsonConvert_00004
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, JsonConvert_00004, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nullptr;
    auto result = NotificationGroupInfo::FromJson(jsonObject);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: JsonConvert_00005
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationGroupInfoTest, JsonConvert_00005, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = "invalid";
    auto result = NotificationGroupInfo::FromJson(jsonObject);
    EXPECT_EQ(result, nullptr);
}

}
}
