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

#define private public
#define protected public
#include "notification_multiline_content.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationMultiLineContentTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetExpandedTitle_00001
 * @tc.desc: Test SetExpandedTitle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, SetExpandedTitle_00001, Function | SmallTest | Level1)
{
    std::string exTitle = "ExTitle";
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    rrc->SetExpandedTitle(exTitle);
    EXPECT_EQ(rrc->GetExpandedTitle(), exTitle);
}

/**
 * @tc.name: SetBriefText_00001
 * @tc.desc: Test SetBriefText parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, SetBriefText_00001, Function | SmallTest | Level1)
{
    std::string briefText = "BriefText";
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    rrc->SetBriefText(briefText);
    EXPECT_EQ(rrc->GetBriefText(), briefText);
}

/**
 * @tc.name: AddSingleLine_00001
 * @tc.desc: Test AddSingleLine parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, AddSingleLine_00001, Function | SmallTest | Level1)
{
    std::string oneLine = "OneLine";
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    rrc->AddSingleLine(oneLine);
    std::vector<std::string> result = rrc->GetAllLines();
    EXPECT_EQ(result.size(), 1);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    std::string ret = "NotificationMultiLineContent{ title = , text = , "
    "additionalText = , lockScreenPicture = null, structuredText = null, "
    "briefText = , expandedTitle = , allLines = [] }";
    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationMultiLineContentTest, ToJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationMultiLineContentTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationMultiLineContent> result =
    std::make_shared<NotificationMultiLineContent>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: AddSingleLine_00002
 * @tc.desc: Test AddSingleLine parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationMultiLineContentTest, AddSingleLine_00002, Function | SmallTest | Level1)
{
    std::string oneLine = "OneLine";
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    int max = 7;
    for (int i = 0; i < max; i++) {
        rrc->AddSingleLine(oneLine);
    }
    std::vector<std::string> result = rrc->GetAllLines();
    EXPECT_EQ(result.size(), max);
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationMultiLineContentTest, FromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"expandedTitle", "test"},
        {"briefText", "test"},
        {"allLines", {"a", "b", "c"}}};
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    auto res = rrc->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationMultiLineContentTest, FromJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"briefText", "test"},
        {"allLines", {"a", "b", "c"}}};
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    auto res = rrc->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationMultiLineContentTest, FromJson_00003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"expandedTitle", "test"},
        {"allLines", {"a", "b", "c"}}};
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    auto res = rrc->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationMultiLineContentTest, FromJson_00004, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"expandedTitle", "test"},
        {"briefText", "test"}};
    auto rrc = std::make_shared<NotificationMultiLineContent>();
    auto res = rrc->FromJson(jsonObject);
    EXPECT_NE(res, nullptr);
}
}
}