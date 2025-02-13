/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include "notification_button_option.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationButtonOptionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetButtonName_00001
 * @tc.desc: Test buttonName_ parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationButtonOptionTest, SetButtonName_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationButtonOption>();
    std::string buttonName = "testbuttonName";
    rrc->SetButtonName(buttonName);
    EXPECT_EQ(rrc->GetButtonName(), buttonName);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test buttonNames_ dump.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationButtonOptionTest, Dump_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationButtonOption>();
    std::string buttonName = "testbuttonName";
    rrc->SetButtonName(buttonName);
    EXPECT_EQ(rrc->Dump(), "NotificationButtonOption{ "
        "buttonName = " + buttonName +" }");
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationButtonOptionTest, FromJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationButtonOption>();
    nlohmann::json jsonObject = nlohmann::json{"buttonName"};
    EXPECT_EQ(jsonObject.is_object(), false);
    EXPECT_EQ(rrc->FromJson(jsonObject), nullptr);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationButtonOptionTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    auto rrc = std::make_shared<NotificationButtonOption>();
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationButtonOptionTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationButtonOption> result =
        std::make_shared<NotificationButtonOption>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationButtonOptionTest, ToJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationButtonOption>();
    std::string buttonName = "testbuttonName";
    rrc->SetButtonName(buttonName);
    nlohmann::json jsonObject;
    jsonObject["buttonName"] = "testButtonName";
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_EQ(rrc->ToJson(jsonObject), true);
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationButtonOptionTest, FromJson_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<NotificationButtonOption>();
    nlohmann::json jsonObject;
    jsonObject["buttonName"] = "testButtonName";
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_NE(rrc->FromJson(jsonObject), nullptr);
}
}
}
