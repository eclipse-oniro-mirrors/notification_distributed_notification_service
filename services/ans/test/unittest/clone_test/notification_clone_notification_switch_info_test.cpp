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
#define private public
#define protected public
#include "notification_clone_notification_switch_info.h"
#undef private
#undef protected

#include "notification_constant.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationCloneNotificationSwitchInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: SetSwitchName_00001
 * @tc.desc: Test SetSwitchName and GetSwitchName.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, SetSwitchName_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    info->SetSwitchName(switchName);
    EXPECT_EQ(info->GetSwitchName(), switchName);
}

/**
 * @tc.name: SetSwitchName_00002
 * @tc.desc: Test SetSwitchName with empty string.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, SetSwitchName_00002, Function | SmallTest | Level1)
{
    std::string switchName = "";
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    info->SetSwitchName(switchName);
    EXPECT_EQ(info->GetSwitchName(), switchName);
}

/**
 * @tc.name: SetSwitchState_00001
 * @tc.desc: Test SetSwitchState and GetSwitchState with all SWITCH_STATE values.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, SetSwitchState_00001, Function | SmallTest | Level1)
{
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();

    // USER_MODIFIED_OFF
    info->SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);

    // USER_MODIFIED_ON
    info->SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    // SYSTEM_DEFAULT_OFF
    info->SetSwitchState(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);

    // SYSTEM_DEFAULT_ON
    info->SetSwitchState(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson with non-empty switchName.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, ToJson_00001, Function | SmallTest | Level1)
{
    std::string switchName = "LOGISTICS";
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    info->SetSwitchName(switchName);
    info->SetSwitchState(switchState);

    nlohmann::json jsonObject;
    info->ToJson(jsonObject);

    EXPECT_TRUE(jsonObject.contains("switchName"));
    EXPECT_EQ(jsonObject["switchName"].get<std::string>(), switchName);
    EXPECT_TRUE(jsonObject.contains("switchState"));
    EXPECT_EQ(jsonObject["switchState"].get<int32_t>(), static_cast<int32_t>(switchState));
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson with empty switchName (switchName should not be written).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, ToJson_00002, Function | SmallTest | Level1)
{
    std::string switchName = "";
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    info->SetSwitchName(switchName);
    info->SetSwitchState(switchState);

    nlohmann::json jsonObject;
    info->ToJson(jsonObject);

    EXPECT_FALSE(jsonObject.contains("switchName"));
    EXPECT_TRUE(jsonObject.contains("switchState"));
    EXPECT_EQ(jsonObject["switchState"].get<int32_t>(), static_cast<int32_t>(switchState));
}

/**
 * @tc.name: FromJson_00001
 * @tc.desc: Test FromJson with null JSON object returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, FromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json nullJson = nullptr;
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    EXPECT_FALSE(info->FromJson(nullJson));
}

/**
 * @tc.name: FromJson_00002
 * @tc.desc: Test FromJson with discarded JSON returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, FromJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json discardedJson = nlohmann::json::parse("[1,2,3]", nullptr, false);
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    EXPECT_FALSE(info->FromJson(discardedJson));
}

/**
 * @tc.name: FromJson_00003
 * @tc.desc: Test FromJson with non-object JSON (array) returns false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, FromJson_00003, Function | SmallTest | Level1)
{
    nlohmann::json arrayJson = nlohmann::json::array({1, 2, 3});
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    EXPECT_FALSE(info->FromJson(arrayJson));
}

/**
 * @tc.name: FromJson_00004
 * @tc.desc: Test FromJson with valid JSON object returns true and parses correctly.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, FromJson_00004, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = {
        {"switchName", "DEAL"},
        {"switchState", 1}
    };
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    EXPECT_TRUE(info->FromJson(jsonObject));
    EXPECT_EQ(info->GetSwitchName(), "DEAL");
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

/**
 * @tc.name: FromJson_00005
 * @tc.desc: Test FromJson with empty JSON object returns true (fields remain default).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, FromJson_00005, Function | SmallTest | Level1)
{
    nlohmann::json emptyObject = nlohmann::json::object();
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    EXPECT_TRUE(info->FromJson(emptyObject));
    // switchName_ default is NotificationConstant::NotificationSwitch::INVALID
    EXPECT_EQ(info->GetSwitchName(), NotificationConstant::NotificationSwitch::INVALID);
    // switchState_ default is SYSTEM_DEFAULT_OFF
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: FromJson_00006
 * @tc.desc: Test FromJson with wrong type values (switchName as number, switchState as string).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, FromJson_00006, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = {
        {"switchName", 123},
        {"switchState", "not_a_number"}
    };
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    EXPECT_TRUE(info->FromJson(jsonObject));
    // switchName is not a string, so it should remain default
    EXPECT_EQ(info->GetSwitchName(), NotificationConstant::NotificationSwitch::INVALID);
    // switchState is not a number, so it should remain default
    EXPECT_EQ(info->GetSwitchState(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: ToJsonFromJsonRoundtrip_00001
 * @tc.desc: Test ToJson and FromJson roundtrip with all SWITCH_STATE values.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, ToJsonFromJsonRoundtrip_00001, Function | SmallTest | Level1)
{
    std::string switchName = "DEAL";

    // Test roundtrip for USER_MODIFIED_OFF
    {
        auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        info->SetSwitchName(switchName);
        info->SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
        nlohmann::json jsonObject;
        info->ToJson(jsonObject);

        auto info2 = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        EXPECT_TRUE(info2->FromJson(jsonObject));
        EXPECT_EQ(info2->GetSwitchName(), switchName);
        EXPECT_EQ(info2->GetSwitchState(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    }

    // Test roundtrip for USER_MODIFIED_ON
    {
        auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        info->SetSwitchName(switchName);
        info->SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        nlohmann::json jsonObject;
        info->ToJson(jsonObject);

        auto info2 = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        EXPECT_TRUE(info2->FromJson(jsonObject));
        EXPECT_EQ(info2->GetSwitchName(), switchName);
        EXPECT_EQ(info2->GetSwitchState(), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    }

    // Test roundtrip for SYSTEM_DEFAULT_OFF
    {
        auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        info->SetSwitchName(switchName);
        info->SetSwitchState(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
        nlohmann::json jsonObject;
        info->ToJson(jsonObject);

        auto info2 = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        EXPECT_TRUE(info2->FromJson(jsonObject));
        EXPECT_EQ(info2->GetSwitchName(), switchName);
        EXPECT_EQ(info2->GetSwitchState(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    }

    // Test roundtrip for SYSTEM_DEFAULT_ON
    {
        auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        info->SetSwitchName(switchName);
        info->SetSwitchState(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
        nlohmann::json jsonObject;
        info->ToJson(jsonObject);

        auto info2 = std::make_shared<NotificationCloneNotificationSwitchInfo>();
        EXPECT_TRUE(info2->FromJson(jsonObject));
        EXPECT_EQ(info2->GetSwitchName(), switchName);
        EXPECT_EQ(info2->GetSwitchState(), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    }
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump method output format.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string switchName = "LOGISTICS";
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    info->SetSwitchName(switchName);
    info->SetSwitchState(switchState);

    std::string dumpStr = info->Dump();
    std::string expected = "NotificationCloneNotificationSwitchInfo{switchName=LOGISTICS, switchState=1}";
    EXPECT_EQ(dumpStr, expected);
}

/**
 * @tc.name: Dump_00002
 * @tc.desc: Test Dump method with default values.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchInfoTest, Dump_00002, Function | SmallTest | Level1)
{
    auto info = std::make_shared<NotificationCloneNotificationSwitchInfo>();
    // Default switchName_ is NotificationConstant::NotificationSwitch::INVALID ("INVALID")
    // Default switchState_ is SYSTEM_DEFAULT_OFF (2)
    std::string dumpStr = info->Dump();
    std::string expected = "NotificationCloneNotificationSwitchInfo{switchName=INVALID, switchState=2}";
    EXPECT_EQ(dumpStr, expected);
}
}  // namespace Notification
}  // namespace OHOS