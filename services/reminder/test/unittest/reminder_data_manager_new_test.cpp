/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "reminder_data_manager.h"

#include "mock_reminder_datashare_helper.h"

using namespace testing::ext;
using namespace OHOS::EventFwk;
namespace OHOS::Notification {
class ReminderDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderDataManager::InitInstance();
        manager = ReminderDataManager::GetInstance();
    }
    static void TearDownTestCase()
    {
        manager = nullptr;
    }
    void SetUp() {};
    void TearDown() {};

public:
    static std::shared_ptr<ReminderDataManager> manager;
};

std::shared_ptr<ReminderDataManager> ReminderDataManagerTest::manager = nullptr;

/**
 * @tc.name: IsInDoNotDisturbMode_001
 * @tc.desc: Test IsInDoNotDisturbMode
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, IsInDoNotDisturbMode_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({false}, {""}, {reminders});
    bool ret = manager->IsInDoNotDisturbMode(100, 1001, "com.test.app");
    EXPECT_EQ(ret, true);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true}, {"0"}, {reminders});
    ret = manager->IsInDoNotDisturbMode(100, 1001, "com.test.app");
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true, true},
        {"1", R"([{"bundle":"com.test.app","uid":2002}])"},
        {reminders});
    ret = manager->IsInDoNotDisturbMode(100, 1001, "com.test.app");
    EXPECT_EQ(ret, true);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true, true},
        {"1", R"([{"bundle":"com.test.app1","uid":1001}])"},
        {reminders});
    ret = manager->IsInDoNotDisturbMode(100, 1001, "com.test.app");
    EXPECT_EQ(ret, true);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true, true},
        {"1", R"([{"bundle":"com.test.app","uid":1001}])"},
        {reminders});
    ret = manager->IsInDoNotDisturbMode(100, 1001, "com.test.app");
    EXPECT_EQ(ret, false);
#endif
}

/**
 * @tc.name: CheckSoundConfig_001
 * @tc.desc: Test CheckSoundConfig
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, CheckSoundConfig_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    int32_t flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    bool ret = manager->CheckSoundConfig(true, flag, 0, false);
    EXPECT_EQ(ret, false);
    ret = manager->CheckSoundConfig(false, flag, 0, false);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    ret = manager->CheckSoundConfig(false, flag, 0, false);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    ret = manager->CheckSoundConfig(false, flag, 0, false);
    EXPECT_EQ(ret, false);
    ret = manager->CheckSoundConfig(false, flag, 1, false);
    EXPECT_EQ(ret, true);
    ret = manager->CheckSoundConfig(false, flag, 1, true);
    EXPECT_EQ(ret, false);
#endif
}

/**
 * @tc.name: GetSettingsData_001
 * @tc.desc: Test GetSettingsData
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, GetSettingsData_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({false}, {""}, {reminders});
    bool ret = manager->GetSettingsData(100);
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true}, {"0"}, {reminders});
    ret = manager->GetSettingsData(100);
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true}, {"1"}, {reminders});
    ret = manager->GetSettingsData(100);
    EXPECT_EQ(ret, true);
#endif
}

/**
 * @tc.name: CheckVibrationConfig_001
 * @tc.desc: Test CheckVibrationConfig
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, CheckVibrationConfig_001, Level1)
{
#ifdef PLAYER_FRAMEWORK_ENABLE
    int32_t flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    bool ret = manager->CheckVibrationConfig(100, true, flag, 0, false);
    EXPECT_EQ(ret, false);
    ret = manager->CheckVibrationConfig(100, false, flag, 0, false);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    ret = manager->CheckVibrationConfig(100, false, flag, 0, false);
    EXPECT_EQ(ret, false);
    flag = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true}, {"0"}, {reminders});
    ret = manager->CheckVibrationConfig(100, false, flag, 0, false);
    EXPECT_EQ(ret, false);
    MockReminderDatashareHelper::Reset();
    MockReminderDatashareHelper::MockQuery({true}, {"1"}, {reminders});
    auto client = std::move(manager->systemSoundClient_);
    ret = manager->CheckVibrationConfig(100, false, flag, 0, false);
    EXPECT_EQ(ret, false);
    manager->systemSoundClient_ = std::move(client);
    ret = manager->CheckVibrationConfig(100, false, flag, 0, true);
    EXPECT_EQ(ret, false);
#endif
}

/**
 * @tc.name: GenDstBundleName_001
 * @tc.desc: Test GenDstBundleName branch coverage
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, GenDstBundleName_001, Level1)
{
    std::string dstBundleName;
    // branch: while loop skips (right - left > 1), right != npos
    manager->GenDstBundleName(dstBundleName, "prefix/bundleName/suffix");
    EXPECT_EQ(dstBundleName, "/bundleName");

    // branch: while loop once (scheme://), right == npos
    dstBundleName.clear();
    manager->GenDstBundleName(dstBundleName, "datashareTest://com.acts.dataShareTest");
    EXPECT_EQ(dstBundleName, "com.acts.dataShareTest");

    // branch: while loop once, right != npos
    dstBundleName.clear();
    manager->GenDstBundleName(dstBundleName, "datashareTest://com.example.app/db/table");
    EXPECT_EQ(dstBundleName, "com.example.app");

    // branch: while loop multiple times (consecutive slashes)
    dstBundleName.clear();
    manager->GenDstBundleName(dstBundleName, "a///b");
    EXPECT_EQ(dstBundleName, "b");

    // branch: while loop once, trailing slash
    dstBundleName.clear();
    manager->GenDstBundleName(dstBundleName, "scheme://bundle/");
    EXPECT_EQ(dstBundleName, "bundle");
}

/**
 * @tc.name: ParseWhiteListAndMatch_001
 * @tc.desc: Test ParseWhiteListAndMatch when listInfo is not a valid JSON string
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_001, Level1)
{
    std::string invalidJson = "not a json string";
    bool result = manager->ParseWhiteListAndMatch(invalidJson, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_002
 * @tc.desc: Test ParseWhiteListAndMatch when JSON parse fails (discarded)
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_002, Level1)
{
    std::string malformedJson = "{invalid: json}";
    bool result = manager->ParseWhiteListAndMatch(malformedJson, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_003
 * @tc.desc: Test ParseWhiteListAndMatch when JSON root is not an array (object)
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_003, Level1)
{
    std::string jsonObject = R"({"bundle": "com.test.app", "uid": 1001})";
    bool result = manager->ParseWhiteListAndMatch(jsonObject, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_004
 * @tc.desc: Test ParseWhiteListAndMatch when array element is not an object
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_004, Level1)
{
    std::string jsonArray = R"([123, "string", null])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_005
 * @tc.desc: Test ParseWhiteListAndMatch when array element lacks bundle field
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_005, Level1)
{
    std::string jsonArray = R"([{"uid": 1001}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_006
 * @tc.desc: Test ParseWhiteListAndMatch when bundle field is not a string
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_006, Level1)
{
    std::string jsonArray = R"([{"bundle": 123, "uid": 1001}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_007
 * @tc.desc: Test ParseWhiteListAndMatch when array element lacks uid field
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_007, Level1)
{
    std::string jsonArray = R"([{"bundle": "com.test.app"}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_008
 * @tc.desc: Test ParseWhiteListAndMatch when uid field is not a number
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_008, Level1)
{
    std::string jsonArray = R"([{"bundle": "com.test.app", "uid": "not_a_number"}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_009
 * @tc.desc: Test ParseWhiteListAndMatch when bundle and uid both match
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_009, Level1)
{
    std::string jsonArray = R"([{"bundle": "com.test.app", "uid": 1001}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_010
 * @tc.desc: Test ParseWhiteListAndMatch when bundle matches but uid does not
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_010, Level1)
{
    std::string jsonArray = R"([{"bundle": "com.test.app", "uid": 2002}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_011
 * @tc.desc: Test ParseWhiteListAndMatch when uid matches but bundle does not
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_011, Level1)
{
    std::string jsonArray = R"([{"bundle": "com.other.app", "uid": 1001}])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_012
 * @tc.desc: Test ParseWhiteListAndMatch with empty array
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_012, Level1)
{
    std::string jsonArray = R"([])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_013
 * @tc.desc: Test ParseWhiteListAndMatch with multiple elements, first invalid, second matches
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_013, Level1)
{
    std::string jsonArray = R"([
        {"uid": 1001},
        {"bundle": "com.test.app", "uid": 1001}
    ])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_014
 * @tc.desc: Test ParseWhiteListAndMatch with multiple elements, none match
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_014, Level1)
{
    std::string jsonArray = R"([
        {"bundle": "com.app1", "uid": 1001},
        {"bundle": "com.app2", "uid": 1002},
        {"bundle": "com.test.app", "uid": 2002}
    ])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: ParseWhiteListAndMatch_015
 * @tc.desc: Test ParseWhiteListAndMatch with multiple valid elements, match in the middle
 * @tc.type: FUNC
 * @tc.require: issue#I9IIDE
 */
HWTEST_F(ReminderDataManagerTest, ParseWhiteListAndMatch_015, Level1)
{
    std::string jsonArray = R"([
        {"bundle": "com.app1", "uid": 1001},
        {"bundle": "com.test.app", "uid": 1001},
        {"bundle": "com.app2", "uid": 1002}
    ])";
    bool result = manager->ParseWhiteListAndMatch(jsonArray, 1001, "com.test.app");
    EXPECT_TRUE(result);
}
}  // namespace OHOS::Notification
