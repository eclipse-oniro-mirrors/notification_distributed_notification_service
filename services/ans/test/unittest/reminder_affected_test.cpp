/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "gtest/gtest.h"

#define private public
#define protected public
#include "reminder_affected.h"
#include "string_utils.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderAffectedTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Test FromJson
 * @tc.desc: Test FromJson
 * @tc.type: FUNC
 */
HWTEST_F(ReminderAffectedTest, FromJson_00001, Function | SmallTest | Level1)
{
    ReminderAffected reminderAffected;
    nlohmann::json jsonObject = nlohmann::json{
        "test", "test"
    };
    auto res = reminderAffected.FromJson(jsonObject);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: Test ValidAndGetAffectedBy
 * @tc.desc: Test ValidAndGetAffectedBy
 * @tc.type: FUNC
 */
HWTEST_F(ReminderAffectedTest, ValidAndGetAffectedBy_00001, Function | SmallTest | Level1)
{
    ReminderAffected reminderAffected;
    nlohmann::json jsonObject = nlohmann::json{
        ReminderAffected::AFFECTED_BY, "test"
    };

    std::vector<std::pair<std::string, std::string>> affectedBy;
    auto res = reminderAffected.ValidAndGetAffectedBy(jsonObject, affectedBy);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: Test ValidAndGetAffectedBy
 * @tc.desc: Test ValidAndGetAffectedBy
 * @tc.type: FUNC
 */
HWTEST_F(ReminderAffectedTest, ValidAndGetAffectedBy_00002, Function | SmallTest | Level1)
{
    ReminderAffected reminderAffected;
    nlohmann::json jsonObject = nlohmann::json{
        ReminderAffected::AFFECTED_BY, {{"test", "test"}, {ReminderAffected::DEVICE_TYPE, ""}}
    };
    std::vector<std::pair<std::string, std::string>> affectedBy;
    auto res = reminderAffected.ValidAndGetAffectedBy(jsonObject, affectedBy);
    ASSERT_FALSE(res);

    jsonObject = nlohmann::json{
        ReminderAffected::AFFECTED_BY, {}
    };
    res = reminderAffected.ValidAndGetAffectedBy(jsonObject, affectedBy);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: Test ValidStatus
 * @tc.desc: Test ValidStatus
 * @tc.type: FUNC
 */
HWTEST_F(ReminderAffectedTest, ValidStatus_00001, Function | SmallTest | Level1)
{
    ReminderAffected reminderAffected;
    nlohmann::json jsonObject = nlohmann::json{
        {ReminderAffected::DEVICE_TYPE, "test"}, {ReminderAffected::STATUS, 1}
    };

    std::string status = "test1";
    auto res = reminderAffected.ValidStatus(jsonObject, status);
    ASSERT_FALSE(res);
    ASSERT_EQ(status, "test1");

    jsonObject = nlohmann::json{
        {ReminderAffected::DEVICE_TYPE, "test"}, {ReminderAffected::STATUS, ""}
    };
    res = reminderAffected.ValidStatus(jsonObject, status);
    ASSERT_TRUE(res);
    ASSERT_EQ(status, "test1");

    jsonObject = nlohmann::json{
        {ReminderAffected::DEVICE_TYPE, "test"}, {ReminderAffected::STATUS, "123"}
    };
    res = reminderAffected.ValidStatus(jsonObject, status);
    ASSERT_FALSE(res);
    ASSERT_EQ(status, "test1");

    jsonObject = nlohmann::json{
        {ReminderAffected::DEVICE_TYPE, "test"}, {ReminderAffected::STATUS, "xxx1"}
    };
    res = reminderAffected.ValidStatus(jsonObject, status);
    ASSERT_TRUE(res);
    ASSERT_EQ(status, "xxx1");
}

/**
 * @tc.name: Test StringUtils
 * @tc.desc: Test StringUtils
 * @tc.type: FUNC
 */
HWTEST_F(ReminderAffectedTest, StringUtils_00001, Function | SmallTest | Level1)
{
    const std::string str = "test, test";
    const std::string splitFlag = ",";
    std::vector<std::string> res;

    StringUtils::Split("", splitFlag, res);
    ASSERT_EQ(res.size(), 0);

    StringUtils::Split(str, splitFlag, res);
    ASSERT_EQ(res.size(), 2);
}
}  // namespace Notification
}  // namespace OHOS
#endif