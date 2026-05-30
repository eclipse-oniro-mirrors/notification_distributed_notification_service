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
#include "gmock/gmock.h"

#define private public
#define protected public
#include "notification_clone_notification_switch.h"
#include "notification_clone_notification_switch_info.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "mock_notification_clone_util.h"
#include "ans_inner_errors.h"
#include "notification_constant.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace Notification {
class NotificationCloneNotificationSwitchTest : public ::testing::Test {
protected:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        int32_t initTestUserId = 100;
        MockSetActiveUserIdForClone(initTestUserId);
        SetFuncGetActiveUserIdIsCalled(false);
    }
    void TearDown() override {}
};

/**
 * @tc.name: OnBackup_00001
 * @tc.desc: Test OnBackup when GetActiveUserId returns invalid userId.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnBackup_00001, Function | SmallTest | Level1)
{
    // Given: Set GetActiveUserId to return invalid userId
    MockSetActiveUserIdForClone(-1);
    nlohmann::json jsonObject;

    // When: Call OnBackup
    ErrCode result = NotificationCloneNotificationSwitch::GetInstance()->OnBackup(jsonObject);

    // Then: Should return ERR_ANS_INVALID_PARAM
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: OnBackup_00002
 * @tc.desc: Test OnBackup with valid userId and no switch data.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnBackup_00002, Function | SmallTest | Level1)
{
    // Given: Set valid userId
    MockSetActiveUserIdForClone(100);
    nlohmann::json jsonObject;

    // When: Call OnBackup
    ErrCode result = NotificationCloneNotificationSwitch::GetInstance()->OnBackup(jsonObject);

    // Then: Should return ERR_OK and contain notificationSwitch key
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(jsonObject.contains("notificationSwitch"));
}

/**
 * @tc.name: OnRestore_00001
 * @tc.desc: Test OnRestore with null JSON object.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestore_00001, Function | SmallTest | Level1)
{
    // Given: Null JSON object
    nlohmann::json jsonNull;
    std::set<std::string> systemApps;

    // When: Call OnRestore with null JSON
    SetFuncGetActiveUserIdIsCalled(false);
    NotificationCloneNotificationSwitch::GetInstance()->OnRestore(jsonNull, systemApps);

    // Then: Should skip restore, GetActiveUserId should not be called for null JSON
    EXPECT_FALSE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_00002
 * @tc.desc: Test OnRestore with JSON object that does not contain notificationSwitch key.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestore_00002, Function | SmallTest | Level1)
{
    // Given: JSON object without notificationSwitch key
    nlohmann::json jsonObject = nlohmann::json::object();
    jsonObject["otherKey"] = "otherValue";
    std::set<std::string> systemApps;

    // When: Call OnRestore
    SetFuncGetActiveUserIdIsCalled(false);
    NotificationCloneNotificationSwitch::GetInstance()->OnRestore(jsonObject, systemApps);

    // Then: Should skip restore, GetActiveUserId should not be called
    EXPECT_FALSE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_00003
 * @tc.desc: Test OnRestore with valid JSON containing notificationSwitch data.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestore_00003, Function | SmallTest | Level1)
{
    // Given: Valid JSON with notificationSwitch data
    MockSetActiveUserIdForClone(100);
    nlohmann::json jsonObject = nlohmann::json::object();
    nlohmann::json switchArray = nlohmann::json::array();

    NotificationCloneNotificationSwitchInfo info;
    info.SetSwitchName(NotificationConstant::NotificationSwitch::DEAL);
    info.SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    nlohmann::json infoJson;
    info.ToJson(infoJson);
    switchArray.push_back(infoJson);

    NotificationCloneNotificationSwitchInfo info2;
    info2.SetSwitchName(NotificationConstant::NotificationSwitch::LOGISTICS);
    info2.SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    nlohmann::json infoJson2;
    info2.ToJson(infoJson2);
    switchArray.push_back(infoJson2);

    jsonObject["notificationSwitch"] = switchArray;
    std::set<std::string> systemApps;

    // When: Call OnRestore
    NotificationCloneNotificationSwitch::GetInstance()->OnRestore(jsonObject, systemApps);

    // Then: GetActiveUserId should be called during RestoreNotificationSwitch
    EXPECT_TRUE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_00004
 * @tc.desc: Test OnRestore with invalid userId (negative) in RestoreNotificationSwitch.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestore_00004, Function | SmallTest | Level1)
{
    // Given: Valid JSON with notificationSwitch data but invalid userId
    MockSetActiveUserIdForClone(-1);
    nlohmann::json jsonObject = nlohmann::json::object();
    nlohmann::json switchArray = nlohmann::json::array();

    NotificationCloneNotificationSwitchInfo info;
    info.SetSwitchName(NotificationConstant::NotificationSwitch::DEAL);
    info.SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    nlohmann::json infoJson;
    info.ToJson(infoJson);
    switchArray.push_back(infoJson);

    jsonObject["notificationSwitch"] = switchArray;
    std::set<std::string> systemApps;

    // When: Call OnRestore with invalid userId
    NotificationCloneNotificationSwitch::GetInstance()->OnRestore(jsonObject, systemApps);

    // Then: RestoreNotificationSwitch should fail due to invalid userId, but OnRestore itself completes
    EXPECT_TRUE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_00005
 * @tc.desc: Test OnRestore with JSON where notificationSwitch is not an array.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestore_00005, Function | SmallTest | Level1)
{
    // Given: JSON where notificationSwitch is a string (not array)
    nlohmann::json jsonObject = nlohmann::json::object();
    jsonObject["notificationSwitch"] = "invalidData";
    std::set<std::string> systemApps;

    // When: Call OnRestore
    SetFuncGetActiveUserIdIsCalled(false);
    NotificationCloneNotificationSwitch::GetInstance()->OnRestore(jsonObject, systemApps);

    // Then: Should skip restore because notificationSwitch is not an array
    EXPECT_FALSE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_00006
 * @tc.desc: Test OnRestore with null items in the notificationSwitch array.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestore_00006, Function | SmallTest | Level1)
{
    // Given: JSON with null items in notificationSwitch array
    MockSetActiveUserIdForClone(100);
    nlohmann::json jsonObject = nlohmann::json::object();
    nlohmann::json switchArray = nlohmann::json::array();
    switchArray.push_back(nlohmann::json());  // null item

    NotificationCloneNotificationSwitchInfo info;
    info.SetSwitchName(NotificationConstant::NotificationSwitch::DEAL);
    info.SetSwitchState(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    nlohmann::json infoJson;
    info.ToJson(infoJson);
    switchArray.push_back(infoJson);

    jsonObject["notificationSwitch"] = switchArray;
    std::set<std::string> systemApps;

    // When: Call OnRestore
    NotificationCloneNotificationSwitch::GetInstance()->OnRestore(jsonObject, systemApps);

    // Then: Null items should be skipped, valid items should be processed
    EXPECT_TRUE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestoreStart_00001
 * @tc.desc: Test OnRestoreStart - aggregation switches are user-level settings, not application-level.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestoreStart_00001, Function | SmallTest | Level1)
{
    // Given: Bundle name, appIndex, userId, and uid
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;

    // When: Call OnRestoreStart
    NotificationCloneNotificationSwitch::GetInstance()->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Then: OnRestoreStart has empty implementation for aggregation switches
    // No state change expected, function completes without error
}

/**
 * @tc.name: OnRestoreEnd_00001
 * @tc.desc: Test OnRestoreEnd with valid userId.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnRestoreEnd_00001, Function | SmallTest | Level1)
{
    // Given: Valid userId
    int32_t userId = 100;

    // When: Call OnRestoreEnd
    NotificationCloneNotificationSwitch::GetInstance()->OnRestoreEnd(userId);

    // Then: OnRestoreEnd completes without error (empty implementation)
}

/**
 * @tc.name: OnUserSwitch_00001
 * @tc.desc: Test OnUserSwitch with valid userId.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneNotificationSwitchTest, OnUserSwitch_00001, Function | SmallTest | Level1)
{
    // Given: Valid userId
    int32_t userId = 100;

    // When: Call OnUserSwitch
    NotificationCloneNotificationSwitch::GetInstance()->OnUserSwitch(userId);

    // Then: OnUserSwitch has empty implementation for aggregation switches
    // No state change expected, function completes without error
}
}
}