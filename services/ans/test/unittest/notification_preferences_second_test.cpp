/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ans_inner_errors.h"
#define private public
#define protected public
#include "notification_preferences.h"
#include "notification_preferences_database.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesTest : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase() {}
    void SetUp(){};
    void TearDown(){};
};

/**
 * @tc.name: SetDistributedDevicelist_0100
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedDevicelist_0100, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    std::vector<std::string> deviceTypes;
    int32_t userId = 100;
    auto ret = notificationPreferences.SetDistributedDevicelist(deviceTypes, userId);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetDistributedDevicelist_0200
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetDistributedDevicelist_0200, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    std::vector<std::string> deviceTypes;
    int32_t userId = 100;
    auto ret = notificationPreferences.SetDistributedDevicelist(deviceTypes, userId);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0100
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0100, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    notificationPreferences.preferncesDB_->rdbDataManager_ = nullptr;
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0200
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0200, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    int32_t userId = 100;
    std::string deviceTypesjsonString = "";
    notificationPreferences.preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetDistributedDevicelist_0300
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0300, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    int32_t userId = 100;
    std::string deviceTypesjsonString = "invalid deviceTypes";
    notificationPreferences.preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0400
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0400, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    int32_t userId = 100;
    std::string deviceTypesjsonString = "null";
    notificationPreferences.preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0500
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0500, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    int32_t userId = 100;
    std::string deviceTypesjsonString = "[]";
    notificationPreferences.preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0600
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0600, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    int32_t userId = 100;
    std::string deviceTypesjsonString = "[1, 2, 3,]";
    notificationPreferences.preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0700
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0700, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    int32_t userId = 100;
    std::string deviceTypesjsonString = R"({"key": "value"})";
    notificationPreferences.preferncesDB_->PutDistributedDevicelist(deviceTypesjsonString, userId);
    std::vector<std::string> deviceTypes;
    auto ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.name: GetDistributedDevicelist_0800
 * @tc.desc: Test SetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetDistributedDevicelist_0800, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("deviceType1");
    int32_t userId = 100;
    auto ret = notificationPreferences.SetDistributedDevicelist(deviceTypes, userId);
    ASSERT_EQ(ret, ERR_OK);
    deviceTypes.clear();
    ASSERT_EQ(deviceTypes.size(), 0);
    ret = notificationPreferences.GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(deviceTypes.size(), 1);
}
} // namespace Notification
} // namespace OHOS
