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

/**
 * @tc.name: GetExtensionSubscriptionEnabled_0100
 * @tc.desc: Test GetExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetExtensionSubscriptionEnabled_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    auto ret = notificationPreferences.GetExtensionSubscriptionEnabled(nullptr, state);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetExtensionSubscriptionEnabled_0200
 * @tc.desc: Test GetExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetExtensionSubscriptionEnabled_0200, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 100);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    auto ret = notificationPreferences.GetExtensionSubscriptionEnabled(bundleOption, state);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetExtensionSubscriptionEnabled_0100
 * @tc.desc: Test SetExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetExtensionSubscriptionEnabled_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetExtensionSubscriptionEnabled(nullptr,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 100);
    auto ret2 = notificationPreferences.SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret2, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetExtensionSubscriptionEnabled_0200
 * @tc.desc: Test SetExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetExtensionSubscriptionEnabled_0200, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle", 100);
    
    auto ret1 = notificationPreferences.SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    ASSERT_EQ(ret1, ERR_OK);
    
    NotificationConstant::SWITCH_STATE state;
    auto getRet = notificationPreferences.GetExtensionSubscriptionEnabled(bundleOption, state);
    ASSERT_EQ(getRet, ERR_OK);
    ASSERT_EQ(state, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    auto ret2 = notificationPreferences.SetExtensionSubscriptionEnabled(
        bundleOption, NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    ASSERT_EQ(ret2, ERR_OK);

    NotificationConstant::SWITCH_STATE state2;
    auto getRet2 = notificationPreferences.GetExtensionSubscriptionEnabled(bundleOption, state2);
    ASSERT_EQ(getRet2, ERR_OK);
    ASSERT_EQ(state2, NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
}
} // namespace Notification
} // namespace OHOS
