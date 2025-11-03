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
 * @tc.name: GetExtensionSubscriptionInfos_0100
 * @tc.desc: Test GetExtensionSubscriptionInfos with bundleOption nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetExtensionSubscriptionInfos_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.GetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetExtensionSubscriptionInfos_0200
 * @tc.desc: Test GetExtensionSubscriptionInfos with bundleName empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetExtensionSubscriptionInfos_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.GetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetExtensionSubscriptionInfos_0300
 * @tc.desc: Test GetExtensionSubscriptionInfos without dbSet.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetExtensionSubscriptionInfos_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.GetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: SetExtensionSubscriptionInfos_0100
 * @tc.desc: Test SetExtensionSubscriptionInfos with bundleOption nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetExtensionSubscriptionInfos_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetExtensionSubscriptionInfos_0200
 * @tc.desc: Test SetExtensionSubscriptionInfos with bundleName empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetExtensionSubscriptionInfos_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetExtensionSubscriptionInfos_0300
 * @tc.desc: Test SetExtensionSubscriptionInfos.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetExtensionSubscriptionInfos_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto type = NotificationConstant::SubscribeType::BLUETOOTH;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", type));
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);

    infos.clear();
    ret = notificationPreferences.GetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(infos.empty());
    EXPECT_EQ(infos.size(), 1);
}

/**
 * @tc.name: ClearExtensionSubscriptionInfos_0100
 * @tc.desc: Test ClearExtensionSubscriptionInfos.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, ClearExtensionSubscriptionInfos_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test", 1);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto type = NotificationConstant::SubscribeType::BLUETOOTH;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", type));
    NotificationPreferences notificationPreferences;
    auto ret = notificationPreferences.SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);

    infos.clear();
    ret = notificationPreferences.GetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(infos.empty());
    EXPECT_EQ(infos.size(), 1);

    infos.clear();
    ret = notificationPreferences.ClearExtensionSubscriptionInfos(bundleOption);
    EXPECT_EQ(ret, ERR_OK);
    
    ret = notificationPreferences.GetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(infos.empty());
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

/**
 * @tc.name: SetRingtoneInfoByBundle_0100
 * @tc.desc: Test SetRingtoneInfoByBundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetRingtoneInfoByBundle_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 100);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = notificationPreferences.SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetRingtoneInfoByBundle_0200
 * @tc.desc: Test SetRingtoneInfoByBundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, SetRingtoneInfoByBundle_0200, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundle", 100);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = notificationPreferences.SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: GetRingtoneInfoByBundle_0100
 * @tc.desc: Test GetRingtoneInfoByBundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetRingtoneInfoByBundle_0100, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("", 100);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = notificationPreferences.GetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetRingtoneInfoByBundle_0200
 * @tc.desc: Test GetRingtoneInfoByBundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetRingtoneInfoByBundle_0200, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundle", 100);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto setRet = notificationPreferences.SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(setRet, ERR_OK);
    sptr<NotificationRingtoneInfo> getResult = nullptr;
    auto getRet = notificationPreferences.GetRingtoneInfoByBundle(bundleOption, getResult);
    ASSERT_EQ(getRet, ERR_ANS_NO_CUSTOM_RINGTONE_INFO);
}

/**
 * @tc.name: GetRingtoneInfoByBundle_0300
 * @tc.desc: Test GetRingtoneInfoByBundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesTest, GetRingtoneInfoByBundle_0300, TestSize.Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundle", 100);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfoToSet = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfoToSet, nullptr);
    ringtoneInfoToSet->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfoToSet->SetRingtoneFileName("fileName");
    ringtoneInfoToSet->SetRingtoneUri("uri");
    auto setRet = notificationPreferences.SetRingtoneInfoByBundle(bundleOption, ringtoneInfoToSet);
    ASSERT_EQ(setRet, ERR_OK);
    sptr<NotificationRingtoneInfo> ringtoneInfoResult = nullptr;
    auto getRet = notificationPreferences.GetRingtoneInfoByBundle(bundleOption, ringtoneInfoResult);
    ASSERT_EQ(getRet, ERR_OK);
}
} // namespace Notification
} // namespace OHOS
