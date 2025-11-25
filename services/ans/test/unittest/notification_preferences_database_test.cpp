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

#define private public
#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_preferences_database.h"
#include "notification_rdb_data_mgr.h"
#include "notification_preferences.h"
#undef private
#undef protected
#include "mock_os_account_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesDatabaseTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp()
    {
        MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
    };
    void TearDown() {};

    const std::string bundleName_ = "bundleName";
    const int bundleUid_ = 2001;
    int32_t userId = 100;
    std::unique_ptr<NotificationPreferencesDatabase> preferncesDB_ =
        std::make_unique<NotificationPreferencesDatabase>();
};

/**
 * @tc.name      : PutSlotsToDisturbeDB_00100
 * @tc.number    :
 * @tc.desc      : Put slots into Disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutSlotsToDisturbeDB_00100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slots.push_back(slot1);
    slots.push_back(slot2);
    EXPECT_TRUE(preferncesDB_->PutSlotsToDisturbeDB(bundleName_, bundleUid_, slots));
}

/**
 * @tc.name      : PutSlotsToDisturbeDB_00200
 * @tc.number    :
 * @tc.desc      : Put slots into Disturbe DB when bundle name is null, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutSlotsToDisturbeDB_00200, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slots.push_back(slot1);
    slots.push_back(slot2);
    EXPECT_FALSE(preferncesDB_->PutSlotsToDisturbeDB(std::string(), 0, slots));
}

/**
 * @tc.name      : PutSlotsToDisturbeDB_00300
 * @tc.number    :
 * @tc.desc      : Put slots into Disturbe DB when slots is null, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutSlotsToDisturbeDB_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_FALSE(preferncesDB_->PutSlotsToDisturbeDB(bundleName_, bundleUid_, slots));
}

/**
 * @tc.name      : PutShowBadge_00100
 * @tc.number    :
 * @tc.desc      : Put bundle show badge into disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutShowBadge_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_TRUE(preferncesDB_->PutShowBadge(bundleInfo, true));
    EXPECT_TRUE(preferncesDB_->PutShowBadge(bundleInfo, false));
}

/**
 * @tc.number    : PutShowBadge_00200
 * @tc.name      :
 * @tc.desc      : Put bundle show badge into disturbe DB when bundle name is null, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutShowBadge_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(std::string());
    EXPECT_FALSE(preferncesDB_->PutShowBadge(bundleInfo, false));
}

/**
 * @tc.name      : PutImportance_00100
 * @tc.number    :
 * @tc.desc      : Put bundle importance into disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutImportance_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);

    EXPECT_TRUE(
        preferncesDB_->PutImportance(bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_NONE));
    EXPECT_TRUE(
        preferncesDB_->PutImportance(bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_MIN));
    EXPECT_TRUE(
        preferncesDB_->PutImportance(bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_LOW));
    EXPECT_TRUE(preferncesDB_->PutImportance(
        bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_DEFAULT));
    EXPECT_TRUE(
        preferncesDB_->PutImportance(bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_HIGH));
    EXPECT_TRUE(preferncesDB_->PutImportance(
        bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_UNDEFINED));
}

/**
 * @tc.name      : PutImportance_00200
 * @tc.number    :
 * @tc.desc      : Put bundle importance into disturbe DB when bundle name is null, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutImportance_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(std::string());
    bundleInfo.SetBundleUid(0);

    EXPECT_FALSE(
        preferncesDB_->PutImportance(bundleInfo, OHOS::Notification::NotificationSlot::NotificationLevel::LEVEL_NONE));
}

/**
 * @tc.name      : PutTotalBadgeNums_00100
 * @tc.number    :
 * @tc.desc      : Put bundle total badge nums into disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutTotalBadgeNums_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_TRUE(preferncesDB_->PutTotalBadgeNums(bundleInfo, 0));
}

/**
 * @tc.number    : PutTotalBadgeNums_00200
 * @tc.name      :
 * @tc.desc      : Put bundle total badge nums into disturbe DB when bundle name is null, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutTotalBadgeNums_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(std::string());
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_FALSE(preferncesDB_->PutTotalBadgeNums(bundleInfo, 0));
}

/**
 * @tc.name      : PutNotificationsEnabledForBundle_00100
 * @tc.number    :
 * @tc.desc      : Put bundle enable into disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutNotificationsEnabledForBundle_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON));
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF));
}

/**
 * @tc.name      : PutNotificationsEnabledForBundle_00200
 * @tc.number    :
 * @tc.desc      : Put bundle enable into disturbe DB when bundle name is null, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutNotificationsEnabledForBundle_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(std::string());
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_FALSE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF));
}

/**
 * @tc.name      : PutNotificationsEnabledForBundle_00300
 * @tc.number    :
 * @tc.desc      : Put bundle enable into disturbe DB when bundle name is null, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutNotificationsEnabledForBundle_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON));
    EXPECT_TRUE(preferncesDB_->RemoveEnabledDbByBundleName(bundleName_, bundleUid_));
}

/**
 * @tc.number    : PutNotificationsEnabled_00100
 * @tc.name      :
 * @tc.desc      : Put notification enable into disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutNotificationsEnabled_00100, Function | SmallTest | Level1)
{
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabled(userId, true));
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabled(userId, false));
}

/**
 * @tc.number    : PutDoNotDisturbDate_00100
 * @tc.name      :
 * @tc.desc      : Put disturbe mode into disturbe DB when DoNotDisturbType is NONE, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDoNotDisturbDate_00100, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    EXPECT_TRUE(preferncesDB_->PutDoNotDisturbDate(userId, date));
}

/**
 * @tc.number    : PutDoNotDisturbDate_00200
 * @tc.name      :
 * @tc.desc      : Put disturbe mode into disturbe DB when DoNotDisturbType is ONCE, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDoNotDisturbDate_00200, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);
    EXPECT_TRUE(preferncesDB_->PutDoNotDisturbDate(userId, date));
}

/**
 * @tc.number    : PutDoNotDisturbDate_00300
 * @tc.name      :
 * @tc.desc      : Put disturbe mode into disturbe DB when DoNotDisturbType is DAILY, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDoNotDisturbDate_00300, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);

    EXPECT_TRUE(preferncesDB_->PutDoNotDisturbDate(userId, date));
}

/**
 * @tc.number    : PutDoNotDisturbDate_00400
 * @tc.name      :
 * @tc.desc      : Put disturbe mode into disturbe DB when DoNotDisturbType is CLEARLY, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDoNotDisturbDate_00400, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::CLEARLY, beginDate, endDate);

    EXPECT_TRUE(preferncesDB_->PutDoNotDisturbDate(userId, date));
}

/**
 * @tc.name      : RemoveAllDataFromDisturbeDB_00100
 * @tc.number    :
 * @tc.desc      : Remove all bundle info from disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveAllDataFromDisturbeDB_00100, Function | SmallTest | Level1)
{
    EXPECT_TRUE(preferncesDB_->RemoveAllDataFromDisturbeDB());
}

/**
 * @tc.name      : RemoveBundleFromDisturbeDB_00100
 * @tc.number    :
 * @tc.desc      : Remove a bundle info from disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveBundleFromDisturbeDB_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    const int32_t uid = -1;
    EXPECT_TRUE(preferncesDB_->PutTotalBadgeNums(bundleInfo, 0));
    EXPECT_EQ(true, preferncesDB_->RemoveBundleFromDisturbeDB(bundleName_, uid));
}

/**
 * @tc.name      : RemoveBundleFromDisturbeDB_00200
 * @tc.number    :
 * @tc.desc      : Remove a bundle info from disturbe DB when bundle name is null, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveBundleFromDisturbeDB_00200, Function | SmallTest | Level1)
{
    const int32_t uid = -1;
    EXPECT_EQ(true, preferncesDB_->RemoveBundleFromDisturbeDB(std::string(), uid));
}

/**
 * @tc.name      : RemoveSlotFromDisturbeDB_00100
 * @tc.number    :
 * @tc.desc      : Remove slot from disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveSlotFromDisturbeDB_00100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    slots.push_back(slot1);
    EXPECT_TRUE(preferncesDB_->PutSlotsToDisturbeDB(bundleName_, bundleUid_, slots));
    EXPECT_TRUE(preferncesDB_->RemoveSlotFromDisturbeDB(
        bundleName_ + std::to_string(bundleUid_),
        OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION, -1));
}

/**
 * @tc.name      : RemoveSlotFromDisturbeDB_00200
 * @tc.number    :
 * @tc.desc      : Remove slot from disturbe DB when bundle name is null, return is false
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveSlotFromDisturbeDB_00200, Function | SmallTest | Level1)
{
    EXPECT_FALSE(preferncesDB_->RemoveSlotFromDisturbeDB(
        std::string(), OHOS::Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION, -1));
}

/**
 * @tc.name      : CheckKvStore_00100
 * @tc.number    :
 * @tc.desc      : Check disturbe DB is exsit, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, CheckKvStore_00100, Function | SmallTest | Level1)
{
    EXPECT_TRUE(preferncesDB_->CheckRdbStore());
}

/**
 * @tc.name      : CheckKvStore_00200
 * @tc.number    :
 * @tc.desc      : Check disturbe DB is exsit, return is false.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, CheckKvStore_00300, Function | SmallTest | Level1)
{
    EXPECT_TRUE(preferncesDB_->CheckRdbStore());
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::SERVICE_REMINDER);
    slots.push_back(slot1);
    slots.push_back(slot2);
    EXPECT_TRUE(preferncesDB_->PutSlotsToDisturbeDB(bundleName_, bundleUid_, slots));
}

/**
 * @tc.name      : PutBundlePropertyValueToDisturbeDB_00100
 * @tc.number    :
 * @tc.desc      : Put bundle property value to disturbeDB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutBundlePropertyValueToDisturbeDB_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo info;
    EXPECT_EQ(true, preferncesDB_->PutBundlePropertyValueToDisturbeDB(info));
}

/**
 * @tc.number    : ChangeSlotToEntry_00100
 * @tc.name      :
 * @tc.desc      : Change slot to entry.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ChangeSlotToEntry_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::unordered_map<std::string, std::string> values;
    EXPECT_TRUE(preferncesDB_->SlotToEntry(bundleName_, bundleUid_, slot, values));
}

/**
 * @tc.name      : CheckBundle_00100
 * @tc.number    :
 * @tc.desc      :Check bundle is exsit, return true when exsiting, create a bundle when does not exsit.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, CheckBundle_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ(true, preferncesDB_->CheckBundle(bundleName_, bundleUid_));
}

/**
 * @tc.number    : PutBundlePropertyToDisturbeDB_00100
 * @tc.name      : PutBundlePropertyToDisturbeDB
 * @tc.desc      : Test PutBundlePropertyToDisturbeDB function return is true
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutBundlePropertyToDisturbeDB_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo), false);
}

/**
 * @tc.number    : PutBundlePropertyToDisturbeDB_00200
 * @tc.name      : PutBundlePropertyToDisturbeDB
 * @tc.desc      : Test PutBundlePropertyToDisturbeDB empty bundle KEY_EXTENSION_SUBSCRIPTION_ENABLED
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutBundlePropertyToDisturbeDB_00200, Function | SmallTest | Level1)
{
    const std::string newName = "empty_db_bundle";
    const int32_t newUid  = 7777;

    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(newName);
    bundleInfo.SetBundleUid(newUid);
    bundleInfo.SetExtensionSubscriptionEnabled(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    bool ret = preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo);
    EXPECT_TRUE(ret);

    NotificationConstant::SWITCH_STATE state {};
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(newName, newUid);
    EXPECT_EQ(NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state), ERR_OK);
    EXPECT_EQ(state, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

/**
 * @tc.name: PutBundlePropertyToDisturbeDB_00400
 * @tc.desc: PutBundlePropertyToDisturbeDB
 * @tc.type: PutBundlePropertyToDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutBundlePropertyToDisturbeDB_00400, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);

    std::string bundleKey = bundleName_ + std::to_string(bundleUid_);
    EXPECT_TRUE(preferncesDB_->PutBundleToDisturbeDB(bundleKey, bundleInfo));

    bool ret = preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number    : RemoveAllSlotsFromDisturbeDB_00100
 * @tc.name      : RemoveAllSlotsFromDisturbeDB
 * @tc.desc      : Test RemoveAllSlotsFromDisturbeDB function return is true
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveAllSlotsFromDisturbeDB_00100, Function | SmallTest | Level1)
{
    std::string bundleKey = "BundleKey";
    EXPECT_EQ(preferncesDB_->RemoveAllSlotsFromDisturbeDB(bundleKey, -1), true);
}

/**
 * @tc.number    : RemoveNotificationEnable_00100
 * @tc.name      : RemoveNotificationEnable
 * @tc.desc      : Test RemoveNotificationEnable function when parameter is normal return is true
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveNotificationEnable_00100, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    EXPECT_EQ(preferncesDB_->RemoveNotificationEnable(userId), true);
}

/**
 * @tc.number    : RemoveDoNotDisturbDate_00100
 * @tc.name      : RemoveDoNotDisturbDate
 * @tc.desc      : Test RemoveDoNotDisturbDate function when parameter is normal return is true
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveDoNotDisturbDate_00100, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    EXPECT_EQ(preferncesDB_->RemoveDoNotDisturbDate(userId), true);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00100
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_name";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00200
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_importance";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00300
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_showBadge";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00400
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00400, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_badgeTotalNum";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00500
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00500, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_privateAllowed";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00600
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00600, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_enabledNotification";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00700
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00700, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_poppedDialog";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00800
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00800, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_uid";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_00900
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_00900, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_showBadgeEnable";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
    auto show = bundleInfo.GetIsShowBadge();
    EXPECT_TRUE(show);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_01000
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_01000, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_bundleReminderFlagsType";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
    auto show = bundleInfo.GetSlotFlags();
    EXPECT_EQ(show, 1);
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_01100
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_01100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_extensionSubscriptionInfo";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
    auto show = bundleInfo.GetExtensionSubscriptionInfosJson();
    ASSERT_FALSE(show.empty());
}

/**
 * @tc.number    : ParseBundlePropertyFromDisturbeDB_01200
 * @tc.name      : ParseBundlePropertyFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundlePropertyFromDisturbeDB_01200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_extensionSubscriptionInfo";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundlePropertyFromDisturbeDB(bundleInfo, bundleKey, entry);
    auto state = bundleInfo.GetExtensionSubscriptionEnabled();
    std::string json = std::to_string(static_cast<int>(state));
    ASSERT_FALSE(json.empty());
}

/**
 * @tc.name: PutExtensionSubscriptionInfos_0100
 * @tc.desc: test PutExtensionSubscriptionInfos with bundleName empty
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionInfos_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bool ret = preferncesDB_->PutExtensionSubscriptionInfos(bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PutExtensionSubscriptionInfos_0200
 * @tc.desc: test PutExtensionSubscriptionInfos with invalid Uid
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionInfos_0200, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    bool ret = preferncesDB_->PutExtensionSubscriptionInfos(bundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00100
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_id";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00200
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_name";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00300
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_description";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00400
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00400, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_level";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00500
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00500, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_showBadge";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00600
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00600, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_enableLight";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00700
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00700, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_enableVibration";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00800
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00800, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_ledLightColor";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_00900
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_00900, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_lockscreenVisibleness";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01000
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01000, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_sound";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01100
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_vibrationSytle";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01200
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_enableBypassDnd";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01300
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_enabled";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01400
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01400, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_reminderFlagsType";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01500
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01500, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_authorizedStatus";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01600
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01600, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_authHintCnt";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01700
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01700, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_reminderMode";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.number    : ParseSlotFromDisturbeDB_01800
 * @tc.name      : ParseSlotFromDisturbeDB
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseSlotFromDisturbeDB_01800, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    std::string bundleKey = "bundleKey";
    std::pair<std::string, std::string> entry;
    entry.first = "ans_bundle_bundleKey_slot_type_1_vibrationSytle";
    entry.second = "1";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseSlotFromDisturbeDB(bundleInfo, bundleKey, entry, -1);
}

/**
 * @tc.name      : PutHasPoppedDialog_00100
 * @tc.number    :
 * @tc.desc      : Put bundle total badge nums into disturbe DB, return is true.
 * @tc.require   : issueI62SME
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutHasPoppedDialog_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_TRUE(preferncesDB_->PutHasPoppedDialog(bundleInfo, 0));
}

/**
 * @tc.number    : PutHasPoppedDialog_00200
 * @tc.name      :
 * @tc.desc      : Put bundle total badge nums into disturbe DB when bundle name is null, return is false.
 * @tc.require   : #issueI62SME
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutHasPoppedDialog_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(std::string());
    bundleInfo.SetBundleUid(bundleUid_);
    EXPECT_FALSE(preferncesDB_->PutHasPoppedDialog(bundleInfo, 0));
}

/**
 * @tc.number    : PutDoNotDisturbDate_00500
 * @tc.name      :
 * @tc.desc      : Put disturbe mode into disturbe DB when date is nullptr, return is false.
 * @tc.require   : #issueI62SME
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDoNotDisturbDate_00500, Function | SmallTest | Level1)
{
    int32_t userId = 0;
    EXPECT_EQ(preferncesDB_->PutDoNotDisturbDate(userId, nullptr), false);
}

/**
 * @tc.number    : RemoveAllSlotsFromDisturbeDB_00200
 * @tc.name      : RemoveAllSlotsFromDisturbeDB
 * @tc.desc      : Test RemoveAllSlotsFromDisturbeDB function return is true
 * @tc.require   : #issueI62SME
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveAllSlotsFromDisturbeDB_00200, Function | SmallTest | Level1)
{
    std::string bundleKey = "";
    EXPECT_EQ(preferncesDB_->RemoveAllSlotsFromDisturbeDB(bundleKey, -1), false);
}

/**
 * @tc.number    : ChangeSlotToEntry_00200
 * @tc.name      :
 * @tc.desc      : Change slot to entry.
 * @tc.require   : #issueI62SME
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ChangeSlotToEntry_00200, Function | SmallTest | Level1)
{
    std::unordered_map<std::string, std::string> values;
    EXPECT_EQ(preferncesDB_->SlotToEntry(bundleName_, bundleUid_, nullptr, values), false);
}

/**
 * @tc.name: SetSmartReminderEnabled_0100
 * @tc.desc: test SetSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetSmartReminderEnabled_0100, TestSize.Level1)
{
    bool enable = true;
    bool ret = preferncesDB_->SetSmartReminderEnabled("testDeviceType1111", enable);
    EXPECT_EQ(ret, true);
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetSmartReminderEnabled_0200, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    bool enable = true;
    EXPECT_FALSE(preferncesDB_->SetSmartReminderEnabled("testDeviceType1111", enable));
}

/**
 * @tc.name: IsSmartReminderEnabled_0100
 * @tc.desc: test IsSmartReminderEnabled with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, IsSmartReminderEnabled_0100, TestSize.Level1)
{
    bool enable = true;
    bool result = preferncesDB_->IsSmartReminderEnabled("testDeviceType1111", enable);
    EXPECT_EQ(result, true);
}

HWTEST_F(NotificationPreferencesDatabaseTest, IsSmartReminderEnabled_0200, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    bool enable = true;
    EXPECT_FALSE(preferncesDB_->IsSmartReminderEnabled("testDeviceType1111", enable));
}


/**
 * @tc.name: PutExtensionSubscriptionBundles_0100
 * @tc.desc: test PutExtensionSubscriptionBundles.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionBundles_0100, TestSize.Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.push_back(new NotificationBundleOption("bundle1", 1001));
    bundles.push_back(new NotificationBundleOption("bundle2", 1002));
    
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("test.bundle.name");
    bundleInfo.SetBundleUid(1000);
    bundleInfo.SetExtensionSubscriptionBundles(bundles);
    
    bool result = preferncesDB_->PutExtensionSubscriptionBundles(bundleInfo);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: PutExtensionSubscriptionBundles_0200
 * @tc.desc: test PutExtensionSubscriptionBundles.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionBundles_0200, TestSize.Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.push_back(new NotificationBundleOption("bundle1", 1001));
    bundles.push_back(new NotificationBundleOption("bundle2", 1002));
    
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("");
    bundleInfo.SetBundleUid(1000);
    bundleInfo.SetExtensionSubscriptionBundles(bundles);
    
    bool result = preferncesDB_->PutExtensionSubscriptionBundles(bundleInfo);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name      : GetAllNotificationEnabledBundles_00100
 * @tc.number    : GetAllNotificationEnabledBundles
 * @tc.desc      : Check func GetAllNotificationEnabledBundles, return true
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetAllNotificationEnabledBundles_00100, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> bundleOption;
    EXPECT_EQ(true, preferncesDB_->GetAllNotificationEnabledBundles(bundleOption));
}

/**
 * @tc.name      : GetAllNotificationEnabledBundles_00200
 * @tc.number    : GetAllNotificationEnabledBundles
 * @tc.desc      : Check func GetAllNotificationEnabledBundles,no data in db return false
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetAllNotificationEnabledBundles_00200, Function | SmallTest | Level1)
{
    preferncesDB_->rdbDataManager_ = nullptr;
    std::vector<NotificationBundleOption> bundleOption;
    EXPECT_EQ(false, preferncesDB_->GetAllNotificationEnabledBundles(bundleOption));
}

/**
 * @tc.number    : RemoveAnsBundleDbInfo_00200
 * @tc.name      :
 * @tc.desc      : Test RemoveAnsBundleDbInfo function.
 * @tc.require   : #issueI62SME
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveAnsBundleDbInfo_00200, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    int32_t uid = 1;
    EXPECT_EQ(preferncesDB_->RemoveAnsBundleDbInfo(bundleName, uid), true);
}

/**
 * @tc.name: GenerateBundleLablel_0100
 * @tc.desc: test GenerateBundleLablel with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GenerateBundleLablel_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("name");
    bundleInfo.SetBundleUid(1);
    std::string deviceType = "test";
    auto ret = preferncesDB_->GenerateBundleLablel(bundleInfo, deviceType);
    EXPECT_EQ(ret, "enabledDistributedNotification-name-1-test");
}

/**
 * @tc.name: GenerateBundleLablel_0100
 * @tc.desc: test GenerateBundleLablel
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GenerateBundleLablel_0200, TestSize.Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    std::string deviceType = "test";
    auto res = preferncesDB_->GenerateBundleLablel(slotType, deviceType, userId);
    EXPECT_EQ(res, "enabledSlotDistributedNotification-test-0-100");
}

/**
 * @tc.name: PutDistributedEnabledForBundle_0100
 * @tc.desc: test PutDistributedEnabledForBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedEnabledForBundle_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("name");
    bundleInfo.SetBundleUid(1);
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    bool ret = preferncesDB_->PutDistributedEnabledForBundle(deviceType, bundleInfo, enable);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: PutDistributedEnabledForBundle_0200
 * @tc.desc: test PutDistributedEnabledForBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedEnabledForBundle_0200, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("");
    bundleInfo.SetBundleUid(1);
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    bool ret = preferncesDB_->PutDistributedEnabledForBundle(deviceType, bundleInfo, enable);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetDistributedEnabledForBundle_0100
 * @tc.desc: test GetDistributedEnabledForBundle with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedEnabledForBundle_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("name");
    bundleInfo.SetBundleUid(1);
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    bool result = preferncesDB_->GetDistributedEnabledForBundle(deviceType, bundleInfo, enable);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: GetDistributedEnabledForBundle_0200
 * @tc.desc: test GetDistributedEnabledForBundle with parameters, expect errorCode ERR_ANS_SERVICE_NOT_CONNECTED
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedEnabledForBundle_0200, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("");
    bundleInfo.SetBundleUid(1);
    std::string deviceType = "testDeviceType1111";
    bool enable = true;
    bool result = preferncesDB_->GetDistributedEnabledForBundle(deviceType, bundleInfo, enable);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: GetDistributedAuthStatus_0100
 * @tc.desc: test GetDistributedAuthStatus with invalid accountLocalId
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedAuthStatus_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::string deviceType = "deviceType";
    std::string deviceId = "deviceId";
    int32_t targetUserId = 100;
    bool isAuth;
    bool result = preferncesDB_->GetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
    EXPECT_EQ(result, false);
    EXPECT_EQ(isAuth, false);
}

/**
 * @tc.name: GetDistributedAuthStatus_0200
 * @tc.desc: test GetDistributedAuthStatus when NativeRdb::E_EMPTY_VALUES_BUCKET
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedAuthStatus_0200, TestSize.Level1)
{
    std::string deviceType = "deviceType";
    std::string deviceId = "deviceId";
    int32_t targetUserId = 100;
    bool isAuth;
    bool result = preferncesDB_->GetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    EXPECT_EQ(result, true);
    EXPECT_EQ(isAuth, false);
}

/**
 * @tc.name: GetDistributedAuthStatus_0300
 * @tc.desc: test GetDistributedAuthStatus when NativeRdb::E_OK
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedAuthStatus_0300, TestSize.Level1)
{
    std::string deviceType = "deviceType";
    std::string deviceId = "deviceId";
    int32_t targetUserId = 100;
    bool isAuth = true;
    bool result = preferncesDB_->SetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    EXPECT_EQ(result, true);
    result = preferncesDB_->GetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    EXPECT_EQ(result, true);
    EXPECT_EQ(isAuth, true);
}

/**
 * @tc.name: SetDistributedAuthStatus_0100
 * @tc.desc: test SetDistributedAuthStatus with invalid accountLocalId
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetDistributedAuthStatus_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::string deviceType = "deviceType";
    std::string deviceId = "deviceId";
    int32_t targetUserId = 100;
    bool isAuth = true;
    bool result = preferncesDB_->SetDistributedAuthStatus(deviceType, deviceId, targetUserId, isAuth);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0100
 * @tc.desc: test AddDoNotDisturbProfiles run success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, AddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(1);
    profile->SetProfileName("Name");
    std::string bundleName = "bundleName";
    int32_t uid = 1;
    NotificationBundleOption notificationBundleOption(bundleName, uid);
    vector<NotificationBundleOption> trustlist;
    trustlist.emplace_back(notificationBundleOption);
    profile->SetProfileTrustList(trustlist);
    profiles.emplace_back(profile);

    auto res = preferncesDB_->AddDoNotDisturbProfiles(userId, profiles);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0200
 * @tc.desc: test AddDoNotDisturbProfiles
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, AddDoNotDisturbProfiles_0200, TestSize.Level1)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = nullptr;
    profiles.push_back(profile);
    auto ret = preferncesDB_->AddDoNotDisturbProfiles(userId, profiles);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0100
 * @tc.desc: test RemoveDoNotDisturbProfiles run success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveDoNotDisturbProfiles_0100, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(1);
    profile->SetProfileName("Name");
    std::string bundleName = "bundleName";
    int32_t uid = 1;
    NotificationBundleOption notificationBundleOption(bundleName, uid);
    vector<NotificationBundleOption> trustlist;
    trustlist.emplace_back(notificationBundleOption);
    profile->SetProfileTrustList(trustlist);
    profiles.emplace_back(profile);

    preferncesDB_->AddDoNotDisturbProfiles(userId, profiles);
    auto res = preferncesDB_->RemoveDoNotDisturbProfiles(userId, profiles);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0200
 * @tc.desc: test RemoveDoNotDisturbProfiles
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveDoNotDisturbProfiles_0200, TestSize.Level1)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = nullptr;
    profiles.push_back(profile);
    auto ret = preferncesDB_->RemoveDoNotDisturbProfiles(userId, profiles);
    ASSERT_FALSE(ret);
}

HWTEST_F(NotificationPreferencesDatabaseTest, RemoveDoNotDisturbProfiles_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile->SetProfileId(1);
    profile->SetProfileName("Name");
    std::string bundleName = "bundleName";
    int32_t uid = 1;
    NotificationBundleOption notificationBundleOption(bundleName, uid);
    vector<NotificationBundleOption> trustlist;
    trustlist.emplace_back(notificationBundleOption);
    profile->SetProfileTrustList(trustlist);
    profiles.emplace_back(profile);

    EXPECT_FALSE(notificationPreferencesDatabase->RemoveDoNotDisturbProfiles(userId, profiles));
}

/**
 * @tc.name: GetDoNotDisturbProfiles_0100
 * @tc.desc: test GetDoNotDisturbProfiles return of QueryData is not zero.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDoNotDisturbProfiles_0100, TestSize.Level1)
{
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profiles.emplace_back(profile);
    preferncesDB_->AddDoNotDisturbProfiles(userId, profiles);
    std::string key;
    auto res = preferncesDB_->GetDoNotDisturbProfiles(key, profile, -1);
    EXPECT_EQ(res, false);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetDoNotDisturbProfiles_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profiles.emplace_back(profile);
    std::string key;
    auto res = notificationPreferencesDatabase->GetDoNotDisturbProfiles(key, profile, -1);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetDoNotDisturbProfile_0100
 * @tc.desc: test GetDoNotDisturbProfile when profiles is empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDoNotDisturbProfile_0100, TestSize.Level1)
{
    NotificationPreferencesInfo info;
    int32_t userId = 1;
    preferncesDB_->GetDoNotDisturbProfile(info, userId);
    int32_t profileId = 1;
    sptr<NotificationDoNotDisturbProfile> profile;
    auto res = info.GetDoNotDisturbProfiles(profileId, userId, profile);
    auto infos = new (std::nothrow) NotificationPreferencesInfo();
    EXPECT_EQ(res, false);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetDoNotDisturbProfile_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    NotificationPreferencesInfo info;
    int32_t userId = 1;
    notificationPreferencesDatabase->GetDoNotDisturbProfile(info, userId);
    int32_t profileId = 1;
    sptr<NotificationDoNotDisturbProfile> profile;
    auto res = info.GetDoNotDisturbProfiles(profileId, userId, profile);
    auto infos = new (std::nothrow) NotificationPreferencesInfo();
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDisableNotificationInfo_0100
 * @tc.desc: test SetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetDisableNotificationInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    EXPECT_FALSE(notificationPreferencesDatabase->SetDisableNotificationInfo(nullptr));
}

/**
 * @tc.name: SetDisableNotificationInfo_0200
 * @tc.desc: test SetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetDisableNotificationInfo_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    EXPECT_FALSE(notificationPreferencesDatabase->SetDisableNotificationInfo(notificationDisable));
}

/**
 * @tc.name: SetDisableNotificationInfo_0300
 * @tc.desc: test SetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetDisableNotificationInfo_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    EXPECT_TRUE(notificationPreferencesDatabase->SetDisableNotificationInfo(notificationDisable));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetDisableNotificationInfo_0400, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    EXPECT_FALSE(notificationPreferencesDatabase->SetDisableNotificationInfo(notificationDisable));
}

/**
 * @tc.name: GetDisableNotificationInfo_0100
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDisableNotificationInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    notificationPreferencesDatabase->SetDisableNotificationInfo(notificationDisable);
    NotificationDisable disable;
    EXPECT_TRUE(notificationPreferencesDatabase->GetDisableNotificationInfo(disable));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetDisableNotificationInfo_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });

    NotificationPreferencesInfo info;
    notificationPreferencesDatabase->GetDisableNotificationInfo(info);

    NotificationDisable disable;
    EXPECT_FALSE(notificationPreferencesDatabase->GetDisableNotificationInfo(disable));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetUserDisableNotificationInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    NotificationDisable disable;
    int32_t userId = 100;
    EXPECT_FALSE(notificationPreferencesDatabase->GetUserDisableNotificationInfo(userId, disable));
}

/**
 * @tc.name: IsDistributedEnabledEmptyForBundle_0100
 * @tc.desc: test IsDistributedEnabledEmptyForBundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, IsDistributedEnabledEmptyForBundle_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("testBundleName");
    bundleInfo.SetBundleUid(1000);
    std::string deviceType = "testType";
    bool ret = preferncesDB_->IsDistributedEnabledEmptyForBundle(deviceType, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetSmartReminderEnableFromCCM_0100
 * @tc.desc: test GetSmartReminderEnableFromCCM
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetSmartReminderEnableFromCCM_0100, TestSize.Level1)
{
    std::string deviceType = "testType";
    bool enabled = true;
    preferncesDB_->GetSmartReminderEnableFromCCM(deviceType, enabled);
    EXPECT_FALSE(enabled);
    preferncesDB_->isCachedSmartReminderEnableList_ = true;
    preferncesDB_->smartReminderEnableList_.clear();
    preferncesDB_->GetSmartReminderEnableFromCCM(deviceType, enabled);
    EXPECT_FALSE(enabled);
    preferncesDB_->smartReminderEnableList_.push_back("test");
    preferncesDB_->GetSmartReminderEnableFromCCM(deviceType, enabled);
    EXPECT_FALSE(enabled);
    preferncesDB_->smartReminderEnableList_.push_back(deviceType);
    preferncesDB_->GetSmartReminderEnableFromCCM(deviceType, enabled);
    EXPECT_TRUE(enabled);
}

/**
 * @tc.name: GenerateSubscriberExistFlagKey_0100
 * @tc.desc: test GenerateSubscriberExistFlagKey
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GenerateSubscriberExistFlagKey_0100, TestSize.Level1)
{
    std::string deviceType = "testType";
    int32_t userId = 0;
    auto ret = preferncesDB_->GenerateSubscriberExistFlagKey(deviceType, userId);
    std::string flag = "existFlag";
    std::string middleLine = "-";
    std::string key = flag.append(middleLine).append(deviceType).append(middleLine).append(std::to_string(userId));
    EXPECT_EQ(ret, key);
}

/**
 * @tc.name: SetSubscriberExistFlag_0100
 * @tc.desc: test SetSubscriberExistFlag
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetSubscriberExistFlag_0100, TestSize.Level1)
{
    auto ret = preferncesDB_->SetSubscriberExistFlag(DEVICE_TYPE_HEADSET, false);
    EXPECT_TRUE(ret);
    bool enabled = true;
    ret = preferncesDB_->GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, enabled);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(enabled);
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetSubscriberExistFlag_0200, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    auto ret = preferncesDB_->SetSubscriberExistFlag(DEVICE_TYPE_HEADSET, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetSubscriberExistFlag_0100
 * @tc.desc: test GetSubscriberExistFlag
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetSubscriberExistFlag_0100, TestSize.Level1)
{
    auto ret = preferncesDB_->SetSubscriberExistFlag(DEVICE_TYPE_HEADSET, true);
    EXPECT_TRUE(ret);
    bool enabled = false;
    ret = preferncesDB_->GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, enabled);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(enabled);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetSubscriberExistFlag_0200, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    bool enabled = false;
    EXPECT_FALSE(preferncesDB_->GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, enabled));
}

/**
 * @tc.name: IsNotificationSlotFlagsExists_0100
 * @tc.desc: test IsNotificationSlotFlagsExists
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, IsNotificationSlotFlagsExists_0100, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    auto ret = preferncesDB_->IsNotificationSlotFlagsExists(bundleOption);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: ParseFromDisturbeDB_0100
 * @tc.desc: test ParseFromDisturbeDB
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseFromDisturbeDB_0100, TestSize.Level1)
{
    NotificationPreferencesInfo preferencesInfo;
    auto ret = preferncesDB_->ParseFromDisturbeDB(preferencesInfo, userId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ParseBundleFromDistureDB_0100
 * @tc.desc: test ParseBundleFromDistureDB
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, ParseBundleFromDistureDB_0100, TestSize.Level1)
{
    NotificationPreferencesInfo preferencesInfo;
    std::unordered_map<std::string, std::string> values;
    values["test"] =  "test";
    preferncesDB_->ParseBundleFromDistureDB(preferencesInfo, values, userId);
    EXPECT_EQ(1, preferencesInfo.infos_.size());
    preferencesInfo.infos_.clear();
}

/**
 * @tc.name: StringToVector_0100
 * @tc.desc: test StringToVector
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, StringToVector_0100, TestSize.Level1)
{
    std::string str = "";
    std::vector<int64_t> data;
    preferncesDB_->StringToVector(str, data);
    EXPECT_EQ(0, data.size());
}

/**
 * @tc.name: StringToVector_0200
 * @tc.desc: test StringToVector
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, StringToVector_0200, TestSize.Level1)
{
    std::string str = "1_2_3";
    std::vector<int64_t> data;
    preferncesDB_->StringToVector(str, data);
    EXPECT_EQ(2, data.size());
}

/**
 * @tc.name: GetByteFromDb_0100
 * @tc.desc: test GetByteFromDb
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetByteFromDb_0100, TestSize.Level1)
{
    std::string key;
    std::vector<uint8_t> value;
    auto res = preferncesDB_->GetByteFromDb(key, value, userId);
    ASSERT_NE(res, ERR_OK);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetByteFromDb_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    std::string key;
    std::vector<uint8_t> value;
    auto res = notificationPreferencesDatabase->GetByteFromDb(key, value, userId);
    EXPECT_EQ(res, NativeRdb::E_ERROR);
}

/**
 * @tc.name: DeleteBatchKvFromDb_0100
 * @tc.desc: test DeleteBatchKvFromDb
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, DeleteBatchKvFromDb_0100, TestSize.Level1)
{
    std::vector<std::string> keys;
    auto res = preferncesDB_->DeleteBatchKvFromDb(keys, userId);
    EXPECT_EQ(res, ERR_OK);
}

HWTEST_F(NotificationPreferencesDatabaseTest, DeleteBatchKvFromDb_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    std::vector<std::string> keys;
    EXPECT_EQ(notificationPreferencesDatabase->DeleteBatchKvFromDb(keys, userId), NativeRdb::E_ERROR);
}

/**
 * @tc.name: SetDistributedEnabledBySlot_0100
 * @tc.desc: test SetDistributedEnabledBySlot
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetDistributedEnabledBySlot_0100, TestSize.Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    std::string deviceType = "test1";
    NotificationConstant::SWITCH_STATE enabled = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto res = preferncesDB_->SetDistributedEnabledBySlot(slotType, deviceType, enabled);
    EXPECT_EQ(res, true);

    res = preferncesDB_->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
    EXPECT_EQ(res, true);
    EXPECT_EQ(enabled, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetDistributedEnabledBySlot_0200, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    std::string deviceType = "test1";
    NotificationConstant::SWITCH_STATE enabled = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    EXPECT_FALSE(preferncesDB_->SetDistributedEnabledBySlot(slotType, deviceType, enabled));
}

HWTEST_F(NotificationPreferencesDatabaseTest, IsDistributedEnabledBySlot_0200, TestSize.Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    std::string deviceType = "test2";
    
    NotificationConstant::SWITCH_STATE enabled = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    auto res = preferncesDB_->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
    EXPECT_EQ(res, true);
    EXPECT_EQ(enabled, NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
}

HWTEST_F(NotificationPreferencesDatabaseTest, IsDistributedEnabledBySlot_0300, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    std::string deviceType = "test2";
    
    NotificationConstant::SWITCH_STATE enabled = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    EXPECT_FALSE(preferncesDB_->IsDistributedEnabledBySlot(slotType, deviceType, enabled));
}

/**
 * @tc.name: UpdateBundlePropertyToDisturbeDB_0100
 * @tc.desc: test UpdateBundlePropertyToDisturbeDB
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, UpdateBundlePropertyToDisturbeDB_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("test1");
    bundleInfo.SetBundleUid(1000);
    
    auto res = preferncesDB_->UpdateBundlePropertyToDisturbeDB(userId, bundleInfo);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: UpdateBundlePropertyToDisturbeDB_0200
 * @tc.desc: test UpdateBundlePropertyToDisturbeDB
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, UpdateBundlePropertyToDisturbeDB_0200, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("");
    bundleInfo.SetBundleUid(1000);
    
    auto res = preferncesDB_->UpdateBundlePropertyToDisturbeDB(userId, bundleInfo);
    EXPECT_EQ(res, false);
}

HWTEST_F(NotificationPreferencesDatabaseTest, UpdateBundlePropertyToDisturbeDB_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("test");
    bundleInfo.SetBundleUid(1000);
    
    auto res = notificationPreferencesDatabase->UpdateBundlePropertyToDisturbeDB(userId, bundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: IsAgentRelationship_0201
 * @tc.desc: test IsAgentRelationship
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, IsAgentRelationship_0201, TestSize.Level1)
{
    std::string cacheString;
    preferncesDB_->GetValueFromDisturbeDB("PROXY_PKG", SUBSCRIBE_USER_INIT,
        [&](const int32_t &status, std::string &value) {
        switch (status) {
            case NativeRdb::E_OK: {
                cacheString = value;
                break;
            }
        }
    });

    std::string value = "[{\"app\":\"ohos.example.app\",\"service\":\"ohos.example.app\"}]";
    int32_t result = preferncesDB_->SetKvToDb("PROXY_PKG", value, SUBSCRIBE_USER_INIT);
    EXPECT_EQ(result, 0);
    bool isAgent = preferncesDB_->IsAgentRelationship("ohos.example.app", "ohos.example.app");
    EXPECT_EQ(isAgent, true);
    isAgent = preferncesDB_->IsAgentRelationship("ohos.example.app", "ohos.example.app1");
    EXPECT_EQ(isAgent, false);
    // delete data
    result = preferncesDB_->DeleteKvFromDb("PROXY_PKG", SUBSCRIBE_USER_INIT);
    EXPECT_EQ(result, 0);
    isAgent = preferncesDB_->IsAgentRelationship("ohos.example.app", "ohos.example.app");
    EXPECT_EQ(isAgent, false);

    // insert data not array
    value = "{\"app\":\"ohos.example.app\",\"service\":\"ohos.example.app\"}";
    result = preferncesDB_->SetKvToDb("PROXY_PKG", value, SUBSCRIBE_USER_INIT);
    EXPECT_EQ(result, 0);
    isAgent = preferncesDB_->IsAgentRelationship("ohos.example.app", "ohos.example.app");
    EXPECT_EQ(isAgent, false);

    // insert empty data
    result = preferncesDB_->SetKvToDb("PROXY_PKG", std::string(), SUBSCRIBE_USER_INIT);
    EXPECT_EQ(result, 0);
    isAgent = preferncesDB_->IsAgentRelationship("ohos.example.app", "ohos.example.app");
    EXPECT_EQ(isAgent, false);

    // recover data
    result = preferncesDB_->SetKvToDb("PROXY_PKG", cacheString, SUBSCRIBE_USER_INIT);
    EXPECT_EQ(result, 0);
}

HWTEST_F(NotificationPreferencesDatabaseTest, IsAgentRelationship_0202, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;

    EXPECT_FALSE(notificationPreferencesDatabase->IsAgentRelationship("ohos.example.app", "ohos.example.app"));
}

/**
 * @tc.name: UpdateBundleSlotToDisturbeDB_0202
 * @tc.desc: test UpdateBundleSlotToDisturbeDB
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, UpdateBundleSlotToDisturbeDB_0202, TestSize.Level1)
{
    int32_t userId = 100;
    int32_t bundleUid = 100000;
    std::string bundleName = "ohos.example.demo";
    std::vector<sptr<NotificationSlot>> slots;
    // updata empty slots
    bool result = preferncesDB_->UpdateBundleSlotToDisturbeDB(userId, bundleName, bundleUid, slots);
    EXPECT_EQ(result, true);

    sptr<NotificationSlot> slotInfo = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    slots.push_back(slotInfo);
    // update empty bundle name
    result = preferncesDB_->UpdateBundleSlotToDisturbeDB(userId, "", bundleUid, slots);
    EXPECT_EQ(result, false);

    // update slots
    result = preferncesDB_->UpdateBundleSlotToDisturbeDB(userId, bundleName, bundleUid, slots);
    EXPECT_EQ(result, true);
}

HWTEST_F(NotificationPreferencesDatabaseTest, UpdateBundleSlotToDisturbeDB_0203, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    int32_t bundleUid = 100000;
    std::string bundleName = "ohos.example.demo";
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slotInfo = new (std::nothrow) NotificationSlot(NotificationConstant::SlotType::LIVE_VIEW);
    slots.push_back(slotInfo);

    // updata empty slots
    bool result = notificationPreferencesDatabase->UpdateBundleSlotToDisturbeDB(userId, bundleName, bundleUid, slots);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: DelBatchCloneBundleInfo_0203
 * @tc.desc: test DelBatchCloneBundleInfo
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, DelBatchCloneBundleInfo_0203, TestSize.Level1)
{
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetAppIndex(0);
    bundleInfo.SetSlotFlags(59);
    bundleInfo.SetBundleName("ohos.example.demo");
    std::vector<NotificationCloneBundleInfo> cloneBundleInfo;
    cloneBundleInfo.push_back(bundleInfo);
    bool result = preferncesDB_->UpdateBatchCloneBundleInfo(100, cloneBundleInfo);
    EXPECT_EQ(result, true);
    result = preferncesDB_->DelBatchCloneBundleInfo(100, cloneBundleInfo);
    EXPECT_EQ(result, true);
}

HWTEST_F(NotificationPreferencesDatabaseTest, DelBatchCloneBundleInfo_0204, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetAppIndex(0);
    bundleInfo.SetSlotFlags(59);
    bundleInfo.SetBundleName("ohos.example.demo");
    std::vector<NotificationCloneBundleInfo> cloneBundleInfo;
    cloneBundleInfo.push_back(bundleInfo);

    EXPECT_FALSE(notificationPreferencesDatabase->DelBatchCloneBundleInfo(100, cloneBundleInfo));
}

HWTEST_F(NotificationPreferencesDatabaseTest, DelCloneBundleInfo_0204, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetAppIndex(0);
    bundleInfo.SetSlotFlags(59);
    bundleInfo.SetBundleName("ohos.example.demo");

    EXPECT_FALSE(notificationPreferencesDatabase->DelCloneBundleInfo(100, bundleInfo));
}


/**
 * @tc.name: SetBundleRemoveFlag_0204
 * @tc.desc: test SetBundleRemoveFlag
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetBundleRemoveFlag_0204, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;
    bool result = preferncesDB_->GetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 1);
    EXPECT_EQ(result, true);

    bundle = new (std::nothrow) NotificationBundleOption("ohos.example.demo", 10000);
    result = preferncesDB_->GetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 1);
    EXPECT_EQ(result, false);
    result = preferncesDB_->GetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 2);
    EXPECT_EQ(result, false);

    result = preferncesDB_->SetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 1);
    EXPECT_EQ(result, true);
    result = preferncesDB_->SetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 2);
    EXPECT_EQ(result, true);

    result = preferncesDB_->GetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 1);
    EXPECT_EQ(result, true);

    // delete data
    std::string key = "label_ans_remove_ohos.example.demo10000_5";
    int32_t res = preferncesDB_->DeleteKvFromDb(key, 100);
    EXPECT_EQ(res, 0);
    key = "label_ans_remove_2_ohos.example.demo10000_5";
    res = preferncesDB_->DeleteKvFromDb(key, 100);
    EXPECT_EQ(res, 0);
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetBundleRemoveFlag_0205, TestSize.Level1)
{
    sptr<NotificationBundleOption> bundle = nullptr;

    EXPECT_FALSE(preferncesDB_->SetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 1));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetBundleRemoveFlag_0206, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    sptr<NotificationBundleOption> bundle =
        new (std::nothrow) NotificationBundleOption("ohos.example.demo", 10000);

    EXPECT_FALSE(preferncesDB_->SetBundleRemoveFlag(bundle, NotificationConstant::SlotType::LIVE_VIEW, 1));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetBundleRemoveFlag_0207, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    sptr<NotificationBundleOption> bundle =
        new (std::nothrow) NotificationBundleOption("ohos.example.demo", 10000);

    EXPECT_FALSE(notificationPreferencesDatabase->SetBundleRemoveFlag(bundle,
        NotificationConstant::SlotType::LIVE_VIEW, 1));
}

/**
 * @tc.name: DelCloneProfileInfo_0205
 * @tc.desc: test DelCloneProfileInfo
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, DelCloneProfileInfo_0205, TestSize.Level1)
{
    NotificationBundleOption bundle1 = NotificationBundleOption("ohos.example.demo", 10000);
    NotificationBundleOption bundle2 = NotificationBundleOption("ohos.example.demo", 10001);
    std::vector<NotificationBundleOption> trustList;
    trustList.push_back(bundle1);
    trustList.push_back(bundle2);

    // update profile1 and profile2
    sptr<NotificationDoNotDisturbProfile> profile1 = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile1->SetProfileId(1);
    profile1->SetProfileName("name1");
    profile1->SetProfileTrustList(trustList);
    sptr<NotificationDoNotDisturbProfile> profile2 = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile2->SetProfileId(2);
    profile2->SetProfileName("name1");
    profile2->SetProfileTrustList(trustList);
    std::vector<sptr<NotificationDoNotDisturbProfile>> profileInfo;
    profileInfo.push_back(profile1);
    profileInfo.push_back(profile2);
    bool result = preferncesDB_->UpdateBatchCloneProfileInfo(100, profileInfo);
    EXPECT_EQ(result, true);
    // delete profile1
    result = preferncesDB_->DelCloneProfileInfo(100, profile1);
    EXPECT_EQ(result, true);
    std::vector<sptr<NotificationDoNotDisturbProfile>> tmpProfilesInfo;
    preferncesDB_->GetAllCloneProfileInfo(100, tmpProfilesInfo);
    EXPECT_EQ((int32_t)tmpProfilesInfo.size(), 1);

    std::vector<sptr<NotificationDoNotDisturbProfile>> deleteProfileInfo;
    deleteProfileInfo.push_back(profile2);
    result = preferncesDB_->DelBatchCloneProfileInfo(100, deleteProfileInfo);
    EXPECT_EQ(result, true);
}

HWTEST_F(NotificationPreferencesDatabaseTest, DelCloneProfileInfo_0206, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    NotificationBundleOption bundle1 = NotificationBundleOption("ohos.example.demo", 10000);
    NotificationBundleOption bundle2 = NotificationBundleOption("ohos.example.demo", 10001);
    std::vector<NotificationBundleOption> trustList;
    trustList.push_back(bundle1);
    trustList.push_back(bundle2);

    // update profile1 and profile2
    sptr<NotificationDoNotDisturbProfile> profile1 = new (std::nothrow) NotificationDoNotDisturbProfile();
    profile1->SetProfileId(1);
    profile1->SetProfileName("name1");
    profile1->SetProfileTrustList(trustList);

    // delete profile1
    EXPECT_FALSE(notificationPreferencesDatabase->DelCloneProfileInfo(100, profile1));
}

HWTEST_F(NotificationPreferencesDatabaseTest, DelBatchCloneProfileInfo_0206, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;

    // delete profile1
    std::vector<sptr<NotificationDoNotDisturbProfile>> deleteProfileInfo;
    EXPECT_FALSE(notificationPreferencesDatabase->DelBatchCloneProfileInfo(100, deleteProfileInfo));
}

/**
 * @tc.name: PutDistributedDevicelist_0100
 * @tc.desc: Test PutDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedDevicelist_0100, TestSize.Level1)
{
    preferncesDB_->rdbDataManager_ = nullptr;
    std::string deviceTypes = "deviceTypes";
    int32_t userId = 100;
    auto ret = preferncesDB_->PutDistributedDevicelist(deviceTypes, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PutDistributedDevicelist_0200
 * @tc.desc: Test PutDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedDevicelist_0200, TestSize.Level1)
{
    preferncesDB_ = std::make_unique<NotificationPreferencesDatabase>();
    ASSERT_NE(preferncesDB_, nullptr);
    std::string deviceTypes = "deviceTypes";
    int32_t userId = 100;
    auto ret = preferncesDB_->PutDistributedDevicelist(deviceTypes, userId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetDistributedDevicelist_0100
 * @tc.desc: Test GetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedDevicelist_0100, TestSize.Level1)
{
    std::string deviceTypes;
    int32_t userId = 100;
    auto ret = preferncesDB_->PutDistributedDevicelist(deviceTypes, userId);
    EXPECT_EQ(ret, true);
    ret = preferncesDB_->GetDistributedDevicelist(deviceTypes);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetDistributedDevicelist_0200
 * @tc.desc: Test GetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedDevicelist_0200, TestSize.Level1)
{
    std::string deviceTypes = "deviceTypes";
    int32_t userId = 100;
    auto ret = preferncesDB_->PutDistributedDevicelist(deviceTypes, userId);
    EXPECT_EQ(ret, true);
    ret = preferncesDB_->GetDistributedDevicelist(deviceTypes);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(deviceTypes.empty(), false);
}

/**
 * @tc.name: GetDistributedDevicelist_0300
 * @tc.desc: Test GetDistributedDevicelist
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedDevicelist_0300, TestSize.Level1)
{
    std::string deviceTypes1 = "deviceTypes1";
    int32_t userId1 = 100;
    auto ret = preferncesDB_->PutDistributedDevicelist(deviceTypes1, userId1);
    EXPECT_EQ(ret, true);
    std::string deviceTypes2 = "deviceTypes2";
    int32_t userId2 = 101;
    ret = preferncesDB_->PutDistributedDevicelist(deviceTypes2, userId2);
    EXPECT_EQ(ret, true);
    std::string deviceTypes;
    ret = preferncesDB_->GetDistributedDevicelist(deviceTypes);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(deviceTypes, deviceTypes1);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedDevicelist_0400, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::string deviceTypes2 = "deviceTypes2";

    EXPECT_EQ(preferncesDB_->GetDistributedDevicelist(deviceTypes2), false);
}

/**
 * @tc.name: PutExtensionSubscriptionEnabled_0100
 * @tc.desc: Test PutExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionEnabled_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bool ret = preferncesDB_->PutExtensionSubscriptionEnabled(bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PutExtensionSubscriptionEnabled_0200
 * @tc.desc: Test PutExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionEnabled_0200, TestSize.Level1)

{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName_);
    bundleInfo.SetBundleUid(bundleUid_);
    bool ret = preferncesDB_->PutExtensionSubscriptionEnabled(bundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: PutExtensionSubscriptionEnabled_0300
 * @tc.desc: Test PutExtensionSubscriptionEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, PutExtensionSubscriptionEnabled_0300, TestSize.Level1)
{
    const std::string noExistName = "no_exist_bundle";
    const int32_t noExistUid = 99999;

    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName(noExistName);
    bundleInfo.SetBundleUid(noExistUid);
    bool ret = preferncesDB_->PutExtensionSubscriptionEnabled(bundleInfo);
    EXPECT_TRUE(ret);
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetLiveViewConfigVersion_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t version = 1;
    EXPECT_TRUE(notificationPreferencesDatabase->SetLiveViewConfigVersion(version));

    int32_t result = 0;
    EXPECT_TRUE(notificationPreferencesDatabase->GetLiveViewConfigVersion(version));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetLiveViewConfigVersion_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t version = 1;

    EXPECT_FALSE(notificationPreferencesDatabase->SetLiveViewConfigVersion(version));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetLiveViewConfigVersion_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t version = 0;

    EXPECT_TRUE(notificationPreferencesDatabase->GetLiveViewConfigVersion(version));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetLiveViewConfigVersion_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t version = 0;

    EXPECT_FALSE(notificationPreferencesDatabase->GetLiveViewConfigVersion(version));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetLiveViewConfigVersion_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;
    EXPECT_TRUE(notificationPreferencesDatabase->SetLiveViewRebuildFlag(userId));

    std::string result = "";
    EXPECT_TRUE(notificationPreferencesDatabase->GetLiveViewRebuildFlag(result, userId));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetLiveViewRebuildFlag_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;

    EXPECT_TRUE(notificationPreferencesDatabase->SetLiveViewRebuildFlag(userId));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetLiveViewRebuildFlag_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;

    EXPECT_FALSE(notificationPreferencesDatabase->SetLiveViewRebuildFlag(userId));
}

HWTEST_F(NotificationPreferencesDatabaseTest, RemoveLiveViewRebuildFlag_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;

    EXPECT_TRUE(notificationPreferencesDatabase->RemoveLiveViewRebuildFlag(userId));
}

HWTEST_F(NotificationPreferencesDatabaseTest, RemoveLiveViewRebuildFlag_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;

    EXPECT_FALSE(notificationPreferencesDatabase->RemoveLiveViewRebuildFlag(userId));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutPriorityEnabled_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;

    EXPECT_TRUE(notificationPreferencesDatabase->PutPriorityEnabled(switchState));

    NotificationConstant::SWITCH_STATE result;
    EXPECT_TRUE(notificationPreferencesDatabase->GetPriorityEnabled(result));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutPriorityEnabled_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;

    EXPECT_FALSE(notificationPreferencesDatabase->PutPriorityEnabled(switchState));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutPriorityEnabled_0300, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;

    EXPECT_FALSE(notificationPreferencesDatabase->PutPriorityEnabled(switchState));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetPriorityEnabled_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::SWITCH_STATE switchState;

    EXPECT_FALSE(notificationPreferencesDatabase->GetPriorityEnabled(switchState));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutPriorityEnabledForBundle_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::PriorityEnableStatus enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE;
    NotificationPreferencesInfo::BundleInfo bundleInfo;

    EXPECT_FALSE(notificationPreferencesDatabase->PutPriorityEnabledForBundle(bundleInfo, enableStatus));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutPriorityEnabledForBundle_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.bundleName_ = "testBundle";
    NotificationConstant::PriorityEnableStatus enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE;
    EXPECT_TRUE(notificationPreferencesDatabase->PutPriorityEnabledForBundle(bundleInfo, enableStatus));
    EXPECT_TRUE(notificationPreferencesDatabase->GetPriorityEnabledForBundle(bundleInfo, enableStatus));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutPriorityEnabledForBundle_0300, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::PriorityEnableStatus enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.bundleName_ = "testBundle";

    EXPECT_FALSE(notificationPreferencesDatabase->PutPriorityEnabledForBundle(bundleInfo, enableStatus));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetPriorityEnabledForBundle_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::PriorityEnableStatus enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE;
    NotificationPreferencesInfo::BundleInfo bundleInfo;

    EXPECT_FALSE(notificationPreferencesDatabase->GetPriorityEnabledForBundle(bundleInfo, enableStatus));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetPriorityEnabledForBundle_0200, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::PriorityEnableStatus enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.bundleName_ = "testBundle";

    EXPECT_FALSE(notificationPreferencesDatabase->GetPriorityEnabledForBundle(bundleInfo, enableStatus));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetPriorityEnabledForBundle_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::PriorityEnableStatus enableStatus = NotificationConstant::PriorityEnableStatus::ENABLE;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.bundleName_ = "testBundle";

    EXPECT_TRUE(notificationPreferencesDatabase->GetPriorityEnabledForBundle(bundleInfo, enableStatus));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedEnabled_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::SWITCH_STATE switchState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON;
    std::string deviceType = "test";

    EXPECT_FALSE(notificationPreferencesDatabase->PutDistributedEnabled(deviceType, switchState));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetDistributedEnabled_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    NotificationConstant::SWITCH_STATE switchState;
    std::string deviceType = "test";

    EXPECT_FALSE(notificationPreferencesDatabase->GetDistributedEnabled(deviceType, switchState));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutSlotFlags_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t flags = 59;
    NotificationPreferencesInfo::BundleInfo bundleInfo;

    EXPECT_FALSE(notificationPreferencesDatabase->PutSlotFlags(bundleInfo, flags));
}

HWTEST_F(NotificationPreferencesDatabaseTest, RemoveSilentEnabledDbByBundle_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t uid = 59;
    std::string bundleName = "";

    EXPECT_FALSE(notificationPreferencesDatabase->RemoveSilentEnabledDbByBundle(bundleName, uid));
}

HWTEST_F(NotificationPreferencesDatabaseTest, RemoveEnabledDbByBundleName_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t uid = 59;
    std::string bundleName = "";

    EXPECT_FALSE(notificationPreferencesDatabase->RemoveEnabledDbByBundleName(bundleName, uid));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetKvToDb_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";
    std::string value = "value";

    EXPECT_EQ(notificationPreferencesDatabase->SetKvToDb(key, value, userId), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetByteToDb_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";
    std::vector<uint8_t> value;

    EXPECT_EQ(notificationPreferencesDatabase->SetByteToDb(key, value, userId), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetKvFromDb_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";
    std::string value = "value";

    EXPECT_EQ(notificationPreferencesDatabase->GetKvFromDb(key, value, userId), NativeRdb::E_ERROR);
}

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
HWTEST_F(NotificationPreferencesDatabaseTest, GetKvFromDb_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";
    std::string value = "value";
    int32_t retCode = 0;

    EXPECT_EQ(notificationPreferencesDatabase->GetKvFromDb(key, value, userId, retCode), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetKvFromDb_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;
    std::string key = "key";
    std::string value = "value";
    int32_t retCode = 0;

    EXPECT_EQ(notificationPreferencesDatabase->GetKvFromDb(key, value, userId, retCode), NativeRdb::E_ERROR);
}
#endif

HWTEST_F(NotificationPreferencesDatabaseTest, GetBatchKvsFromDb_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";
    std::unordered_map<std::string, std::string> value;

    EXPECT_EQ(notificationPreferencesDatabase->GetBatchKvsFromDb(key, value, userId), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetBatchKvsFromDbContainsKey_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";
    std::unordered_map<std::string, std::string> value;

    EXPECT_EQ(notificationPreferencesDatabase->GetBatchKvsFromDbContainsKey(key, value, userId), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, DeleteKvFromDb_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string key = "key";

    EXPECT_EQ(notificationPreferencesDatabase->DeleteKvFromDb(key, userId), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, DropUserTable_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;

    EXPECT_EQ(notificationPreferencesDatabase->DropUserTable(userId), NativeRdb::E_ERROR);
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetAdditionalConfig_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    std::string key = "testKey";

    EXPECT_EQ(notificationPreferencesDatabase->GetAdditionalConfig(key), "");
}

HWTEST_F(NotificationPreferencesDatabaseTest, UpdateCloneToDisturbeDB_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;
    std::unordered_map<std::string, std::string> values;

    EXPECT_FALSE(notificationPreferencesDatabase->UpdateCloneToDisturbeDB(userId, values));
}

HWTEST_F(NotificationPreferencesDatabaseTest, UpdateCloneToDisturbeDB_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::unordered_map<std::string, std::string> values;
    values["test"] = "test";

    EXPECT_FALSE(notificationPreferencesDatabase->UpdateCloneToDisturbeDB(userId, values));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetCloneTimeStamp_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    int64_t timestamp = 100;

    EXPECT_FALSE(notificationPreferencesDatabase->SetCloneTimeStamp(userId, timestamp));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetAllDistribuedEnabledBundles_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    int32_t userId = 100;
    std::string deviceType = "device";
    std::vector<NotificationBundleOption> bundles;

    EXPECT_FALSE(notificationPreferencesDatabase->GetAllDistribuedEnabledBundles(userId, deviceType, bundles));
}

HWTEST_F(NotificationPreferencesDatabaseTest, SetHashCodeRule_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;
    uint32_t type = 1;

    EXPECT_FALSE(notificationPreferencesDatabase->SetHashCodeRule(userId, type));
}

HWTEST_F(NotificationPreferencesDatabaseTest, GetHashCodeRule_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t userId = 100;

    EXPECT_EQ(notificationPreferencesDatabase->GetHashCodeRule(userId), 0);
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedBundleOption_001, TestSize.Level0)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    notificationPreferencesDatabase->rdbDataManager_ = nullptr;
    auto bundle = std::make_shared<NotificationBundleOption>("newName", 20000);
    std::vector<sptr<DistributedBundleOption>> bundles;
    bundles.push_back(new DistributedBundleOption(bundle, true));
    std::string deviceType = "testDeviceType";
    int32_t userId = 12345;

    EXPECT_FALSE(notificationPreferencesDatabase->PutDistributedBundleOption(bundles, deviceType, userId));
}

HWTEST_F(NotificationPreferencesDatabaseTest, PutDistributedBundleOption_002, TestSize.Level0)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    std::vector<sptr<DistributedBundleOption>> bundles;
    std::string deviceType = "testDeviceType";
    int32_t userId = 12345;

    EXPECT_TRUE(notificationPreferencesDatabase->PutDistributedBundleOption(bundles, deviceType, userId));
}

/**
 * @tc.name: SetRingtoneInfoByBundle_0100
 * @tc.desc: test SetRingtoneInfoByBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetRingtoneInfoByBundle_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = preferncesDB_->SetRingtoneInfoByBundle(bundleInfo, ringtoneInfo);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: SetRingtoneInfoByBundle_0200
 * @tc.desc: test SetRingtoneInfoByBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetRingtoneInfoByBundle_0200, TestSize.Level1)
{
    preferncesDB_->rdbDataManager_ = nullptr;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("bundle");
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = preferncesDB_->SetRingtoneInfoByBundle(bundleInfo, ringtoneInfo);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: SetRingtoneInfoByBundle_0300
 * @tc.desc: test SetRingtoneInfoByBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetRingtoneInfoByBundle_0300, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("bundle");
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = preferncesDB_->SetRingtoneInfoByBundle(bundleInfo, ringtoneInfo);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: GetRingtoneInfoByBundle_0100
 * @tc.desc: test GetRingtoneInfoByBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetRingtoneInfoByBundle_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = preferncesDB_->GetRingtoneInfoByBundle(bundleInfo, ringtoneInfo);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetRingtoneInfoByBundle_0200
 * @tc.desc: test GetRingtoneInfoByBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetRingtoneInfoByBundle_0200, TestSize.Level1)
{
    preferncesDB_->rdbDataManager_ = nullptr;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("bundle");
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = preferncesDB_->GetRingtoneInfoByBundle(bundleInfo, ringtoneInfo);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetRingtoneInfoByBundle_0300
 * @tc.desc: test GetRingtoneInfoByBundle.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetRingtoneInfoByBundle_0300, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetBundleName("bundle");
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    auto ret = preferncesDB_->SetRingtoneInfoByBundle(bundleInfo, ringtoneInfo);
    ASSERT_EQ(ret, true);
    sptr<NotificationRingtoneInfo> info = new NotificationRingtoneInfo();
    ASSERT_NE(info, nullptr);
    auto res = preferncesDB_->GetRingtoneInfoByBundle(bundleInfo, info);
    ASSERT_EQ(res, true);
}

/**
 * @tc.name: SetGeofenceEnabled_0100
 * @tc.desc: Test SetGeofenceEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetGeofenceEnabled_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    bool ret = preferncesDB_->SetGeofenceEnabled(false);
    EXPECT_FALSE(ret);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
}

/**
 * @tc.name: SetGeofenceEnabled_0200
 * @tc.desc: Test SetGeofenceEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, SetGeofenceEnabled_0200, TestSize.Level1)
{
    preferncesDB_->rdbDataManager_ = nullptr;
    bool ret = preferncesDB_->SetGeofenceEnabled(true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsGeofenceEnabled_0100
 * @tc.desc: Test IsGeofenceEnabled
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTest, IsGeofenceEnabled_0100, TestSize.Level1)
{
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(-1);
    bool enabled = false;
    bool ret = preferncesDB_->IsGeofenceEnabled(enabled);
    EXPECT_FALSE(ret);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
}
}  // namespace Notification
}  // namespace OHOS
