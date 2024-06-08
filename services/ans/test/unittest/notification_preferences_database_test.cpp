/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesDatabaseTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
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
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo, true));
    EXPECT_TRUE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo, false));
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
    EXPECT_FALSE(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo, false));
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
    ASSERT_EQ(true, preferncesDB_->RemoveBundleFromDisturbeDB(bundleName_, uid));
}

/**
 * @tc.name      : RemoveBundleFromDisturbeDB_00200
 * @tc.number    :
 * @tc.desc      : Remove a bundle info from disturbe DB when bundle name is null, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseTest, RemoveBundleFromDisturbeDB_00200, Function | SmallTest | Level1)
{
    const int32_t uid = -1;
    ASSERT_EQ(true, preferncesDB_->RemoveBundleFromDisturbeDB(std::string(), uid));
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
    ASSERT_EQ(true, preferncesDB_->PutBundlePropertyValueToDisturbeDB(info));
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
    ASSERT_EQ(true, preferncesDB_->CheckBundle(bundleName_, bundleUid_));
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
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo), true);
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
    ASSERT_EQ(preferncesDB_->RemoveAllSlotsFromDisturbeDB(bundleKey, -1), true);
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
    ASSERT_EQ(preferncesDB_->RemoveNotificationEnable(userId), true);
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
    ASSERT_EQ(preferncesDB_->RemoveDoNotDisturbDate(userId), true);
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
    ASSERT_EQ(preferncesDB_->PutDoNotDisturbDate(userId, nullptr), false);
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
    ASSERT_EQ(preferncesDB_->RemoveAllSlotsFromDisturbeDB(bundleKey, -1), false);
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
    ASSERT_EQ(preferncesDB_->SlotToEntry(bundleName_, bundleUid_, nullptr, values), false);
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
    ASSERT_EQ(ret, true);
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
    ASSERT_EQ(result, true);
}

/**
 * @tc.name      : GetAllNotificationEnabledBundles_00100
 * @tc.number    : GetAllNotificationEnabledBundles
 * @tc.desc      : Check func GetAllNotificationEnabledBundles,no data in db return false
 */
HWTEST_F(NotificationPreferencesDatabaseTest, GetAllNotificationEnabledBundles_00100, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> bundleOption;
    ASSERT_EQ(false, preferncesDB_->GetAllNotificationEnabledBundles(bundleOption));
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
    ASSERT_EQ(preferncesDB_->RemoveAnsBundleDbInfo(bundleName, uid), true);
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
    ASSERT_EQ(ret, "enabledNotificationDistributed-name-1-test");
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
    ASSERT_EQ(ret, true);
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
    ASSERT_EQ(ret, false);
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
    ASSERT_EQ(result, true);
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
    ASSERT_EQ(result, false);
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
    ASSERT_EQ(res, true);
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
    ASSERT_EQ(res, true);
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
    ASSERT_EQ(res, false);
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
    ASSERT_EQ(res, false);
}
}  // namespace Notification
}  // namespace OHOS
