/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rdb_errno.h"
#define private public
#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_preferences_database.h"
#undef private
#undef protected

extern void MockInit(bool mockRet);
extern void MockQueryData(bool mockRet);
extern void MockInsertData(bool mockRet);
extern void MockInsertBatchData(bool mockRet);
extern void MockQueryDataBeginWithKey(bool mockRet);
extern void MockDeleteBatchData(bool mockRet);
extern void MockDeleteData(bool mockRet);
extern void MockDropTable(bool mockRet);

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesDatabaseBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};

    std::unique_ptr<NotificationPreferencesDatabase> preferncesDB_ =
        std::make_unique<NotificationPreferencesDatabase>();
};

/**
 * @tc.name      : NotificationPreferences_00100
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is false
    MockInit(false);
    // test PutBundlePropertyToDisturbeDB function
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_00200
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and status is NativeRdb::E_EMPTY_VALUES_BUCKET
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_EMPTY_VALUES_BUCKET
    MockQueryData(false);
    // set PutBundleToDisturbeDB is false
    MockInsertData(false);
    // test PutBundlePropertyToDisturbeDB function
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_00300
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and status is NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test PutBundlePropertyToDisturbeDB function
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_00400
 * @tc.number    :
 * @tc.desc      : test CheckBundle function and status is NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00400, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test CheckBundle function
    std::string bundleName = "<bundleName>";
    int32_t bundleUid = 1;
    ASSERT_EQ(preferncesDB_->CheckBundle(bundleName, bundleUid), false);
}

/**
 * @tc.name      : NotificationPreferences_00500
 * @tc.number    :
 * @tc.desc      : test PutShowBadge function and CheckBundle is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00500, Function | SmallTest | Level1)
{
    // set GetBundleName is not empty
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test PutShowBadge function
    bool enable = true;
    ASSERT_EQ(preferncesDB_->PutShowBadge(bundleInfo, enable), false);
}

/**
 * @tc.name      : NotificationPreferences_00600
 * @tc.number    :
 * @tc.desc      : test PutImportance function and CheckBundle is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00600, Function | SmallTest | Level1)
{
    // set GetBundleName is not empty
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test PutImportance function
    int32_t importance = 1;
    ASSERT_EQ(preferncesDB_->PutImportance(bundleInfo, importance), false);
}

/**
 * @tc.name      : NotificationPreferences_00700
 * @tc.number    :
 * @tc.desc      : test PutTotalBadgeNums function and CheckBundle is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00700, Function | SmallTest | Level1)
{
    // set GetBundleName is not empty
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test PutTotalBadgeNums function
    int32_t totalBadgeNum = 1;
    ASSERT_EQ(preferncesDB_->PutTotalBadgeNums(bundleInfo, totalBadgeNum), false);
}

/**
 * @tc.name      : NotificationPreferences_00900
 * @tc.number    :
 * @tc.desc      : test PutNotificationsEnabledForBundle function and CheckBundle is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_00900, Function | SmallTest | Level1)
{
    // set GetBundleName is not empty
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test PutNotificationsEnabledForBundle function
    bool enabled = true;
    ASSERT_EQ(preferncesDB_->PutNotificationsEnabledForBundle(bundleInfo, enabled), false);
}

/**
 * @tc.name      : NotificationPreferences_01000
 * @tc.number    :
 * @tc.desc      : test PutNotificationsEnabled function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01000, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test PutNotificationsEnabled function
    int32_t userId = 1;
    bool enabled = true;
    ASSERT_EQ(preferncesDB_->PutNotificationsEnabled(userId, enabled), false);
}

/**
 * @tc.name      : NotificationPreferences_01100
 * @tc.number    :
 * @tc.desc      : test PutNotificationsEnabled function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01100, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockInsertData(false);
    // test PutNotificationsEnabled function
    int32_t userId = 1;
    bool enabled = true;
    ASSERT_EQ(preferncesDB_->PutNotificationsEnabled(userId, enabled), false);
}

/**
 * @tc.name      : NotificationPreferences_01200
 * @tc.number    :
 * @tc.desc      : test PutHasPoppedDialog function and CheckBundle is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test PutHasPoppedDialog function
    bool hasPopped = true;
    ASSERT_EQ(preferncesDB_->PutHasPoppedDialog(bundleInfo, hasPopped), false);
}

/**
 * @tc.name      : NotificationPreferences_01300
 * @tc.number    :
 * @tc.desc      : test PutDoNotDisturbDate function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01300, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test PutDoNotDisturbDate function
    int32_t userId = 1;
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
    ASSERT_EQ(preferncesDB_->PutDoNotDisturbDate(userId, date), false);
}

/**
 * @tc.name      : NotificationPreferences_01400
 * @tc.number    :
 * @tc.desc      : test PutDoNotDisturbDate function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01400, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockInsertBatchData(false);
    // test PutDoNotDisturbDate function
    int32_t userId = 1;
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
    ASSERT_EQ(preferncesDB_->PutDoNotDisturbDate(userId, date), false);
}

/**
 * @tc.name      : NotificationPreferences_01500
 * @tc.number    :
 * @tc.desc      : test GetValueFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01500, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test GetValueFromDisturbeDB function
    std::string key = "<key>";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetValueFromDisturbeDB(key, -1, [&](std::string &value) {});
}

/**
 * @tc.name      : NotificationPreferences_01600
 * @tc.number    :
 * @tc.desc      : test GetValueFromDisturbeDB function and result == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01600, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result == NativeRdb::E_ERROR
    MockQueryData(true);
    // test GetValueFromDisturbeDB function
    std::string key = "<key>";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetValueFromDisturbeDB(key, -1, [&](std::string &value) {});
}

/**
 * @tc.name      : NotificationPreferences_01700
 * @tc.number    :
 * @tc.desc      : test GetValueFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01700, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test GetValueFromDisturbeDB function
    std::string key = "<key>";
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetValueFromDisturbeDB(key, -1, [&](const int32_t &status, std::string &value) {});
}

/**
 * @tc.name      : NotificationPreferences_01800
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyValueToDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01800, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test PutBundlePropertyValueToDisturbeDB function
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_NE(nullptr, preferncesDB_);
    ASSERT_EQ(preferncesDB_->PutBundlePropertyValueToDisturbeDB(bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_01900
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyValueToDisturbeDB function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_01900, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockInsertBatchData(false);
    // test PutBundlePropertyValueToDisturbeDB function
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_EQ(preferncesDB_->PutBundlePropertyValueToDisturbeDB(bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_02000
 * @tc.number    :
 * @tc.desc      : test ParseFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02000, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test ParseFromDisturbeDB function
    NotificationPreferencesInfo info;
    ASSERT_EQ(preferncesDB_->ParseFromDisturbeDB(info), false);
}

/**
 * @tc.name      : NotificationPreferences_02100
 * @tc.number    :
 * @tc.desc      : test ParseFromDisturbeDB function and result == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02100, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result == NativeRdb::E_ERROR
    MockQueryDataBeginWithKey(false);
    // test ParseFromDisturbeDB function
    NotificationPreferencesInfo info;
    ASSERT_EQ(preferncesDB_->ParseFromDisturbeDB(info), true);
}

/**
 * @tc.name      : NotificationPreferences_02200
 * @tc.number    :
 * @tc.desc      : test RemoveAllDataFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02200, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    ASSERT_EQ(preferncesDB_->RemoveAllDataFromDisturbeDB(), false);
}

/**
 * @tc.name      : NotificationPreferences_02300
 * @tc.number    :
 * @tc.desc      : test RemoveBundleFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02300, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test RemoveBundleFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    const int32_t uid = -1;
    ASSERT_EQ(preferncesDB_->RemoveBundleFromDisturbeDB(bundleKey, uid), false);
}

/**
 * @tc.name      : NotificationPreferences_02400
 * @tc.number    :
 * @tc.desc      : test RemoveBundleFromDisturbeDB function and result == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02400, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result == NativeRdb::E_ERROR
    MockQueryDataBeginWithKey(false);
    // test RemoveBundleFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    const int32_t uid = -1;
    ASSERT_EQ(preferncesDB_->RemoveBundleFromDisturbeDB(bundleKey, uid), false);
}

/**
 * @tc.name      : NotificationPreferences_02500
 * @tc.number    :
 * @tc.desc      : test RemoveBundleFromDisturbeDB function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02500, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_ERROR
    MockQueryDataBeginWithKey(true);
    // set result != NativeRdb::E_OK
    MockDeleteBatchData(false);
    // test RemoveBundleFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->RemoveBundleFromDisturbeDB(bundleKey, -1), false);
}

/**
 * @tc.name      : NotificationPreferences_02600
 * @tc.number    :
 * @tc.desc      : test RemoveSlotFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02600, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test RemoveSlotFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    NotificationConstant::SlotType type = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    ASSERT_EQ(preferncesDB_->RemoveSlotFromDisturbeDB(bundleKey, type, -1), false);
}

/**
 * @tc.name      : NotificationPreferences_02700
 * @tc.number    :
 * @tc.desc      : test RemoveSlotFromDisturbeDB function and result == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02700, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result == NativeRdb::E_ERROR
    MockQueryDataBeginWithKey(false);
    // test RemoveSlotFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    NotificationConstant::SlotType type = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    ASSERT_EQ(preferncesDB_->RemoveSlotFromDisturbeDB(bundleKey, type, -1), false);
}

/**
 * @tc.name      : NotificationPreferences_02800
 * @tc.number    :
 * @tc.desc      : test RemoveSlotFromDisturbeDB function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02800, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_ERROR
    MockQueryDataBeginWithKey(true);
    // set result != NativeRdb::E_OK
    MockDeleteBatchData(false);
    // test RemoveSlotFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    NotificationConstant::SlotType type = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    ASSERT_EQ(preferncesDB_->RemoveSlotFromDisturbeDB(bundleKey, type, -1), false);
}

/**
 * @tc.name      : NotificationPreferences_02900
 * @tc.number    :
 * @tc.desc      : test RemoveAllSlotsFromDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_02900, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test RemoveAllSlotsFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->RemoveAllSlotsFromDisturbeDB(bundleKey, -1), false);
}

/**
 * @tc.name      : NotificationPreferences_03000
 * @tc.number    :
 * @tc.desc      : test RemoveAllSlotsFromDisturbeDB function and result == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03000, Function | SmallTest | Level1)
{
    // set CheckKvStore is true
    MockInit(true);
    // set result == NativeRdb::E_ERROR
    MockQueryDataBeginWithKey(false);
    // test RemoveAllSlotsFromDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->RemoveAllSlotsFromDisturbeDB(bundleKey, -1), false);
}

/**
 * @tc.name      : NotificationPreferences_03100
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and type is BUNDLE_BADGE_TOTAL_NUM_TYPE
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03100, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // set type is BUNDLE_BADGE_TOTAL_NUM_TYPE
    BundleType type = BundleType::BUNDLE_BADGE_TOTAL_NUM_TYPE;
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleKey, type, true, 0), false);
}

/**
 * @tc.name      : NotificationPreferences_03200
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and type is BUNDLE_IMPORTANCE_TYPE
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03200, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // set type is BUNDLE_BADGE_TOTAL_NUM_TYPE
    BundleType type = BundleType::BUNDLE_IMPORTANCE_TYPE;
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleKey, type, true, 0), false);
}

/**
 * @tc.name      : NotificationPreferences_03300
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and type is BUNDLE_SHOW_BADGE_TYPE
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03300, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // set type is BUNDLE_SHOW_BADGE_TYPE
    BundleType type = BundleType::BUNDLE_SHOW_BADGE_TYPE;
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleKey, type, true, 0), false);
}

/**
 * @tc.name      : NotificationPreferences_03500
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and type is BUNDLE_ENABLE_NOTIFICATION_TYPE
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03500, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // set type is BUNDLE_ENABLE_NOTIFICATION_TYPE
    BundleType type = BundleType::BUNDLE_ENABLE_NOTIFICATION_TYPE;
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleKey, type, true, 0), false);
}

/**
 * @tc.name      : NotificationPreferences_03600
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and type is BUNDLE_POPPED_DIALOG_TYPE
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03600, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // set type is BUNDLE_POPPED_DIALOG_TYPE
    BundleType type = BundleType::BUNDLE_POPPED_DIALOG_TYPE;
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleKey, type, true, 0), false);
}

/**
 * @tc.name      : NotificationPreferences_03700
 * @tc.number    :
 * @tc.desc      : test PutBundlePropertyToDisturbeDB function and type is BUNDLE_NAME_TYPE
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03700, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // set type is BUNDLE_NAME_TYPE
    BundleType type = BundleType::BUNDLE_NAME_TYPE;
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    ASSERT_EQ(preferncesDB_->PutBundlePropertyToDisturbeDB(bundleKey, type, true, 0), false);
}

/**
 * @tc.name      : NotificationPreferences_03800
 * @tc.number    :
 * @tc.desc      : test PutBundleToDisturbeDB function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03800, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockInsertData(false);
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_EQ(preferncesDB_->PutBundleToDisturbeDB(bundleKey, bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_03900
 * @tc.number    :
 * @tc.desc      : test PutBundleToDisturbeDB function and PutBundlePropertyValueToDisturbeDB is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_03900, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result == NativeRdb::E_OK
    MockInsertData(true);
    // set PutBundlePropertyValueToDisturbeDB is false
    MockInsertBatchData(false);
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_EQ(preferncesDB_->PutBundleToDisturbeDB(bundleKey, bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_04000
 * @tc.number    :
 * @tc.desc      : test PutBundleToDisturbeDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04000, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test PutBundlePropertyToDisturbeDB function
    std::string bundleKey = "<bundleKey>";
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_EQ(preferncesDB_->PutBundleToDisturbeDB(bundleKey, bundleInfo), false);
}

/**
 * @tc.name      : NotificationPreferences_04100
 * @tc.number    :
 * @tc.desc      : test SlotToEntry function and CheckBundle is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set CheckBundle is false
    MockQueryData(true);
    // test SlotToEntry function
    std::string bundleName = "<bundleName>";
    int32_t bundleUid = 1;
    sptr<NotificationSlot> slot = new NotificationSlot();
    std::unordered_map<std::string, std::string> values;
    ASSERT_EQ(preferncesDB_->SlotToEntry(bundleName, bundleUid, slot, values), false);
}

/**
 * @tc.name      : NotificationPreferences_04200
 * @tc.number    :
 * @tc.desc      : test PutSlotsToDisturbeDB function and result is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string name = "<SetBundleName>";
    bundleInfo.SetBundleName(name);
    // set CheckRdbStore is true
    MockInit(true);
    // set CheckBundle is false
    MockQueryData(true);
    // test PutSlotsToDisturbeDB function
    std::string bundleName = "<bundleName>";
    int32_t bundleUid = 1;
    sptr<NotificationSlot> slot = new NotificationSlot();
    std::vector<sptr<NotificationSlot>> slots;
    slots.emplace_back(slot);
    ASSERT_EQ(preferncesDB_->PutSlotsToDisturbeDB(bundleName, bundleUid, slots), false);
}

/**
 * @tc.name      : NotificationPreferences_04300
 * @tc.number    :
 * @tc.desc      : test ParseBundleFromDistureDB function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04300, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    NotificationPreferencesInfo info;
    std::unordered_map<std::string, std::string> values;
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->ParseBundleFromDistureDB(info, values, -1);
}

/**
 * @tc.name      : NotificationPreferences_04400
 * @tc.number    :
 * @tc.desc      : test FindLastString function and pos == std::string::npos
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04400, Function | SmallTest | Level1)
{
    std::string findString = "";
    std::string inputString = "";
    ASSERT_EQ(preferncesDB_->FindLastString(findString, inputString), "");
}

/**
 * @tc.name      : NotificationPreferences_04500
 * @tc.number    :
 * @tc.desc      : test StringToInt function and str is empty
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04500, Function | SmallTest | Level1)
{
    std::string str = "";
    ASSERT_EQ(preferncesDB_->StringToInt(str), 0);
}

/**
 * @tc.name      : NotificationPreferences_04600
 * @tc.number    :
 * @tc.desc      : test StringToInt64 function and str is empty
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04600, Function | SmallTest | Level1)
{
    std::string str = "";
    ASSERT_EQ(preferncesDB_->StringToInt64(str), 0);
}

/**
 * @tc.name      : NotificationPreferences_04700
 * @tc.number    :
 * @tc.desc      : test GetDoNotDisturbType function and status == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04700, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test GetDoNotDisturbType function
    NotificationPreferencesInfo info;
    int32_t userId = 1;
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetDoNotDisturbType(info, userId);
}

/**
 * @tc.name      : NotificationPreferences_04800
 * @tc.number    :
 * @tc.desc      : test GetDoNotDisturbBeginDate function and status == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04800, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test GetDoNotDisturbBeginDate function
    NotificationPreferencesInfo info;
    int32_t userId = 1;
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetDoNotDisturbBeginDate(info, userId);
}

/**
 * @tc.name      : NotificationPreferences_04900
 * @tc.number    :
 * @tc.desc      : test GetDoNotDisturbEndDate function and status == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_04900, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test GetDoNotDisturbEndDate function
    NotificationPreferencesInfo info;
    int32_t userId = 1;
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetDoNotDisturbEndDate(info, userId);
}

/**
 * @tc.name      : NotificationPreferences_05000
 * @tc.number    :
 * @tc.desc      : test GetEnableAllNotification function and status == NativeRdb::E_ERROR
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05000, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set status is NativeRdb::E_ERROR
    MockQueryData(true);
    // test GetEnableAllNotification function
    NotificationPreferencesInfo info;
    int32_t userId = 1;
    ASSERT_NE(nullptr, preferncesDB_);
    preferncesDB_->GetEnableAllNotification(info, userId);
}

/**
 * @tc.name      : NotificationPreferences_05100
 * @tc.number    :
 * @tc.desc      : test RemoveNotificationEnable function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05100, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test RemoveNotificationEnable function
    int32_t userId = 1;
    ASSERT_EQ(preferncesDB_->RemoveNotificationEnable(userId), false);
}

/**
 * @tc.name      : NotificationPreferences_05200
 * @tc.number    :
 * @tc.desc      : test RemoveNotificationEnable function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05200, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockDeleteData(false);
    // test RemoveNotificationEnable function
    int32_t userId = 1;
    ASSERT_EQ(preferncesDB_->RemoveNotificationEnable(userId), false);
}

/**
 * @tc.name      : NotificationPreferences_05300
 * @tc.number    :
 * @tc.desc      : test RemoveDoNotDisturbDate function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05300, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test RemoveDoNotDisturbDate function
    int32_t userId = 1;
    ASSERT_EQ(preferncesDB_->RemoveDoNotDisturbDate(userId), false);
}

/**
 * @tc.name      : NotificationPreferences_05400
 * @tc.number    :
 * @tc.desc      : test RemoveDoNotDisturbDate function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05400, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockDeleteBatchData(false);
    // test RemoveDoNotDisturbDate function
    int32_t userId = 1;
    ASSERT_EQ(preferncesDB_->RemoveDoNotDisturbDate(userId), false);
}

/**
 * @tc.name      : NotificationPreferences_05500
 * @tc.number    :
 * @tc.desc      : test RemoveAnsBundleDbInfo function and CheckRdbStore is false
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05500, Function | SmallTest | Level1)
{
    // set CheckRdbStore is false
    MockInit(false);
    // test RemoveAnsBundleDbInfo function
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    ASSERT_EQ(preferncesDB_->RemoveAnsBundleDbInfo(bundleName, userId), false);
}

/**
 * @tc.name      : NotificationPreferences_05600
 * @tc.number    :
 * @tc.desc      : test RemoveAnsBundleDbInfo function and result != NativeRdb::E_OK
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05600, Function | SmallTest | Level1)
{
    // set CheckRdbStore is true
    MockInit(true);
    // set result != NativeRdb::E_OK
    MockDeleteData(false);
    // test RemoveAnsBundleDbInfo function
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    ASSERT_EQ(preferncesDB_->RemoveAnsBundleDbInfo(bundleName, userId), false);
}

/**
 * @tc.name      : NotificationPreferences_05700
 * @tc.number    :
 * @tc.desc      : Test set k-v to db
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05700, Function | SmallTest | Level1)
{
    MockInit(true);
    MockInsertData(false);
    ASSERT_EQ(preferncesDB_->SetKvToDb(string("test"), string("test"), -1), NativeRdb::E_ERROR);
    MockInsertData(true);
    ASSERT_EQ(preferncesDB_->SetKvToDb(string("test"), string("test"), -1), NativeRdb::E_OK);
}

/**
 * @tc.name      : NotificationPreferences_05701
 * @tc.number    :
 * @tc.desc      : Test get k-v from db
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05701, Function | SmallTest | Level1)
{
    MockInit(true);
    MockQueryData(false);
    string value;
    ASSERT_EQ(preferncesDB_->GetKvFromDb(string("test"), value, -1), NativeRdb::E_ERROR);
    MockQueryData(true);
    ASSERT_EQ(preferncesDB_->GetKvFromDb(string("test"), value, -1), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : NotificationPreferences_05702
 * @tc.number    :
 * @tc.desc      : Test batch get kv from db
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05702, Function | SmallTest | Level1)
{
    MockInit(true);
    MockQueryDataBeginWithKey(false);
    std::unordered_map<std::string, std::string> value;
    ASSERT_EQ(preferncesDB_->GetBatchKvsFromDb(string("test"), value, -1), NativeRdb::E_ERROR);
    MockQueryDataBeginWithKey(true);
    ASSERT_EQ(preferncesDB_->GetBatchKvsFromDb(string("test"), value, -1), NativeRdb::E_OK);
}

/**
 * @tc.name      : NotificationPreferences_05703
 * @tc.number    :
 * @tc.desc      : Test batch get kv from db
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, NotificationPreferences_05703, Function | SmallTest | Level1)
{
    MockInit(true);
    MockDeleteData(false);
    std::unordered_map<std::string, std::string> value;
    ASSERT_EQ(preferncesDB_->DeleteKvFromDb(string("test"), -1), NativeRdb::E_ERROR);
    MockDeleteData(true);
    ASSERT_EQ(preferncesDB_->DeleteKvFromDb(string("test"), -1), NativeRdb::E_OK);
}

/**
 * @tc.name      : DropUserTable_00100
 * @tc.number    :
 * @tc.desc      : Test DropUserTable
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, DropUserTable_00100, Function | SmallTest | Level1)
{
    MockInit(true);
    MockDropTable(true);
    ASSERT_EQ(preferncesDB_->DropUserTable(-1), NativeRdb::E_OK);
}

/**
 * @tc.name      : DropUserTable_00200
 * @tc.number    :
 * @tc.desc      : Test DropUserTable
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, DropUserTable_00200, Function | SmallTest | Level1)
{
    MockInit(true);
    MockDropTable(false);
    ASSERT_EQ(preferncesDB_->DropUserTable(-1), NativeRdb::E_ERROR);
}

/**
 * @tc.name      : PutSlotFlags_00100
 * @tc.number    :
 * @tc.desc      : Put bundle total badge nums into disturbe DB, return is true.
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, PutSlotFlags_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_EQ(preferncesDB_->PutSlotFlags(bundleInfo, 0), true);
}

/**
 * @tc.name      : IsAgentRelationship_00100
 * @tc.number    : IsAgentRelationship_00100
 * @tc.desc      : test IsAgentRelationship.
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, IsAgentRelationship_00100, Function | SmallTest | Level1)
{
    std::string agent = "agent";
    std::string source = "source";
    ASSERT_EQ(preferncesDB_->IsAgentRelationship(agent, source), false);
}

/**
 * @tc.name      : GetAdditionalConfig_00100
 * @tc.number    : GetAdditionalConfig_00100
 * @tc.desc      : test GetAdditionalConfig.
 */
HWTEST_F(NotificationPreferencesDatabaseBranchTest, GetAdditionalConfig_00100, Function | SmallTest | Level1)
{
    std::string key = "key";
    ASSERT_EQ(preferncesDB_->GetAdditionalConfig(key), "");
}

}  // namespace Notification
}  // namespace OHOS
