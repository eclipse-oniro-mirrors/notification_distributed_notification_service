/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <chrono>
#include <thread>
#include <set>
#define private public
#define protected public
#include "notification_clone_disturb_service.h"
#include "notification_preferences_info.h"
#include "notification_do_not_disturb_profile.h"
#include "ans_inner_errors.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "mock_notification_clone_util.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::SetArgPointee;
using ::testing::Return;
using ::testing::DoAll;
using namespace OHOS;
using namespace Notification;

// Test suite class
class NotificationCloneDisturbTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize objects and dependencies
        notificationCloneDisturb = new NotificationCloneDisturb();
        int32_t initTestUserId = 100;
        int32_t initTestUid = 1000;
        MockSetActiveUserIdForClone(initTestUserId);
        MockSetBundleUidForClone(initTestUid);
        SetFuncGetActiveUserIdIsCalled(false);
        SetFuncGetBundleUidIsCalled(false);
    }

    void TearDown() override
    {
        // Clean up resources
        delete notificationCloneDisturb;
        notificationCloneDisturb = nullptr;
    }

    NotificationCloneDisturb* notificationCloneDisturb;
};

/**
 * @tc.name: OnBackUp_00001
 * @tc.desc: Test clone OnBackUp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnBackUp_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    int32_t userId = 100;
    auto advancedNotificationService_ = AdvancedNotificationService::GetInstance();

    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->AddDoNotDisturbProfiles(profiles);
    
    ErrCode result = notificationCloneDisturb->OnBackup(jsonObject);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OnBackUp_00002
 * @tc.desc: Test clone OnBackUp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnBackUp_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    int32_t userId = 100;
    auto advancedNotificationService_ = AdvancedNotificationService::GetInstance();

    sptr<NotificationDoNotDisturbProfile> date = new NotificationDoNotDisturbProfile();
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->AddDoNotDisturbProfiles(profiles);
    
    ErrCode result = notificationCloneDisturb->OnBackup(jsonObject);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OnRestore_00001
 * @tc.desc: Test clone OnRestore jsonObject is wrong type.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestore_00001, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonNull;
    nlohmann::json jsonObject = nlohmann::json::object();

    // When
    std::set<std::string> systemApps;
    notificationCloneDisturb->OnRestore(jsonNull, systemApps);
    notificationCloneDisturb->OnRestore(jsonObject, systemApps);

    // Then
    EXPECT_FALSE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_00002
 * @tc.desc: Test clone OnRestore when cloneDisturbQueue_ is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestore_00002, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    sptr<NotificationDoNotDisturbProfile> profile = new NotificationDoNotDisturbProfile();
    nlohmann::json jsonNode;
    jsonNode = profile->ToJson();
    jsonArray.emplace_back(jsonNode);
    notificationCloneDisturb->profiles_.emplace_back(profile);
    notificationCloneDisturb->cloneDisturbQueue_ == nullptr;

    // When
    std::set<std::string> systemApps;
    notificationCloneDisturb->OnRestore(jsonArray, systemApps);

    // Then
    EXPECT_FALSE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnRestore_00003
 * @tc.desc: Test clone OnRestore when profiles_ is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestore_00003, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();

    // When
    std::set<std::string> systemApps;
    notificationCloneDisturb->OnRestore(jsonArray, systemApps);

    // Then
    EXPECT_TRUE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnRestore_00004
 * @tc.desc: Test clone OnRestore when Bundle exists.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestore_00004, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    sptr<NotificationDoNotDisturbProfile> profile = new NotificationDoNotDisturbProfile();
    profile->SetProfileTrustList({{"testBundleName", 1}});
    nlohmann::json jsonNode = nlohmann::json::parse(profile->ToJson());
    jsonArray.emplace_back(jsonNode);
    notificationCloneDisturb->profiles_.emplace_back(profile);

    // When
    std::set<std::string> systemApps;
    systemApps.insert("testBundleName");
    notificationCloneDisturb->OnRestore(jsonArray, systemApps);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    // Then
    EXPECT_TRUE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnRestore_00005
 * @tc.desc: Test clone OnRestore when Bundle exists.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestore_00005, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    sptr<NotificationDoNotDisturbProfile> profile = new NotificationDoNotDisturbProfile();
    profile->SetProfileTrustList({{"testBundleName", 1}});
    nlohmann::json jsonNode = nlohmann::json::parse(profile->ToJson());
    jsonArray.emplace_back(jsonNode);
    notificationCloneDisturb->profiles_.emplace_back(profile);
    int32_t invalidUid = -1;
    MockSetBundleUidForClone(invalidUid);

    // When
    std::set<std::string> systemApps;
    notificationCloneDisturb->OnRestore(jsonArray, systemApps);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    // Then
    EXPECT_FALSE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: GetProfileUid_Test_001
 * @tc.desc: Test that the function sets the UID from uidMap when the key exists in uidMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, GetProfileUid_Test_001, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    std::set<std::string> systemApps;
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> exitBunldleList;
    std::vector<NotificationBundleOption> notExitBunldleList;

    // Create a bundle with a known key
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    trustList.push_back(bundle);
    systemApps.insert("com.example.app");
    notificationCloneDisturb->GetProfileUid(userId, systemApps, trustList, exitBunldleList, notExitBunldleList);

    EXPECT_EQ(exitBunldleList.size(), 1);
    EXPECT_EQ(notExitBunldleList.size(), 0);
}

/**
 * @tc.name: GetProfileUid_Test_002
 * @tc.desc: Test that the function sets the UID from uidMap when the key exists in uidMap.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, GetProfileUid_Test_002, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    std::set<std::string> systemApps;
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> exitBunldleList;
    std::vector<NotificationBundleOption> notExitBunldleList;
    int32_t invalidUid = -1;
    MockSetBundleUidForClone(invalidUid);

    // Create a bundle with an unknown key
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    trustList.push_back(bundle);
    notificationCloneDisturb->GetProfileUid(userId, systemApps, trustList, exitBunldleList, notExitBunldleList);

    EXPECT_EQ(exitBunldleList.size(), 0);
    EXPECT_EQ(notExitBunldleList.size(), 1);
}

/**
 * @tc.name: OnRestoreStart_Test_001
 * @tc.desc: Test OnRestoreStart function when profiles_ is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_001, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;

    // Ensure profiles_ is empty
    notificationCloneDisturb->profiles_.clear();

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Verify that the function returned without any action
    EXPECT_TRUE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnRestoreStart_Test_002
 * @tc.desc: Test OnRestoreStart function when cloneDisturbQueue_ is null
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_002, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;
    sptr<NotificationDoNotDisturbProfile> profile = new NotificationDoNotDisturbProfile();
    notificationCloneDisturb->profiles_.emplace_back(profile);

    // Ensure cloneDisturbQueue_ is null
    notificationCloneDisturb->cloneDisturbQueue_ = nullptr;

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Verify that the function returned without any action
    EXPECT_EQ(notificationCloneDisturb->cloneDisturbQueue_, nullptr);
}

/**
 * @tc.name: OnRestoreStart_Test_003
 * @tc.desc: Test OnRestoreStart function when trustList is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_003, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;
    sptr<NotificationDoNotDisturbProfile> profile = new NotificationDoNotDisturbProfile();
    notificationCloneDisturb->profiles_.emplace_back(profile);

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    // Verify that the profile is deleted
    EXPECT_TRUE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnRestoreStart_Test_004
 * @tc.desc: Test OnRestoreStart function when trustList is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnRestoreStart_Test_004, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.app";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 12345;
    sptr<NotificationDoNotDisturbProfile> profile = new NotificationDoNotDisturbProfile();
    profile->SetProfileTrustList({{}});
    notificationCloneDisturb->profiles_.emplace_back(profile);

    // Call the function
    notificationCloneDisturb->OnRestoreStart(bundleName, appIndex, userId, uid);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    // Verify that the profile is deleted
    EXPECT_FALSE(notificationCloneDisturb->profiles_.empty());
}

/**
 * @tc.name: OnUserSwitch_Test_001
 * @tc.desc: Test OnUserSwitch function when cloneDisturbQueue_ is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, OnUserSwitch_Test_001, Function | SmallTest | Level1)
{
    // Ensure cloneDisturbQueue_ is not null
    notificationCloneDisturb->cloneDisturbQueue_ = nullptr;

    // Call the function
    notificationCloneDisturb->OnUserSwitch(100);

    // Verify that the profile is deleted
    EXPECT_EQ(notificationCloneDisturb->cloneDisturbQueue_, nullptr);
}

/**
 * @tc.name: CheckBundleInfo_Test_001
 * @tc.desc: Test that when a matching bundle is found in trustList, it is added to bundleList and
 *           removed from trustList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, CheckBundleInfo_Test_001, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> bundleList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    NotificationBundleOption matchingBundle;
    matchingBundle.SetBundleName("com.example.app");
    matchingBundle.SetAppIndex(1);
    trustList.push_back(matchingBundle);

    notificationCloneDisturb->CheckBundleInfo(trustList, bundleList, bundle);

    EXPECT_EQ(bundleList.size(), 1);
    EXPECT_EQ(trustList.size(), 0);
    EXPECT_EQ(bundleList[0].GetBundleName(), "com.example.app");
    EXPECT_EQ(bundleList[0].GetAppIndex(), 1);
}

/**
 * @tc.name: CheckBundleInfo_Test_002
 * @tc.desc: Test that when no matching bundle is found in trustList, the bundle is not added to bundleList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, CheckBundleInfo_Test_002, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> bundleList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    NotificationBundleOption nonMatchingBundle;
    nonMatchingBundle.SetBundleName("com.example.other");
    nonMatchingBundle.SetAppIndex(2);
    trustList.push_back(nonMatchingBundle);

    notificationCloneDisturb->CheckBundleInfo(trustList, bundleList, bundle);

    EXPECT_EQ(bundleList.size(), 0);
    EXPECT_EQ(trustList.size(), 1);
}

/**
 * @tc.name: CheckBundleInfo_Test_003
 * @tc.desc: Test that when trustList is empty, the bundle is not added to bundleList.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneDisturbTest, CheckBundleInfo_Test_003, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> trustList;
    std::vector<NotificationBundleOption> bundleList;
    NotificationBundleOption bundle;
    bundle.SetBundleName("com.example.app");
    bundle.SetAppIndex(1);

    notificationCloneDisturb->CheckBundleInfo(trustList, bundleList, bundle);

    EXPECT_EQ(bundleList.size(), 0);
    EXPECT_EQ(trustList.size(), 0);
}
