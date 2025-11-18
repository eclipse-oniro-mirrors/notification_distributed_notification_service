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
#include <set>
#define private public
#define protected public
#include "notification_clone_bundle_service.h"
#include "notification_do_not_disturb_profile.h"
#include "ans_inner_errors.h"
#include "notification_clone_util.h"
#include "advanced_notification_service.h"
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
class NotificationCloneBundleTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize objects and dependencies
        notificationCloneBundle = new NotificationCloneBundle();
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
        delete notificationCloneBundle;
        notificationCloneBundle = nullptr;
    }

    NotificationCloneBundle* notificationCloneBundle;
};

/**
 * @tc.name: OnBackUp_00001
 * @tc.desc: Test clone OnBackUp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnBackUp_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    ErrCode result = notificationCloneBundle->OnBackup(jsonObject);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OnRestore_Test_00001
 * @tc.desc: Test that OnRestore does nothing when input param has wrong type.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestore_Test_00001, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonNull;
    nlohmann::json jsonObject = nlohmann::json::object();

    // When
    std::set<std::string> systemApps;
    notificationCloneBundle->OnRestore(jsonNull, systemApps);
    notificationCloneBundle->OnRestore(jsonObject, systemApps);

    // Then
    EXPECT_FALSE(GetFuncGetActiveUserIdIsCalled());
}

/**
 * @tc.name: OnRestore_Test_00002
 * @tc.desc: Test OnRestore when task queue is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestore_Test_00002, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundleInfo;
    nlohmann::json jsonNode;
    cloneBundleInfo.ToJson(jsonNode);
    jsonArray.emplace_back(jsonNode);
    notificationCloneBundle->bundlesInfo_.emplace_back(cloneBundleInfo);
    notificationCloneBundle->cloneBundleQueue_ = nullptr;

    // When
    std::set<std::string> systemApps;
    notificationCloneBundle->OnRestore(jsonArray, systemApps);

    // Then
    EXPECT_TRUE(GetFuncGetActiveUserIdIsCalled());
    EXPECT_FALSE(notificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestore_Test_00003
 * @tc.desc: Test OnRestore when task bundlesInfo_ is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestore_Test_00003, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();

    // When
    std::set<std::string> systemApps;
    notificationCloneBundle->OnRestore(jsonArray, systemApps);

    // Then
    EXPECT_TRUE(notificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestore_Test_00004
 * @tc.desc: Test OnRestore when bundle doesn't exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestore_Test_00004, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetBundleName("com.ohos.demo");
    nlohmann::json jsonNode;
    cloneBundleInfo.ToJson(jsonNode);
    jsonArray.emplace_back(jsonNode);
    notificationCloneBundle->bundlesInfo_.emplace_back(cloneBundleInfo);
    int32_t invalidUid = -1;
    MockSetBundleUidForClone(invalidUid);

    // When
    std::set<std::string> systemApps;
    systemApps.insert("com.ohos.demo");
    notificationCloneBundle->OnRestore(jsonArray, systemApps);

    // Then
    EXPECT_TRUE(GetFuncGetActiveUserIdIsCalled());
    EXPECT_TRUE(GetFuncGetBundleUidIsCalled());
}

/**
 * @tc.name: OnRestore_Test_00005
 * @tc.desc: Test OnRestore when bundle exists.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestore_Test_00005, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetBundleName("com.ohos.demo");
    nlohmann::json jsonNode;
    cloneBundleInfo.ToJson(jsonNode);
    jsonArray.emplace_back(jsonNode);
    notificationCloneBundle->bundlesInfo_.emplace_back(cloneBundleInfo);
    int32_t initTestUid = 1000;
    MockSetBundleUidForClone(initTestUid);

    // When
    std::set<std::string> systemApps;
    systemApps.insert("com.ohos.demo");
    notificationCloneBundle->OnRestore(jsonArray, systemApps);

    // Then
    EXPECT_TRUE(GetFuncGetActiveUserIdIsCalled());
    EXPECT_TRUE(GetFuncGetBundleUidIsCalled());
}

/**
 * @tc.name: OnRestoreStart_Test_001
 * @tc.desc: Test that OnRestoreStart does nothing when bundlesInfo_ is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestoreStart_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "testBundle";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 200;

    // Ensure bundlesInfo_ is empty
    notificationCloneBundle->bundlesInfo_.clear();

    // Act
    notificationCloneBundle->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Assert
    EXPECT_TRUE(notificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestoreStart_Test_002
 * @tc.desc: Test that OnRestoreStart updates and removes the bundle when a match is found.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestoreStart_Test_002, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "testBundle";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 200;

    // Create a matching bundle and add it to bundlesInfo_
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName);
    bundleInfo.SetAppIndex(appIndex);
    bundleInfo.SetUid(150); // Original uid
    notificationCloneBundle->bundlesInfo_.push_back(bundleInfo);

    // Act
    notificationCloneBundle->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Assert
    EXPECT_EQ(notificationCloneBundle->bundlesInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreStart_Test_003
 * @tc.desc: Test that OnRestoreStart updates and removes the bundle when a match is found.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnRestoreStart_Test_003, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "testBundle";
    int32_t appIndex = 1;
    int32_t userId = 100;
    int32_t uid = 200;

    // Create a non-matching bundle and add it to bundlesInfo_
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetBundleName("otherBundle");
    bundleInfo.SetAppIndex(2);
    bundleInfo.SetUid(150);
    notificationCloneBundle->bundlesInfo_.push_back(bundleInfo);

    // Act
    notificationCloneBundle->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Assert
    EXPECT_EQ(notificationCloneBundle->bundlesInfo_.size(), 1);
}

/**
 * @tc.name: OnUserSwitch_Test_001
 * @tc.desc: Test OnUserSwitch function when cloneBundleQueue_ is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleTest, OnUserSwitch_Test_001, Function | SmallTest | Level1)
{
    // Ensure cloneDisturbQueue_ is not null
    notificationCloneBundle->cloneBundleQueue_  = nullptr;

    // Call the function
    notificationCloneBundle->OnUserSwitch(100);

    // Verify that the profile is deleted
    EXPECT_EQ(notificationCloneBundle->cloneBundleQueue_, nullptr);
}
