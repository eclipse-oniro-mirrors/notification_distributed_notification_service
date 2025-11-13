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
#define private public
#define protected public
#include "ans_inner_errors.h"
#include "dh_notification_clone_bundle_service.h"
#include "advanced_notification_service.h"
#include "mock_notification_clone_util.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace Notification;

// Test suite class
class DhNotificationCloneBundleTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize objects and dependencies
        dhNotificationCloneBundle = DhNotificationCloneBundle::GetInstance();
        int32_t initTestUserId = 100;
        int32_t initTestUid = 1000;
        MockSetActiveUserIdForClone(initTestUserId);
        MockSetBundleUidForClone(initTestUid);
        SetFuncGetActiveUserIdIsCalled(false);
        SetFuncGetBundleUidIsCalled(false);
    }

    void TearDown() override
    {}

    std::shared_ptr<DhNotificationCloneBundle> dhNotificationCloneBundle = nullptr;
};

/**
 * @tc.name: OnRestore_Test_00001
 * @tc.desc: Test that OnRestore does nothing when input param has wrong type.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestore_Test_00001, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonNull;
    nlohmann::json jsonObject = nlohmann::json::object();
    NotificationCloneBundleInfo cloneBundleInfo;
    dhNotificationCloneBundle->bundlesInfo_.emplace_back(cloneBundleInfo);

    // When
    dhNotificationCloneBundle->OnRestore(jsonNull);
    dhNotificationCloneBundle->OnRestore(jsonObject);

    // Then
    EXPECT_FALSE(dhNotificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestore_Test_00002
 * @tc.desc: Test OnRestore when task queue is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestore_Test_00002, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundleInfo;
    nlohmann::json jsonNode;
    cloneBundleInfo.ToJson(jsonNode);
    jsonArray.emplace_back(jsonNode);
    dhNotificationCloneBundle->bundlesInfo_.emplace_back(cloneBundleInfo);
    dhNotificationCloneBundle->dhCloneBundleQueue_ = nullptr;

    // When
    dhNotificationCloneBundle->OnRestore(jsonArray);

    // Then
    EXPECT_FALSE(dhNotificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestore_Test_00003
 * @tc.desc: Test OnRestore when task bundlesInfo_ is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestore_Test_00003, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();

    // When
    dhNotificationCloneBundle->OnRestore(jsonArray);

    // Then
    EXPECT_TRUE(dhNotificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestore_Test_00004
 * @tc.desc: Test OnRestore when bundle doesn't exist.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestore_Test_00004, Function | SmallTest | Level1)
{
    // Given
    nlohmann::json jsonArray = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundleInfo;
    nlohmann::json jsonNode;
    cloneBundleInfo.ToJson(jsonNode);
    jsonArray.emplace_back(jsonNode);
    dhNotificationCloneBundle->bundlesInfo_.emplace_back(cloneBundleInfo);

    // When
    dhNotificationCloneBundle->OnRestore(jsonArray);

    // Then
    EXPECT_FALSE(dhNotificationCloneBundle->bundlesInfo_.empty());
}

/**
 * @tc.name: OnRestoreStart_Test_001
 * @tc.desc: Test that error is reported when bundlesInfo_ is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestoreStart_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "testBundle";
    int32_t appIndex = 0;
    int32_t userId = 0;
    int32_t uid = 12345;

    // Ensure bundlesInfo_ is empty
    dhNotificationCloneBundle->bundlesInfo_.clear();

    // Act
    dhNotificationCloneBundle->OnRestoreStart(bundleName, appIndex, userId, uid);

    EXPECT_EQ(dhNotificationCloneBundle->bundlesInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreStart_Test_002
 * @tc.desc: Test that error is reported when bundlesInfo_ is not null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestoreStart_Test_002, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "testBundle";
    int32_t appIndex = 0;
    int32_t userId = 0;
    int32_t uid = 12345;

    // Create a bundle with the same name
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetBundleName(bundleName);
    bundleInfo.SetUid(54321); // Original UID

    // Add the bundle to bundlesInfo_
    dhNotificationCloneBundle->bundlesInfo_.push_back(bundleInfo);

    // Act
    dhNotificationCloneBundle->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Assert
    // Check if the bundle was updated and deleted
    EXPECT_EQ(dhNotificationCloneBundle->bundlesInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreStart_Test_003
 * @tc.desc: Test that error is reported when bundlesInfo_ is not null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestoreStart_Test_003, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "testBundle";
    int32_t appIndex = 0;
    int32_t userId = 0;
    int32_t uid = 12345;

    // Create a bundle with a different name
    NotificationCloneBundleInfo bundleInfo;
    bundleInfo.SetBundleName("differentBundle");
    bundleInfo.SetUid(54321);

    // Add the bundle to bundlesInfo_
    dhNotificationCloneBundle->bundlesInfo_.push_back(bundleInfo);

    // Act
    dhNotificationCloneBundle->OnRestoreStart(bundleName, appIndex, userId, uid);

    // Assert
    // Check if the bundle was not modified
    EXPECT_EQ(dhNotificationCloneBundle->bundlesInfo_.size(), 1);
    EXPECT_EQ(dhNotificationCloneBundle->bundlesInfo_.front().GetBundleName(), "differentBundle");
    EXPECT_EQ(dhNotificationCloneBundle->bundlesInfo_.front().GetUid(), 54321);
}

/**
 * @tc.name: OnUserSwitch_Test_001
 * @tc.desc: Test that error is reported when dhCloneBundleQueue_ is null.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnUserSwitch_Test_001, Function | SmallTest | Level1)
{
    dhNotificationCloneBundle->dhCloneBundleQueue_ = nullptr;

    // Call the function under test
    dhNotificationCloneBundle->OnUserSwitch(1);

    EXPECT_EQ(dhNotificationCloneBundle->dhCloneBundleQueue_, nullptr);
}