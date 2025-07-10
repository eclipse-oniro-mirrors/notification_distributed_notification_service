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
#include "notification_clone_bundle_service.h"
#include "notification_do_not_disturb_profile.h"
#include "ans_inner_errors.h"
#include "notification_clone_util.h"
#include "advanced_notification_service.h"
#include "mock/mock_notification_clone_util.h"
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
    int32_t userId = 100;
    auto advancedNotificationService_ = AdvancedNotificationService::GetInstance();

    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->AddDoNotDisturbProfiles(profiles);
    
    ErrCode result = notificationCloneBundle->OnBackup(jsonObject);
    notificationCloneBundle->OnRestore(jsonObject);
    EXPECT_EQ(result, ERR_OK);
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