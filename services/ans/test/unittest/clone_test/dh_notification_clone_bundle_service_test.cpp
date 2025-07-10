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
    }

    void TearDown() override
    {}

    std::shared_ptr<DhNotificationCloneBundle> dhNotificationCloneBundle = nullptr;
};

/**
 * @tc.name: OnRestore_Test_001
 * @tc.desc: Test that error is reported when appIndex is -1
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhNotificationCloneBundleTest, OnRestore_Test_001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    int32_t userId = 100;
    auto advancedNotificationService_ = AdvancedNotificationService::GetInstance();

    sptr<NotificationDoNotDisturbProfile> date = nullptr;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles = { date };
    auto ret = advancedNotificationService_->AddDoNotDisturbProfiles(profiles);
    
    ErrCode result = dhNotificationCloneBundle->OnBackup(jsonObject);
    dhNotificationCloneBundle->OnRestore(jsonObject);
    EXPECT_EQ(result, ERR_OK);
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