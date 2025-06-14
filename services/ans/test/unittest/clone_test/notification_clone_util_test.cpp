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
#include "notification_clone_util.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace Notification;

// Test suite class
class NotificationCloneUtilTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize objects and dependencies
        notificationCloneUtil = new NotificationCloneUtil();
    }

    void TearDown() override
    {
        delete notificationCloneUtil;
        notificationCloneUtil = nullptr;
    }

    NotificationCloneUtil* notificationCloneUtil;
};

/**
 * @tc.name: GetBundleUid_Test_001
 * @tc.desc: Test that error is reported when appIndex is -1
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneUtilTest, GetBundleUid_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "com.example.app";
    int32_t userId = 100;
    int32_t appIndex = -1;

    int32_t actualUid = notificationCloneUtil->GetBundleUid(bundleName, userId, appIndex);

    EXPECT_EQ(actualUid, 1000);
}

/**
 * @tc.name: GetBundleUid_Test_002
 * @tc.desc: Test that error is reported when appIndex is 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneUtilTest, GetBundleUid_Test_002, Function | SmallTest | Level1)
{
    // Arrange
    std::string bundleName = "com.example.app";
    int32_t userId = 100;
    int32_t appIndex = 0;

    int32_t actualUid = notificationCloneUtil->GetBundleUid(bundleName, userId, appIndex);

    EXPECT_EQ(actualUid, -1);
}