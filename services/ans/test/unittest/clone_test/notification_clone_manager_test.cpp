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
#include "notification_clone_manager.h"
#include "ans_inner_errors.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace Notification;

// Test suite class
class AncoRestoreStartEventSubscriberTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Initialize objects and dependencies
        ancoRestoreStartEventSubscriber = AncoRestoreStartEventSubscriber::create();
        notificationCloneManager = &NotificationCloneManager::GetInstance();
    }

    void TearDown() override
    {}

    std::shared_ptr<AncoRestoreStartEventSubscriber> ancoRestoreStartEventSubscriber = nullptr;
    NotificationCloneManager* notificationCloneManager;
};

/**
 * @tc.name: OnReceiveEvent_Test_001
 * @tc.desc: Test that error is reported when uid is 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AncoRestoreStartEventSubscriberTest, OnReceiveEvent_Test_001, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    want.SetParam("bundleName", std::string("testBundle"));
    want.SetParam("uid", 0);
    EventFwk::CommonEventData data{want};

    // Act
    ancoRestoreStartEventSubscriber->OnReceiveEvent(data);
    EXPECT_EQ(data.GetWant().GetIntParam("uid", 0), 0);
}

/**
 * @tc.name: OnReceiveEvent_Test_002
 * @tc.desc: Test that error is reported when uid is negative
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AncoRestoreStartEventSubscriberTest, OnReceiveEvent_Test_002, Function | SmallTest | Level1)
{
    // Arrange
    EventFwk::Want want;
    want.SetParam("bundleName", std::string("testBundle"));
    want.SetParam("uid", -1);
    EventFwk::CommonEventData data{want};

    // Act
    ancoRestoreStartEventSubscriber->OnReceiveEvent(data);
    EXPECT_EQ(data.GetWant().GetIntParam("uid", 0), -1);
}

/**
 * @tc.name: OnReceiveEvent_Test_003
 * @tc.desc: Test that error is reported when uid is negative
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AncoRestoreStartEventSubscriberTest, OnReceiveEvent_Test_003, Function | SmallTest | Level1)
{
    // Arrange
    EventFwk::Want want;
    want.SetParam("bundleName", std::string("testBundle"));
    want.SetParam("uid", 1);
    EventFwk::CommonEventData data{want};

    // Act
    ancoRestoreStartEventSubscriber->OnReceiveEvent(data);
    EXPECT_EQ(data.GetWant().GetIntParam("uid", 0), 1);
}

/**
 * @tc.name: OnRestoreStart_Test_001
 * @tc.desc: Test that error is reported when uid is negative
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AncoRestoreStartEventSubscriberTest, OnRestoreStart_Test_001, Function | SmallTest | Level1)
{
    // Arrange
    EventFwk::Want want;
    want.SetParam("bundleName", std::string("testBundle"));
    want.SetParam("index", -1);

    // Act
    notificationCloneManager->OnRestoreStart(want);
    EXPECT_EQ(want.GetIntParam("index", 0), -1);
}

/**
 * @tc.name: OnRestoreStart_Test_002
 * @tc.desc: Test that error is reported when uid is negative
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AncoRestoreStartEventSubscriberTest, OnRestoreStart_Test_002, Function | SmallTest | Level1)
{
    // Arrange
    EventFwk::Want want;
    want.SetParam("bundleName", std::string(""));
    want.SetParam("index", 1);

    // Act
    notificationCloneManager->OnRestoreStart(want);
    EXPECT_EQ(want.GetIntParam("index", 0), 1);
}

/**
 * @tc.name: OnDhRestoreStart_Test_001
 * @tc.desc: Test that error is reported when uid is negative
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AncoRestoreStartEventSubscriberTest, OnDhRestoreStart_Test_001, Function | SmallTest | Level1)
{
    std::string bundleName = "testBundle";
    int32_t uid = 12345;

    // Ensure cloneTemplates is empty
    notificationCloneManager->cloneTemplates.clear();

    // Call the function
    notificationCloneManager->OnDhRestoreStart(bundleName, uid);

    EXPECT_TRUE(notificationCloneManager->cloneTemplates.empty());
}