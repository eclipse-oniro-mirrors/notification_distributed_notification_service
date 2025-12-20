/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "reminder_notify_manager.h"

#include "mock_i_remote_object.h"

using namespace testing::ext;
namespace OHOS::Notification {
class ReminderNotifyManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ReminderNotifyManagerTest_001
 * @tc.desc: test ReminderNotifyManager function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderNotifyManagerTest, ReminderNotifyManagerTest_001, Level1)
{
    ReminderNotifyManager manager;
    EXPECT_NE(manager.queue_, nullptr);
    EXPECT_NE(manager.deathRecipient_, nullptr);
}

/**
 * @tc.name: ReminderNotifyManagerTest_002
 * @tc.desc: test ReminderNotifyManager::RegisterNotify function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderNotifyManagerTest, ReminderNotifyManagerTest_002, Level1)
{
    ReminderNotifyManager manager;
    manager.RegisterNotify(100, nullptr);
    EXPECT_EQ(manager.notifies_.size(), 0);

    sptr<RemoteDeathRecipient> deathRecipient = manager.deathRecipient_;
    manager.deathRecipient_ = nullptr;
    sptr<IRemoteObject> object = new (std::nothrow) MockIRemoteObject();
    manager.RegisterNotify(100, object);
    EXPECT_EQ(manager.notifies_.size(), 0);

    manager.deathRecipient_ = deathRecipient;
    manager.RegisterNotify(100, object);
    EXPECT_EQ(manager.notifies_.size(), 1);
    manager.RegisterNotify(100, object);
    EXPECT_EQ(manager.notifies_.size(), 1);
}

/**
 * @tc.name: ReminderNotifyManagerTest_003
 * @tc.desc: test ReminderNotifyManager::UnRegisterNotify function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderNotifyManagerTest, ReminderNotifyManagerTest_003, Level1)
{
    ReminderNotifyManager manager;
    manager.UnRegisterNotify(100);
    EXPECT_EQ(manager.notifies_.size(), 0);

    sptr<IRemoteObject> object = new (std::nothrow) MockIRemoteObject();
    manager.RegisterNotify(100, object);
    EXPECT_EQ(manager.notifies_.size(), 1);
    manager.UnRegisterNotify(100);
    EXPECT_EQ(manager.notifies_.size(), 0);
}

/**
 * @tc.name: ReminderNotifyManagerTest_004
 * @tc.desc: test ReminderNotifyManager::NotifyReminderState function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderNotifyManagerTest, ReminderNotifyManagerTest_004, Level1)
{
    ReminderNotifyManager manager;

    sptr<IRemoteObject> object1 = new (std::nothrow) MockIRemoteObject();
    manager.RegisterNotify(100, object1);
    sptr<IRemoteObject> object2 = new (std::nothrow) MockIRemoteObject();
    manager.RegisterNotify(101, object1);
    EXPECT_EQ(manager.notifies_.size(), 2);

    std::vector<ReminderState> states;
    int32_t ret = manager.NotifyReminderState(102, states);
    EXPECT_EQ(ret, false);
    ret = manager.NotifyReminderState(101, states);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ReminderNotifyManagerTest_005
 * @tc.desc: test ReminderNotifyManager::OnRemoteDied function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderNotifyManagerTest, ReminderNotifyManagerTest_005, Level1)
{
    ReminderNotifyManager manager;
    manager.OnRemoteDied(nullptr);
    EXPECT_EQ(manager.notifies_.size(), 0);

    sptr<IRemoteObject> object = new (std::nothrow) MockIRemoteObject();
    wptr<IRemoteObject> wobject = object;
    object = nullptr;
    manager.OnRemoteDied(wobject);
    EXPECT_EQ(manager.notifies_.size(), 0);

    sptr<IRemoteObject> object1 = new (std::nothrow) MockIRemoteObject();
    manager.RegisterNotify(100, object1);
    sptr<IRemoteObject> object2 = new (std::nothrow) MockIRemoteObject();
    manager.RegisterNotify(101, object2);
    sptr<IRemoteObject> object3 = new (std::nothrow) MockIRemoteObject();
    wobject = object3;
    manager.OnRemoteDied(wobject);
    EXPECT_EQ(manager.notifies_.size(), 2);
    wobject = object2;
    manager.OnRemoteDied(wobject);
    EXPECT_EQ(manager.notifies_.size(), 1);
}
}  // namespace OHOS::Notification