/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "errors.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include <gtest/gtest.h>

#include "reminder_agent_service_proxy.h"
#include "reminder_request.h"
#include "reminder_request_timer.h"

#include "ans_inner_errors.h"
#include "mock_i_remote_object.h"

using namespace testing::ext;

namespace {
    bool g_mockWriteInterfaceTokenRet = true;
}

void MockWriteInterfaceToken(bool mockRet)
{
    g_mockWriteInterfaceTokenRet = mockRet;
}
namespace OHOS {
namespace Notification {
class ReminderAgentServiceProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/*
 * @tc.name: PublishReminder_0100
 * @tc.desc: test ReminderAgentServiceProxy's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, PublishReminder_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, PublishReminder_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    ReminderRequest reminderRequest;
    int32_t reminderId = 0;
    ErrCode res = proxy->PublishReminder(reminderRequest, reminderId);
    EXPECT_NE(ERR_OK, res);
}

/*
 * @tc.name: PublishReminder_0200
 * @tc.desc: test ReminderAgentServiceProxy's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, PublishReminder_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, PublishReminder_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    ReminderRequestTimer reminderRequest;
    int32_t reminderId = 0;
    ErrCode res = proxy->PublishReminder(reminderRequest, reminderId);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: CancelReminder_0100
 * @tc.desc: test ReminderAgentServiceProxy's CancelReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, CancelReminder_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, CancelReminder_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t reminderId = 0;
    ErrCode res = proxy->CancelReminder(reminderId);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: CancelAllReminders_0100
 * @tc.desc: test ReminderAgentServiceProxy's CancelAllReminders function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, CancelAllReminders_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, CancelAllReminders_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    ErrCode res = proxy->CancelAllReminders();
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: GetValidReminders_0100
 * @tc.desc: test ReminderAgentServiceProxy's GetValidReminders function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, GetValidReminders_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, GetValidReminders_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<ReminderRequestAdaptation> reminderVector;
    ErrCode res = proxy->GetValidReminders(reminderVector);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: AddExcludeDate_0100
 * @tc.desc: test ReminderAgentServiceProxy's AddExcludeDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, AddExcludeDate_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, AddExcludeDate_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t reminderId = 0;
    int64_t date = 0;
    ErrCode res = proxy->AddExcludeDate(reminderId, date);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: DelExcludeDates_0100
 * @tc.desc: test ReminderAgentServiceProxy's DelExcludeDates function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, DelExcludeDates_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, DelExcludeDates_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t reminderId = 0;
    ErrCode res = proxy->DelExcludeDates(reminderId);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: GetExcludeDates_0100
 * @tc.desc: test ReminderAgentServiceProxy's GetExcludeDates function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, GetExcludeDates_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, GetExcludeDates_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t reminderId = 0;
    std::vector<int64_t> dates;
    ErrCode res = proxy->GetExcludeDates(reminderId, dates);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: UpdateReminder_0100
 * @tc.desc: test ReminderAgentServiceProxy's UpdateReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, UpdateReminder_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, UpdateReminder_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t reminderId = 0;
    ReminderRequest reminderRequest;
    ErrCode res = proxy->UpdateReminder(reminderId, reminderRequest);
    EXPECT_NE(ERR_OK, res);
}

/*
 * @tc.name: UpdateReminder_0200
 * @tc.desc: test ReminderAgentServiceProxy's UpdateReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceProxyTest, UpdateReminder_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceProxyTest, UpdateReminder_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<ReminderAgentServiceProxy> proxy = std::make_shared<ReminderAgentServiceProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t reminderId = 0;
    ReminderRequestTimer reminderRequest;
    ErrCode res = proxy->UpdateReminder(reminderId, reminderRequest);
    EXPECT_EQ(ERR_OK, res);
}
}
}
