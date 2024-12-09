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

#include "reminder_agent_service_stub.h"
#include "reminder_request.h"
#include "reminder_request_timer.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"

#include "ans_inner_errors.h"
#include "mock_i_remote_object.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderAgentServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
    sptr<ReminderAgentServiceStub> reminderAgentServiceStub_;
};

/*
 * @tc.name: PublishReminder_0100
 * @tc.desc: test ReminderAgentServiceStub's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, PublishReminder_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, PublishReminder_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::ALARM);
    ReminderRequest reminder;
    ReminderRequestAlarm reminderRequestAlarm;
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteStrongParcelable(&reminder);
    data.WriteParcelable(&reminderRequestAlarm);
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: PublishReminder_0200
 * @tc.desc: test ReminderAgentServiceStub's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, PublishReminder_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, PublishReminder_0200, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::INVALID);
    ReminderRequest reminder;
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteParcelable(&reminder);
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: PublishReminder_0300
 * @tc.desc: test ReminderAgentServiceStub's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, PublishReminder_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, PublishReminder_0300, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: PublishReminder_0400
 * @tc.desc: test ReminderAgentServiceStub's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, PublishReminder_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, PublishReminder_0400, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::TIMER);
    ReminderRequest reminder;
    ReminderRequestAlarm reminderRequestTimer;
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteStrongParcelable(&reminder);
    data.WriteParcelable(&reminderRequestTimer);
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: PublishReminder_0500
 * @tc.desc: test ReminderAgentServiceStub's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, PublishReminder_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, PublishReminder_0500, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::CALENDAR);
    ReminderRequest reminder;
    ReminderRequestCalendar reminderRequestCalendar;
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteStrongParcelable(&reminder);
    data.WriteParcelable(&reminderRequestCalendar);
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: PublishReminder_0600
 * @tc.desc: test ReminderAgentServiceStub's PublishReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, PublishReminder_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, PublishReminder_0600, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ReminderRequest reminder;
    ReminderRequestCalendar reminderRequestCalendar;
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    data.WriteStrongParcelable(&reminder);
    data.WriteParcelable(&reminderRequestCalendar);
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: CancelReminder_0100
 * @tc.desc: test ReminderAgentServiceStub's CancelReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, CancelReminder_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, CancelReminder_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_CANCEL_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    int32_t reminderId = 4;
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    data.WriteInt32(reminderId);
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: CancelReminder_0200
 * @tc.desc: test ReminderAgentServiceStub's CancelReminder function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, CancelReminder_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, CancelReminder_0200, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_CANCEL_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/*
 * @tc.name: CancelAllReminders_0100
 * @tc.desc: test ReminderAgentServiceStub's CancelAllReminders function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, CancelAllReminders_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, CancelAllReminders_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_CANCEL_ALL_REMINDERS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: GetValidReminders_0100
 * @tc.desc: test ReminderAgentServiceStub's GetValidReminders function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, GetValidReminders_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, GetValidReminders_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_GET_VALID_REMINDERS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/*
 * @tc.name: AddExcludeDate_0100
 * @tc.desc: test ReminderAgentServiceStub's AddExcludeDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, AddExcludeDate_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, AddExcludeDate_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_ADD_EXCLUDE_DATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/*
 * @tc.name: DelExcludeDates_0100
 * @tc.desc: test ReminderAgentServiceStub's DelExcludeDates function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, DelExcludeDates_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, DelExcludeDates_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_DEL_EXCLUDE_DATES);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/*
 * @tc.name: GetExcludeDates_0100
 * @tc.desc: test ReminderAgentServiceStub's GetExcludeDates function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(ReminderAgentServiceStubTest, GetExcludeDates_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "ReminderAgentServiceStubTest, GetExcludeDates_0100, TestSize.Level1";
    uint32_t code = static_cast<uint32_t>(IReminderAgentServiceIpcCode::COMMAND_GET_EXCLUDE_DATES);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(ReminderAgentServiceStub::GetDescriptor());
    ErrCode ret = reminderAgentServiceStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}
}
}
