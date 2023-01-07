/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "ans_manager_stub.h"
#include "ans_subscriber_stub.h"
#include "reminder_request_alarm.h"
#include "reminder_request_timer.h"
#include "reminder_request_calendar.h"
#undef private
#undef protected

#include "ans_inner_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class AnsManagerStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        ansManagerStub_ = new AnsManagerStub();
    }
    void TearDown() {}
    sptr<AnsManagerStub> ansManagerStub_;
};

/**
 * @tc.name: OnRemoteRequest01
 * @tc.desc: Test if get the wrong descriptor.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, OnRemoteRequest0001, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(u"error.GetDescriptor");

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)OBJECT_NULL);
}

/**
 * @tc.name: OnRemoteRequest02
 * @tc.desc: Test if get the wrong code.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, OnRemoteRequest0002, Function | SmallTest | Level1)
{
    uint32_t code = 267;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: HandlePublish01
 * @tc.desc: Test HandlePublish succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublish01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string label = "this is a notification label";
    sptr<NotificationRequest> notification = new NotificationRequest();
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(label);
    data.WriteParcelable(notification);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandlePublish02
 * @tc.desc: Test if the label is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublish02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationRequest> notification = new NotificationRequest();
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(notification);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublish03
 * @tc.desc: Test if the notification is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublish03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string label = "this is a notification label";
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(label);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublishToDevice01
 * @tc.desc: Test HandlePublishToDevice succeeds;
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishToDevice01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION_TO_DEVICE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    sptr<NotificationRequest> notification = new NotificationRequest();
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(notification);
    data.WriteString(deviceId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandlePublishToDevice02
 * @tc.desc: Test if the notification is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishToDevice02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION_TO_DEVICE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublishToDevice03
 * @tc.desc: Test if the deviceId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishToDevice03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_NOTIFICATION_TO_DEVICE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationRequest> notification = new NotificationRequest();
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(notification);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancel01
 * @tc.desc: Test HandleCancel succeeds
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancel01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 3;
    std::string label = "this is a notification label";
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);
    data.WriteString(label);
    
    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleCancel02
 * @tc.desc: Test if the notificationId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancel02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string label = "this is a notification label";
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(label);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancel03
 * @tc.desc: Test if the label in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancel03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 3;
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelAll01
 * @tc.desc: Test HandleCancelAll succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelAll01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_ALL_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleCancelAsBundle01
 * @tc.desc: Test HandlePublish succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelAsBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 3;
    std::string representativeBundle = "this is a representativeBundle";
    int32_t userId = 4;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);
    data.WriteString(representativeBundle);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleCancelAsBundle02
 * @tc.desc: Test if the notificationId in data is null..
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelAsBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string representativeBundle = "this is a representativeBundle";
    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(representativeBundle);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelAsBundle03
 * @tc.desc: Test if the representativeBundle in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelAsBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 3;
    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelAsBundle04
 * @tc.desc: Test if the userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelAsBundle04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 3;
    std::string representativeBundle = "this is a representativeBundle";
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);
    data.WriteString(representativeBundle);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleAddSlotByType01
 * @tc.desc: Test HandleAddSlotByType succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleAddSlotByType01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ADD_SLOT_BY_TYPE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleRemoveSlotByType01
 * @tc.desc: Test HandleRemoveSlotByType succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveSlotByType01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_SLOT_BY_TYPE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleRemoveAllSlots01
 * @tc.desc: Test HandleRemoveAllSlots succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveAllSlots01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_ALL_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetSlotByType01
 * @tc.desc: Test HandleGetSlotByType succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetSlotByType01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SLOT_BY_TYPE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetSlotNumAsBundle01
 * @tc.desc: Test HandleGetSlotNumAsBundle succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetSlotNumAsBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SLOT_NUM_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetSlotNumAsBundle02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetSlotNumAsBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SLOT_NUM_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetActiveNotifications01
 * @tc.desc: Test HandleGetActiveNotifications succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetActiveNotifications01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ACTIVE_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetActiveNotificationNums01
 * @tc.desc: Test HandleGetActiveNotificationNums succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetActiveNotificationNums01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ACTIVE_NOTIFICATION_NUMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetAllActiveNotifications01
 * @tc.desc: Test HandleGetAllActiveNotifications succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetAllActiveNotifications01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ALL_ACTIVE_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetNotificationAgent01
 * @tc.desc: Test HandleSetNotificationAgent succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationAgent01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_AGENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string agent = "this is a agent";
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(agent);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetNotificationAgent02
 * @tc.desc: Test if the agent in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationAgent02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_AGENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetNotificationAgent01
 * @tc.desc: Test HandleGetNotificationAgent succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetNotificationAgent01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_NOTIFICATION_AGENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleCanPublishAsBundle01
 * @tc.desc: Test HandleCanPublishAsBundle succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCanPublishAsBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CAN_PUBLISH_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string representativeBundle = "this is a representativeBundle";
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(representativeBundle);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleCanPublishAsBundle02
 * @tc.desc: Test if the representativeBundle in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCanPublishAsBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CAN_PUBLISH_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublishAsBundle01
 * @tc.desc: Test HandlePublishAsBundle succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishAsBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationRequest> notification = new NotificationRequest();

    std::string representativeBundle = "this is a representativeBundle";
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(notification);
    data.WriteString(representativeBundle);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandlePublishAsBundle02
 * @tc.desc: Test if the notification in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishAsBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string representativeBundle = "this is a representativeBundle";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(representativeBundle);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublishAsBundle03
 * @tc.desc: Test if the representativeBundle in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishAsBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_AS_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationRequest> notification = new NotificationRequest();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(notification);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationBadgeNum01
 * @tc.desc: Test HandleSetNotificationBadgeNum succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationBadgeNum01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_BADGE_NUM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t num = 4;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(num);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetNotificationBadgeNum02
 * @tc.desc: Test if the num in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationBadgeNum02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_BADGE_NUM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetBundleImportance01
 * @tc.desc: Test HandleGetBundleImportance succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetBundleImportance01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_BUNDLE_IMPORTANCE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetDoNotDisturbDate01
 * @tc.desc: Test HandleSetDoNotDisturbDate succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetDoNotDisturbDate01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_DO_NOT_DISTURB_DATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(date);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetDoNotDisturbDate02
 * @tc.desc: Test if the date in data is null..
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetDoNotDisturbDate02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_DO_NOT_DISTURB_DATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetDoNotDisturbDate01
 * @tc.desc: Test HandleGetDoNotDisturbDate succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetDoNotDisturbDate01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_DO_NOT_DISTURB_DATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleDoesSupportDoNotDisturbMode01
 * @tc.desc: Test HandleDoesSupportDoNotDisturbMode01 succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDoesSupportDoNotDisturbMode01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DOES_SUPPORT_DO_NOT_DISTURB_MODE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandlePublishContinuousTaskNotification01
 * @tc.desc: Test HandlePublishContinuousTaskNotification succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishContinuousTaskNotification01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_CONTINUOUS_TASK_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationRequest> request = new NotificationRequest();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(request);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandlePublishContinuousTaskNotification02
 * @tc.desc: Test if the request in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandlePublishContinuousTaskNotification02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_CONTINUOUS_TASK_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelContinuousTaskNotification01
 * @tc.desc: Test HandleCancelContinuousTaskNotification succeeds.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelContinuousTaskNotification01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_CONTINUOUS_TASK_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string label = "this is a label";
    int32_t notificationId = 3;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(label);
    data.WriteInt32(notificationId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleCancelContinuousTaskNotification02
 * @tc.desc: Test if the label in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelContinuousTaskNotification02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_CONTINUOUS_TASK_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 3;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelContinuousTaskNotification03
 * @tc.desc: Test if the notificationId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleCancelContinuousTaskNotification03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_CONTINUOUS_TASK_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string label = "this is a label";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(label);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleIsNotificationPolicyAccessGranted01
 * @tc.desc: Test HandleIsNotificationPolicyAccessGranted succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleIsNotificationPolicyAccessGranted01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_NOTIFICATION_POLICY_ACCESS_GRANTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetPrivateNotificationsAllowed02
 * @tc.desc: Test if the allow in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetPrivateNotificationsAllowed02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_PRIVATIVE_NOTIFICATIONS_ALLOWED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetPrivateNotificationsAllowed01
 * @tc.desc: Test HandleGetPrivateNotificationsAllowed succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetPrivateNotificationsAllowed01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_PRIVATIVE_NOTIFICATIONS_ALLOWED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleRemoveNotification01
 * @tc.desc: Test HandleRemoveNotification succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveNotification01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t notificationId = 1;
    std::string label = "this is a label";
    int32_t removeReason = 2;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteInt32(notificationId);
    data.WriteString(label);
    data.WriteInt32(removeReason);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleRemoveNotification02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveNotification02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t notificationId = 1;
    std::string label = "this is a label";
    int32_t removeReason = 2;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(notificationId);
    data.WriteString(label);
    data.WriteInt32(removeReason);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRemoveNotification03
 * @tc.desc: Test if the notificationId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveNotification03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::string label = "this is a label";
    int32_t removeReason = 2;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteString(label);
    data.WriteInt32(removeReason);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRemoveNotification04
 * @tc.desc: Test if the label in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveNotification04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t notificationId = 1;
    int32_t removeReason = 2;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteInt32(notificationId);
    data.WriteInt32(removeReason);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRemoveNotification05
 * @tc.desc: Test if the removeReason in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveNotification05, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t notificationId = 1;
    std::string label = "this is a label";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteInt32(notificationId);
    data.WriteString(label);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRemoveAllNotifications01
 * @tc.desc: Test HandleRemoveAllNotifications succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveAllNotifications01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_ALL_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleRemoveAllNotifications02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveAllNotifications02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_ALL_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDelete01
 * @tc.desc: Test HandleDelete succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDelete01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string key = "this is a key";
    int32_t removeReason = 2;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(key);
    data.WriteInt32(removeReason);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleDelete02
 * @tc.desc: Test if the key in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDelete02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t removeReason = 2;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(removeReason);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDelete03
 * @tc.desc: Test if the removeReason in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDelete03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string key = "this is a key";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(key);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDeleteByBundle01
 * @tc.desc: Test HandleDeleteByBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDeleteByBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_NOTIFICATION_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleDeleteByBundle02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDeleteByBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_NOTIFICATION_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDeleteAll01
 * @tc.desc: Test HandleDeleteAll succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleDeleteAll01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_ALL_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetSlotsByBundle01
 * @tc.desc: Test HandleGetSlotsByBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetSlotsByBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SLOTS_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleGetSlotsByBundle02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleGetSlotsByBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SLOTS_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleUpdateSlots01
 * @tc.desc: Test HandleUpdateSlots succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleUpdateSlots01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UPDATE_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t infoSize = 3;
    sptr<NotificationSlot> slot1 = new NotificationSlot();
    sptr<NotificationSlot> slot2 = new NotificationSlot();
    sptr<NotificationSlot> slot3 = new NotificationSlot();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(infoSize);
    data.WriteStrongParcelable(slot1);
    data.WriteStrongParcelable(slot2);
    data.WriteStrongParcelable(slot3);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleUpdateSlots02
 * @tc.desc: Test if the StrongParcelable:info in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleUpdateSlots02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UPDATE_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t infoSize = 3;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(infoSize);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleUpdateSlots03
 * @tc.desc: Test if the StrongParcelable:info in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleUpdateSlots03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UPDATE_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRequestEnableNotification01
 * @tc.desc: Test HandleRequestEnableNotification succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRequestEnableNotification01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REQUEST_ENABLE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleRequestEnableNotification02
 * @tc.desc: Test if the deviceId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleRequestEnableNotification02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REQUEST_ENABLE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForBundle01
 * @tc.desc: Test HandleSetNotificationsEnabledForBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    bool enabled = false;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForBundle02
 * @tc.desc: Test if the deviceId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = false;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForBundle03
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForAllBundles01
 * @tc.desc: Test HandleSetNotificationsEnabledForAllBundles succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForAllBundles01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForAllBundles02
 * @tc.desc: Test if the deviceId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForAllBundles02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForAllBundles03
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForAllBundles03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_ALL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForSpecialBundle01
 * @tc.desc: Test HandleSetNotificationsEnabledForSpecialBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForSpecialBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);
    data.WriteParcelable(bundleOption);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForSpecialBundle02
 * @tc.desc: Test if the deviceId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForSpecialBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(bundleOption);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForSpecialBundle03
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForSpecialBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledForSpecialBundle04
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledForSpecialBundle04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_FOR_SPECIAL_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string deviceId = "this is a deviceId";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(deviceId);
    data.WriteParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetShowBadgeEnabledForBundle01
 * @tc.desc: Test HandleSetShowBadgeEnabledForBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetShowBadgeEnabledForBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_SHOW_BADGE_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(bundleOption);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)NO_ERROR);
}

/**
 * @tc.name: HandleSetShowBadgeEnabledForBundle02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetShowBadgeEnabledForBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_SHOW_BADGE_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetShowBadgeEnabledForBundle03
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI5XQ4E
 */
HWTEST_F(AnsManagerStubTest, HandleSetShowBadgeEnabledForBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_SHOW_BADGE_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleAddSlots01
 * @tc.desc: Test if the slots in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleAddSlots01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ADD_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleAddSlots02
 * @tc.desc: Test if the result in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleAddSlots02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ADD_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slots.emplace_back(slot);

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    ErrCode result = ansManagerStub_->AddSlots(slots);
    ansManagerStub_->WriteParcelableVector(slots, reply, result);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetSlots01
 * @tc.desc: Test HandleGetSlots succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetSlots01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SLOTS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleGetSpecialActiveNotifications01
 * @tc.desc: Test HandleGetSpecialActiveNotifications succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetSpecialActiveNotifications01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SPECIAL_ACTIVE_NOTIFICATIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::vector<std::string> key;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStringVector(key);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleGetShowBadgeEnabledForBundle01
 * @tc.desc: Test HandleGetShowBadgeEnabledForBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetShowBadgeEnabledForBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SHOW_BADGE_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(bundleOption);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleGetShowBadgeEnabledForBundle02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetShowBadgeEnabledForBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SHOW_BADGE_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetShowBadgeEnabledForBundle03
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetShowBadgeEnabledForBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SHOW_BADGE_ENABLED_FOR_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetShowBadgeEnabled01
 * @tc.desc: Test HandleGetShowBadgeEnabled succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetShowBadgeEnabled01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SHOW_BADGE_ENABLED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleSubscribe01
 * @tc.desc: Test HandleSubscribe succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSubscribe01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<IRemoteObject> subscriber;
    bool subcribeInfo = true;
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(subscriber);
    data.WriteBool(subcribeInfo);
    data.WriteParcelable(info);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSubscribe02
 * @tc.desc: Test if the subcribeInfo in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSubscribe02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<IRemoteObject> subscriber;
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteRemoteObject(subscriber);
    data.WriteParcelable(info);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSubscribe03
 * @tc.desc: Test if the info in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSubscribe03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<IRemoteObject> subscriber;
    bool subcribeInfo = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(subscriber);
    data.WriteBool(subcribeInfo);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSubscribe04
 * @tc.desc: Test if the subscriber in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSubscribe04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool subcribeInfo = true;
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(subcribeInfo);
    data.WriteParcelable(info);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleUnsubscribe01
 * @tc.desc: Test HandleUnsubscribe succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleUnsubscribe01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UNSUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<IRemoteObject> subscriber;
    bool subcribeInfo = true;
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(subscriber);
    data.WriteBool(subcribeInfo);
    data.WriteParcelable(info);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleUnsubscribe02
 * @tc.desc: Test if the subcribeInfo in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleUnsubscribe02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UNSUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<IRemoteObject> subscriber;
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteRemoteObject(subscriber);
    data.WriteParcelable(info);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleUnsubscribe03
 * @tc.desc: Test if the info in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleUnsubscribe03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UNSUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<IRemoteObject> subscriber;
    bool subcribeInfo = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(subscriber);
    data.WriteBool(subcribeInfo);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleUnsubscribe04
 * @tc.desc: Test if the subscriber in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleUnsubscribe04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::UNSUBSCRIBE_NOTIFICATION);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool subcribeInfo = true;
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(subcribeInfo);
    data.WriteParcelable(info);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleAreNotificationsSuspended01
 * @tc.desc: Test HandleAreNotificationsSuspended succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleAreNotificationsSuspended01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ARE_NOTIFICATION_SUSPENDED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool suspended = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(suspended);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleGetCurrentAppSorting01
 * @tc.desc: Test HandleGetCurrentAppSorting succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetCurrentAppSorting01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_CURRENT_APP_SORTING);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsAllowedNotify01
 * @tc.desc: Test HandleIsAllowedNotify succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsAllowedNotify01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_ALLOWED_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsAllowedNotifySelf01
 * @tc.desc: Test HandleIsAllowedNotifySelf succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsAllowedNotifySelf01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_ALLOWED_NOTIFY_SELF);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsSpecialBundleAllowedNotify01
 * @tc.desc: Test HandleIsSpecialBundleAllowedNotify succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsSpecialBundleAllowedNotify01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_SPECIAL_BUNDLE_ALLOWED_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsSpecialBundleAllowedNotify02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsSpecialBundleAllowedNotify02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_SPECIAL_BUNDLE_ALLOWED_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelGroup01
 * @tc.desc: Test HandleCancelGroup succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleCancelGroup01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_GROUP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string groupName = "this is groupName";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(groupName);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleCancelGroup02
 * @tc.desc: Test if the groupName in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleCancelGroup02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_GROUP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRemoveGroupByBundle01
 * @tc.desc: Test HandleRemoveGroupByBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveGroupByBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_GROUP_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::string groupName = "this is groupName";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteString(groupName);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleRemoveGroupByBundle02
 * @tc.desc: Test if the groupName in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveGroupByBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_GROUP_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleRemoveGroupByBundle03
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleRemoveGroupByBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::REMOVE_GROUP_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string groupName = "this is groupName";

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(groupName);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleIsDistributedEnabled01
 * @tc.desc: Test HandleIsDistributedEnabled succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsDistributedEnabled01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_DISTRIBUTED_ENABLED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleEnableDistributed01
 * @tc.desc: Test HandleEnableDistributed succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributed01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleEnableDistributed02
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributed02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleEnableDistributedByBundle01
 * @tc.desc: Test HandleEnableDistributedByBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributedByBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleEnableDistributedByBundle02
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributedByBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleEnableDistributedByBundle03
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributedByBundle03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleEnableDistributedSelf01
 * @tc.desc: Test HandleEnableDistributedSelf succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributedSelf01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED_SELF);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleEnableDistributedSelf02
 * @tc.desc: Test if the enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleEnableDistributedSelf02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::ENABLE_DISTRIBUTED_SELF);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleIsDistributedEnableByBundle01
 * @tc.desc: Test HandleIsDistributedEnableByBundle succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsDistributedEnableByBundle01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_DISTRIBUTED_ENABLED_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsDistributedEnableByBundle02
 * @tc.desc: Test if the bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsDistributedEnableByBundle02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_DISTRIBUTED_ENABLED_BY_BUNDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetDeviceRemindType01
 * @tc.desc: Test HandleGetDeviceRemindType succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetDeviceRemindType01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_DEVICE_REMIND_TYPE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleShellDump01
 * @tc.desc: Test HandleShellDump succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleShellDump01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SHELL_DUMP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string cmd = "this is cmd";
    std::string bundle = "this is bundle";
    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(cmd);
    data.WriteString(bundle);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleShellDump02
 * @tc.desc: Test if the userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleShellDump02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SHELL_DUMP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string cmd = "this is cmd";
    std::string bundle = "this is bundle";
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(cmd);
    data.WriteString(bundle);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}
/**
 * @tc.name: HandleShellDump03
 * @tc.desc: Test if the cmd in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleShellDump03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SHELL_DUMP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string bundle = "this is bundle";
    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(bundle);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}
/**
 * @tc.name: HandleShellDump04
 * @tc.desc: Test if the bundle in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleShellDump04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SHELL_DUMP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string cmd = "this is cmd";
    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(cmd);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublishReminder01
 * @tc.desc: Test Reminder type ALARM.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandlePublishReminder01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::ALARM);
    sptr<ReminderRequest> reminder = new ReminderRequest();
    sptr<ReminderRequestAlarm> reminderRequestAlarm = new ReminderRequestAlarm();
    
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteStrongParcelable(reminder);
    data.WriteParcelable(reminderRequestAlarm);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HandlePublishReminder02
 * @tc.desc: Test Reminder type invalid.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandlePublishReminder02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::INVALID);
    sptr<ReminderRequest> reminder = new ReminderRequest();
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteParcelable(reminder);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: HandlePublishReminder03
 * @tc.desc: Test reminder in date is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandlePublishReminder03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandlePublishReminder04
 * @tc.desc: Test Reminder type TIMER.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandlePublishReminder04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::TIMER);
    sptr<ReminderRequest> reminder = new ReminderRequest();
    sptr<ReminderRequestTimer> reminderRequestTimer = new ReminderRequestTimer();
    
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteStrongParcelable(reminder);
    data.WriteParcelable(reminderRequestTimer);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HandlePublishReminder05
 * @tc.desc: Test Reminder type CALENDAR.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandlePublishReminder05, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::CALENDAR);
    sptr<ReminderRequest> reminder = new ReminderRequest();
    sptr<ReminderRequestCalendar> reminderRequestCalendar = new ReminderRequestCalendar();
    
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteUint8(typeInfo);
    data.WriteStrongParcelable(reminder);
    data.WriteParcelable(reminderRequestCalendar);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HandlePublishReminder06
 * @tc.desc: Test typeInfo in date is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandlePublishReminder06, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::PUBLISH_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<ReminderRequest> reminder = new ReminderRequest();
    sptr<ReminderRequestCalendar> reminderRequestCalendar = new ReminderRequestCalendar();
    
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(reminder);
    data.WriteParcelable(reminderRequestCalendar);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelReminder01
 * @tc.desc: Test HandleCancelReminder ERR_INVALID_OPERATION.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleCancelReminder01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t reminderId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(reminderId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HandleCancelReminder02
 * @tc.desc: Test reminderId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleCancelReminder02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_REMINDER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleCancelAllReminders01
 * @tc.desc: Test HandleCancelAllReminders result ERR_INVALID_OPERATION.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleCancelAllReminders01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::CANCEL_ALL_REMINDERS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HandleGetValidReminders01
 * @tc.desc: Test HandleGetValidReminders result ERR_INVALID_OPERATION.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetValidReminders01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ALL_VALID_REMINDERS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: ReadParcelableVector01
 * @tc.desc: Test ReadParcelableVector result.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, ReadParcelableVector01, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slots.emplace_back(slot);
    MessageParcel data;
    bool ret = ansManagerStub_->ReadParcelableVector(slots, data);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ReadParcelableVector02
 * @tc.desc: Test ReadParcelableVector result.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, ReadParcelableVector02, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slots.emplace_back(slot);
    MessageParcel data;

    int32_t infoSize = 4;
    data.WriteInt32(infoSize);
    data.WriteStrongParcelable(slot);
    bool ret = ansManagerStub_->ReadParcelableVector(slots, data);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: HandleIsSupportTemplate01
 * @tc.desc: Test HandleIsSupportTemplate succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsSupportTemplate01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_SUPPORT_TEMPLATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    std::string templateName = "this is templateName";
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteString(templateName);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsSupportTemplate02
 * @tc.desc: Test templateName in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsSupportTemplate02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_SUPPORT_TEMPLATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleIsSpecialUserAllowedNotifyByUser01
 * @tc.desc: Test HandleIsSpecialUserAllowedNotifyByUser succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsSpecialUserAllowedNotifyByUser01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_SPECIAL_USER_ALLOWED_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleIsSpecialUserAllowedNotifyByUser02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleIsSpecialUserAllowedNotifyByUser02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::IS_SPECIAL_USER_ALLOWED_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledByUser01
 * @tc.desc: Test HandleSetNotificationsEnabledByUser succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledByUser01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleSetNotificationsEnabledByUser02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledByUser02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetNotificationsEnabledByUser03
 * @tc.desc: Test enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetNotificationsEnabledByUser03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_NOTIFICATION_ENABLED_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDeleteAllByUser01
 * @tc.desc: Test HandleDeleteAllByUser succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDeleteAllByUser01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_ALL_NOTIFICATIONS_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleDeleteAllByUser02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDeleteAllByUser02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::DELETE_ALL_NOTIFICATIONS_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetDoNotDisturbDateByUser01
 * @tc.desc: Test HandleSetDoNotDisturbDateByUser succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetDoNotDisturbDateByUser01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_DO_NOT_DISTURB_DATE_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);
    data.WriteStrongParcelable(date);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleSetDoNotDisturbDateByUser02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetDoNotDisturbDateByUser02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_DO_NOT_DISTURB_DATE_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(date);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetDoNotDisturbDateByUser03
 * @tc.desc: Test date in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetDoNotDisturbDateByUser03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_DO_NOT_DISTURB_DATE_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetDoNotDisturbDateByUser01
 * @tc.desc: Test HandleGetDoNotDisturbDateByUser succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetDoNotDisturbDateByUser01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_DO_NOT_DISTURB_DATE_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteParcelable(date);
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleGetDoNotDisturbDateByUser02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetDoNotDisturbDateByUser02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_DO_NOT_DISTURB_DATE_BY_USER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetEnabledForBundleSlot01
 * @tc.desc: Test HandleSetEnabledForBundleSlot succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetEnabledForBundleSlot01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t type = 4;
    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteInt32(type);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleSetEnabledForBundleSlot02
 * @tc.desc: Test bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetEnabledForBundleSlot02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t type = 4;
    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(type);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetEnabledForBundleSlot03
 * @tc.desc: Test type in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetEnabledForBundleSlot03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleSetEnabledForBundleSlot04
 * @tc.desc: Test enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleSetEnabledForBundleSlot04, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t type = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteInt32(type);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetEnabledForBundleSlot01
 * @tc.desc: Test HandleGetEnabledForBundleSlot succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetEnabledForBundleSlot01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int32_t type = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);
    data.WriteInt32(type);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleGetEnabledForBundleSlot02
 * @tc.desc: Test bundleOption in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetEnabledForBundleSlot02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t type = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(type);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleGetEnabledForBundleSlot03
 * @tc.desc: Test type in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleGetEnabledForBundleSlot03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_ENABLED_FOR_BUNDLE_SLOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteStrongParcelable(bundleOption);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDistributedSetEnabledWithoutApp01
 * @tc.desc: Test HandleDistributedSetEnabledWithoutApp succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDistributedSetEnabledWithoutApp01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleDistributedSetEnabledWithoutApp02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDistributedSetEnabledWithoutApp02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    bool enabled = true;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteBool(enabled);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDistributedSetEnabledWithoutApp03
 * @tc.desc: Test enabled in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDistributedSetEnabledWithoutApp03, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::SET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: HandleDistributedGetEnabledWithoutApp01
 * @tc.desc: Test HandleDistributedGetEnabledWithoutApp succeed.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDistributedGetEnabledWithoutApp01, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};

    int32_t userId = 4;
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());
    data.WriteInt32(userId);

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: HandleDistributedGetEnabledWithoutApp02
 * @tc.desc: Test userId in data is null.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HandleDistributedGetEnabledWithoutApp02, Function | SmallTest | Level1)
{
    uint32_t code = static_cast<uint32_t>(AnsManagerInterface::TransactId::GET_SYNC_NOTIFICATION_ENABLED_WITHOUT_APP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    data.WriteInterfaceToken(AnsManagerStub::GetDescriptor());

    ErrCode ret = ansManagerStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: GetSlots01
 * @tc.desc: Test GetSlots return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetSlots01, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slots.emplace_back(slot);

    ErrCode result = ansManagerStub_->GetSlots(slots);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetSpecialActiveNotifications01
 * @tc.desc: Test GetSpecialActiveNotifications return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetSpecialActiveNotifications01, Function | SmallTest | Level1)
{
    std::vector<std::string> keys;
    std::string key = "this is key";
    keys.emplace_back(key);
    std::vector<sptr<Notification>> notifications;
    sptr<Notification> notification = new Notification();
    notifications.emplace_back(notification);

    ErrCode result = ansManagerStub_->GetSpecialActiveNotifications(keys, notifications);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: PublishAsBundle01
 * @tc.desc: Test PublishAsBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, PublishAsBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> notification = new NotificationRequest();
    std::string representativeBundle = "this is representativeBundle";

    ErrCode result = ansManagerStub_->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetNotificationBadgeNum01
 * @tc.desc: Test SetNotificationBadgeNum return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetNotificationBadgeNum01, Function | SmallTest | Level1)
{
    int num = 2;
    ErrCode result = ansManagerStub_->SetNotificationBadgeNum(num);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetBundleImportance01
 * @tc.desc: Test GetBundleImportance return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetBundleImportance01, Function | SmallTest | Level1)
{
    int importance = 2;
    ErrCode result = ansManagerStub_->GetBundleImportance(importance);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HasNotificationPolicyAccessPermission01
 * @tc.desc: Test HasNotificationPolicyAccessPermission return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, HasNotificationPolicyAccessPermission01, Function | SmallTest | Level1)
{
    bool granted = true;
    ErrCode result = ansManagerStub_->HasNotificationPolicyAccessPermission(granted);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetPrivateNotificationsAllowed01
 * @tc.desc: Test SetPrivateNotificationsAllowed return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetPrivateNotificationsAllowed01, Function | SmallTest | Level1)
{
    bool allow = true;
    ErrCode result = ansManagerStub_->SetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetPrivateNotificationsAllowed01
 * @tc.desc: Test GetPrivateNotificationsAllowed return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetPrivateNotificationsAllowed01, Function | SmallTest | Level1)
{
    bool allow = true;
    ErrCode result = ansManagerStub_->GetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: RemoveNotification01
 * @tc.desc: Test RemoveNotification return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, RemoveNotification01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    int notificationId = 4;
    std::string label = "this is label";
    int32_t removeReason = 2;
    ErrCode result = ansManagerStub_->RemoveNotification(bundleOption, notificationId, label, removeReason);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: RemoveAllNotifications01
 * @tc.desc: Test RemoveAllNotifications return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, RemoveAllNotifications01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    ErrCode result = ansManagerStub_->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: Delete01
 * @tc.desc: Test Delete return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, Delete01, Function | SmallTest | Level1)
{
    std::string key = "this is key";
    int32_t removeReason = 2;
    ErrCode result = ansManagerStub_->Delete(key, removeReason);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: DeleteByBundle01
 * @tc.desc: Test DeleteByBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, DeleteByBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    ErrCode result = ansManagerStub_->DeleteByBundle(bundleOption);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: DeleteAll01
 * @tc.desc: Test DeleteAll return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, DeleteAll01, Function | SmallTest | Level1)
{
    ErrCode result = ansManagerStub_->DeleteAll();
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetSlotsByBundle01
 * @tc.desc: Test GetSlotsByBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetSlotsByBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slots.emplace_back(slot);

    ErrCode result = ansManagerStub_->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: UpdateSlots01
 * @tc.desc: Test UpdateSlots return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, UpdateSlots01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot();
    slots.emplace_back(slot);

    ErrCode result = ansManagerStub_->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: RequestEnableNotification01
 * @tc.desc: Test RequestEnableNotification return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, RequestEnableNotification01, Function | SmallTest | Level1)
{
    std::string deviceId = "this is deviceId";
    ErrCode result = ansManagerStub_->RequestEnableNotification(deviceId);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetNotificationsEnabledForBundle01
 * @tc.desc: Test SetNotificationsEnabledForBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetNotificationsEnabledForBundle01, Function | SmallTest | Level1)
{
    std::string bundle = "this is bundle";
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetNotificationsEnabledForBundle(bundle, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundles01
 * @tc.desc: Test SetNotificationsEnabledForAllBundles return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetNotificationsEnabledForAllBundles01, Function | SmallTest | Level1)
{
    std::string deviceId = "this is deviceId";
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetNotificationsEnabledForAllBundles(deviceId, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetNotificationsEnabledForSpecialBundle01
 * @tc.desc: Test SetNotificationsEnabledForSpecialBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetNotificationsEnabledForSpecialBundle01, Function | SmallTest | Level1)
{
    std::string deviceId = "this is deviceId";
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetNotificationsEnabledForSpecialBundle(deviceId, bundleOption, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetShowBadgeEnabledForBundle01
 * @tc.desc: Test SetShowBadgeEnabledForBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetShowBadgeEnabledForBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetShowBadgeEnabledForBundle01
 * @tc.desc: Test GetShowBadgeEnabledForBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetShowBadgeEnabledForBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    ErrCode result = ansManagerStub_->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetShowBadgeEnabled01
 * @tc.desc: Test GetShowBadgeEnabled return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetShowBadgeEnabled01, Function | SmallTest | Level1)
{
    bool enabled = true;

    ErrCode result = ansManagerStub_->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: AreNotificationsSuspended01
 * @tc.desc: Test AreNotificationsSuspended return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, AreNotificationsSuspended01, Function | SmallTest | Level1)
{
    bool suspended = true;

    ErrCode result = ansManagerStub_->AreNotificationsSuspended(suspended);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetCurrentAppSorting01
 * @tc.desc: Test GetCurrentAppSorting return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetCurrentAppSorting01, Function | SmallTest | Level1)
{
    std::vector<NotificationSorting> sortingList;
    sptr<NotificationSortingMap> sortingMap = new NotificationSortingMap(sortingList);

    ErrCode result = ansManagerStub_->GetCurrentAppSorting(sortingMap);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsAllowedNotify01
 * @tc.desc: Test IsAllowedNotify return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsAllowedNotify01, Function | SmallTest | Level1)
{
    bool allowed = true;

    ErrCode result = ansManagerStub_->IsAllowedNotify(allowed);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsAllowedNotifySelf01
 * @tc.desc: Test IsAllowedNotifySelf return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsAllowedNotifySelf01, Function | SmallTest | Level1)
{
    bool allowed = true;

    ErrCode result = ansManagerStub_->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsSpecialBundleAllowedNotify01
 * @tc.desc: Test IsSpecialBundleAllowedNotify return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsSpecialBundleAllowedNotify01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool allowed = true;

    ErrCode result = ansManagerStub_->IsSpecialBundleAllowedNotify(bundleOption, allowed);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: CancelGroup01
 * @tc.desc: Test CancelGroup return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, CancelGroup01, Function | SmallTest | Level1)
{
    std::string groupName = "this is groupName";

    ErrCode result = ansManagerStub_->CancelGroup(groupName);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: RemoveGroupByBundle01
 * @tc.desc: Test RemoveGroupByBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, RemoveGroupByBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    std::string groupName = "this is groupName";

    ErrCode result = ansManagerStub_->RemoveGroupByBundle(bundleOption, groupName);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetDoNotDisturbDate01
 * @tc.desc: Test SetDoNotDisturbDate return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetDoNotDisturbDate01, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();

    ErrCode result = ansManagerStub_->SetDoNotDisturbDate(date);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetDoNotDisturbDate01
 * @tc.desc: Test GetDoNotDisturbDate return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetDoNotDisturbDate01, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();

    ErrCode result = ansManagerStub_->GetDoNotDisturbDate(date);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: DoesSupportDoNotDisturbMode01
 * @tc.desc: Test DoesSupportDoNotDisturbMode return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, DoesSupportDoNotDisturbMode01, Function | SmallTest | Level1)
{
    bool doesSupport = true;

    ErrCode result = ansManagerStub_->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsDistributedEnabled01
 * @tc.desc: Test IsDistributedEnabled return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsDistributedEnabled01, Function | SmallTest | Level1)
{
    bool enabled = true;

    ErrCode result = ansManagerStub_->IsDistributedEnabled(enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: EnableDistributed01
 * @tc.desc: Test EnableDistributed return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, EnableDistributed01, Function | SmallTest | Level1)
{
    bool enabled = true;

    ErrCode result = ansManagerStub_->EnableDistributed(enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: EnableDistributedByBundle01
 * @tc.desc: Test EnableDistributedByBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, EnableDistributedByBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    ErrCode result = ansManagerStub_->EnableDistributedByBundle(bundleOption, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: EnableDistributedSelf01
 * @tc.desc: Test EnableDistributedSelf return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, EnableDistributedSelf01, Function | SmallTest | Level1)
{
    bool enabled = true;

    ErrCode result = ansManagerStub_->EnableDistributedSelf(enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsDistributedEnableByBundle01
 * @tc.desc: Test IsDistributedEnableByBundle return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsDistributedEnableByBundle01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    bool enabled = true;

    ErrCode result = ansManagerStub_->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetDeviceRemindType01
 * @tc.desc: Test GetDeviceRemindType return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetDeviceRemindType01, Function | SmallTest | Level1)
{
    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::NONE;

    ErrCode result = ansManagerStub_->GetDeviceRemindType(remindType);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: PublishContinuousTaskNotification01
 * @tc.desc: Test PublishContinuousTaskNotification return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, PublishContinuousTaskNotification01, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest();

    ErrCode result = ansManagerStub_->PublishContinuousTaskNotification(request);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: CancelContinuousTaskNotification01
 * @tc.desc: Test CancelContinuousTaskNotification return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, CancelContinuousTaskNotification01, Function | SmallTest | Level1)
{
    std::string label = "this is label";
    int32_t notificationId = 4;

    ErrCode result = ansManagerStub_->CancelContinuousTaskNotification(label, notificationId);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: PublishReminder01
 * @tc.desc: Test PublishReminder return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, PublishReminder01, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = new ReminderRequest();

    ErrCode result = ansManagerStub_->PublishReminder(reminder);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: CancelReminder01
 * @tc.desc: Test CancelReminder return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, CancelReminder01, Function | SmallTest | Level1)
{
    int32_t reminderId = 5;

    ErrCode result = ansManagerStub_->CancelReminder(reminderId);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetValidReminders01
 * @tc.desc: Test GetValidReminders return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetValidReminders01, Function | SmallTest | Level1)
{
    std::vector<sptr<ReminderRequest>> reminders;
    sptr<ReminderRequest> reminder = new ReminderRequest();
    reminders.emplace_back(reminder);

    ErrCode result = ansManagerStub_->GetValidReminders(reminders);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: CancelAllReminders01
 * @tc.desc: Test CancelAllReminders return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, CancelAllReminders01, Function | SmallTest | Level1)
{
    ErrCode result = ansManagerStub_->CancelAllReminders();
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsSupportTemplate01
 * @tc.desc: Test IsSupportTemplate return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsSupportTemplate01, Function | SmallTest | Level1)
{
    std::string templateName = "this is templateName";
    bool support = true;

    ErrCode result = ansManagerStub_->IsSupportTemplate(templateName, support);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: IsSpecialUserAllowedNotify01
 * @tc.desc: Test IsSpecialUserAllowedNotify return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, IsSpecialUserAllowedNotify01, Function | SmallTest | Level1)
{
    int32_t userId = 2;
    bool allowed = true;

    ErrCode result = ansManagerStub_->IsSpecialUserAllowedNotify(userId, allowed);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetNotificationsEnabledByUser01
 * @tc.desc: Test SetNotificationsEnabledByUser return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetNotificationsEnabledByUser01, Function | SmallTest | Level1)
{
    int32_t deviceId = 2;
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetNotificationsEnabledByUser(deviceId, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: DeleteAllByUser01
 * @tc.desc: Test DeleteAllByUser return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, DeleteAllByUser01, Function | SmallTest | Level1)
{
    int32_t userId = 2;

    ErrCode result = ansManagerStub_->DeleteAllByUser(userId);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetDoNotDisturbDate02
 * @tc.desc: Test SetDoNotDisturbDate return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetDoNotDisturbDate02, Function | SmallTest | Level1)
{
    int32_t userId = 2;
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();

    ErrCode result = ansManagerStub_->SetDoNotDisturbDate(userId, date);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetDoNotDisturbDate02
 * @tc.desc: Test GetDoNotDisturbDate return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetDoNotDisturbDate02, Function | SmallTest | Level1)
{
    int32_t userId = 2;
    sptr<NotificationDoNotDisturbDate> date = new NotificationDoNotDisturbDate();

    ErrCode result = ansManagerStub_->GetDoNotDisturbDate(userId, date);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetEnabledForBundleSlot01
 * @tc.desc: Test SetEnabledForBundleSlot return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetEnabledForBundleSlot01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetEnabledForBundleSlot01
 * @tc.desc: Test GetEnabledForBundleSlot return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetEnabledForBundleSlot01, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    bool enabled = true;

    ErrCode result = ansManagerStub_->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: ShellDump01
 * @tc.desc: Test ShellDump return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, ShellDump01, Function | SmallTest | Level1)
{
    std::string cmd = "this is cmd";
    std::string bundle = "this is bundle";
    int32_t userId = 5;
    std::vector<std::string> dumpInfo;

    ErrCode result = ansManagerStub_->ShellDump(cmd, bundle, userId, dumpInfo);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetSyncNotificationEnabledWithoutApp01
 * @tc.desc: Test SetSyncNotificationEnabledWithoutApp return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, SetSyncNotificationEnabledWithoutApp01, Function | SmallTest | Level1)
{
    int32_t userId = 2;
    bool enabled = true;

    ErrCode result = ansManagerStub_->SetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetSyncNotificationEnabledWithoutApp01
 * @tc.desc: Test GetSyncNotificationEnabledWithoutApp return.
 * @tc.type: FUNC
 * @tc.require: issueI620XB
 */
HWTEST_F(AnsManagerStubTest, GetSyncNotificationEnabledWithoutApp01, Function | SmallTest | Level1)
{
    int32_t userId = 2;
    bool enabled = true;

    ErrCode result = ansManagerStub_->GetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(result, (int)ERR_INVALID_OPERATION);
}
}
}