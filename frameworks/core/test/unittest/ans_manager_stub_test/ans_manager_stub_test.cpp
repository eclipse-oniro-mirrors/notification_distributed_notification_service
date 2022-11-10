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
}
}