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

}
}