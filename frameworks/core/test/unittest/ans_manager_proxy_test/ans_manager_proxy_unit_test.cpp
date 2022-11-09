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

#include <functional>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "ans_manager_proxy.h"
#undef private
#undef protected
#include "ans_const_define.h"
#include "ans_manager_interface.h"
#include "ans_inner_errors.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;
using namespace std::placeholders;

extern void MockWriteInterfaceToken(bool mockRet);

class AnsManagerProxyUnitTest : public testing::Test {
public:
    AnsManagerProxyUnitTest() {}

    virtual ~AnsManagerProxyUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AnsManagerProxyUnitTest::SetUpTestCase()
{
    MockWriteInterfaceToken(true);
}

void AnsManagerProxyUnitTest::TearDownTestCase() {}

void AnsManagerProxyUnitTest::SetUp() {}

void AnsManagerProxyUnitTest::TearDown() {}

int SendRequestReplace(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, bool retBool, bool setRetBool)
{
    if (setError) {
        reply.WriteInt32(error);
    }
    if (setRetBool) {
        reply.WriteBool(retBool);
    }
    return 0;
}

/*
 * @tc.name: InnerTransactTest_0100
 * @tc.desc: test if AnsManagerProxy's InnerTransact function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, InnerTransactTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, InnerTransactTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).WillOnce(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint32_t code = 0;
    MessageOption flags;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = proxy->InnerTransact(code, flags, data, reply);
    EXPECT_EQ(ERR_OK, res);
}

/*
 * @tc.name: InnerTransactTest_0200
 * @tc.desc: test AnsManagerProxy's InnerTransact function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, InnerTransactTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, InnerTransactTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).WillOnce(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint32_t code = 0;
    MessageOption flags;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = proxy->InnerTransact(code, flags, data, reply);
    EXPECT_EQ(ERR_DEAD_OBJECT, res);
}

/*
 * @tc.name: InnerTransactTest_0300
 * @tc.desc: test AnsManagerProxy's InnerTransact function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, InnerTransactTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, InnerTransactTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).WillOnce(DoAll(Return(-1)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint32_t code = 0;
    MessageOption flags;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = proxy->InnerTransact(code, flags, data, reply);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, res);
}

/*
 * @tc.name: InnerTransactTest_0400
 * @tc.desc: test AnsManagerProxy's InnerTransact function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, InnerTransactTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, InnerTransactTest_0400, TestSize.Level1";
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(nullptr);
    ASSERT_NE(nullptr, proxy);
    uint32_t code = 0;
    MessageOption flags;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = proxy->InnerTransact(code, flags, data, reply);
    EXPECT_EQ(ERR_DEAD_OBJECT, res);
}

/*
 * @tc.name: PublishTest_0100
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "label";
    sptr<NotificationRequest> notification = nullptr;
    int32_t result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: PublishTest_0200
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "label";
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishTest_0300
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "";
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishTest_0400
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "label";
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: PublishTest_0500
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "label";
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: PublishTest_0600
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "label";
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishToDeviceTest_0100
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishToDeviceTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishToDeviceTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationRequest> notification = nullptr;
    std::string deviceId = "Device";
    int32_t result = proxy->PublishToDevice(notification, deviceId);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: PublishToDeviceTest_0200
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishToDeviceTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishToDeviceTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    std::string deviceId = "Device";
    int32_t result = proxy->PublishToDevice(notification, deviceId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishToDeviceTest_0300
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishToDeviceTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishToDeviceTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    std::string deviceId = "";
    int32_t result = proxy->PublishToDevice(notification, deviceId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishToDeviceTest_0400
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishToDeviceTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishToDeviceTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    std::string deviceId = "Device";
    int32_t result = proxy->PublishToDevice(notification, deviceId);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: PublishToDeviceTest_0500
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishToDeviceTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishToDeviceTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    std::string deviceId = "Device";
    int32_t result = proxy->PublishToDevice(notification, deviceId);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: PublishToDeviceTest_0600
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishToDeviceTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishToDeviceTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    std::string deviceId = "Device";
    int32_t result = proxy->PublishToDevice(notification, deviceId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelTest_0100
 * @tc.desc: test Cancel function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string label = "label";
    int32_t result = proxy->Cancel(notificationId, label);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelTest_0200
 * @tc.desc: test Cancel function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string label = "";
    int32_t result = proxy->Cancel(notificationId, label);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelTest_0300
 * @tc.desc: test Cancel function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string label = "label";
    int32_t result = proxy->Cancel(notificationId, label);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: CancelTest_0400
 * @tc.desc: test Cancel function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string label = "label";
    int32_t result = proxy->Cancel(notificationId, label);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CancelTest_0500
 * @tc.desc: test Cancel function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string label = "label";
    int32_t result = proxy->Cancel(notificationId, label);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelAllTest_0100
 * @tc.desc: test CancelAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAllTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAllTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelAll();
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelAllTest_0200
 * @tc.desc: test CancelAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAllTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAllTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelAll();
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: CancelAllTest_0300
 * @tc.desc: test CancelAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAllTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAllTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelAll();
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CancelAllTest_0400
 * @tc.desc: test CancelAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAllTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAllTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelAll();
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelAsBundleTest_0100
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string representativeBundle = "Bundle";
    int32_t userId = 0;
    int32_t result = proxy->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelAsBundleTest_0200
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string representativeBundle = "";
    int32_t userId = 0;
    int32_t result = proxy->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelAsBundleTest_0300
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string representativeBundle = "Bundle";
    int32_t userId = 0;
    int32_t result = proxy->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: CancelAsBundleTest_0400
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string representativeBundle = "Bundle";
    int32_t userId = 0;
    int32_t result = proxy->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CancelAsBundleTest_0500
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    std::string representativeBundle = "Bundle";
    int32_t userId = 0;
    int32_t result = proxy->CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: AddSlotByTypeTest_0100
 * @tc.desc: test AddSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotByTypeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotByTypeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->AddSlotByType(slotType);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: AddSlotByTypeTest_0200
 * @tc.desc: test AddSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotByTypeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotByTypeTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->AddSlotByType(slotType);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: AddSlotByTypeTest_0300
 * @tc.desc: test AddSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotByTypeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotByTypeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->AddSlotByType(slotType);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: AddSlotByTypeTest_0400
 * @tc.desc: test AddSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotByTypeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotByTypeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->AddSlotByType(slotType);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: AddSlotsTest_0100
 * @tc.desc: test AddSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotsTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->AddSlots(slots);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: AddSlotsTest_0200
 * @tc.desc: test AddSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->AddSlots(slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: AddSlotsTest_0300
 * @tc.desc: test AddSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotsTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    slots.resize(MAX_SLOT_NUM + 1);   // set MAX_SLOT_NUM + 1 slots
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->AddSlots(slots);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: AddSlotsTest_0400
 * @tc.desc: test AddSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->AddSlots(slots);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: AddSlotsTest_0500
 * @tc.desc: test AddSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->AddSlots(slots);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: AddSlotsTest_0600
 * @tc.desc: test AddSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, AddSlotsTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, AddSlotsTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->AddSlots(slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RequestEnableNotificationTest_0100
 * @tc.desc: test RequestEnableNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RequestEnableNotificationTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RequestEnableNotificationTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "Device";
    bool popFlag = false;
    int32_t result = proxy->RequestEnableNotification(deviceId, popFlag);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RequestEnableNotificationTest_0200
 * @tc.desc: test RequestEnableNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RequestEnableNotificationTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RequestEnableNotificationTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "";
    bool popFlag = false;
    int32_t result = proxy->RequestEnableNotification(deviceId, popFlag);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RequestEnableNotificationTest_0300
 * @tc.desc: test RequestEnableNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RequestEnableNotificationTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RequestEnableNotificationTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "Device";
    bool popFlag = false;
    int32_t result = proxy->RequestEnableNotification(deviceId, popFlag);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, popFlag);
}

/*
 * @tc.name: RequestEnableNotificationTest_0400
 * @tc.desc: test RequestEnableNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RequestEnableNotificationTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RequestEnableNotificationTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "Device";
    bool popFlag = false;
    int32_t result = proxy->RequestEnableNotification(deviceId, popFlag);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: RequestEnableNotificationTest_0500
 * @tc.desc: test RequestEnableNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RequestEnableNotificationTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RequestEnableNotificationTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "Device";
    bool popFlag = false;
    int32_t result = proxy->RequestEnableNotification(deviceId, popFlag);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RequestEnableNotificationTest_0600
 * @tc.desc: test RequestEnableNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RequestEnableNotificationTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RequestEnableNotificationTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "Device";
    bool popFlag = false;
    int32_t result = proxy->RequestEnableNotification(deviceId, popFlag);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}
