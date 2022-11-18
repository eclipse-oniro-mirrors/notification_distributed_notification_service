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
#include "notification_subscriber.h"
#undef private
#undef protected
#include "ans_const_define.h"
#include "ans_manager_interface.h"
#include "ans_inner_errors.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"
#include "notification.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;
using namespace std::placeholders;

extern void MockWriteInterfaceToken(bool mockRet);

namespace OHOS {
namespace Notification {
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

int SendRequestReplaceNum(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, uint64_t retNum, bool setRetNum)
{
    if (setError) {
        reply.WriteInt32(error);
    }
    if (setRetNum) {
        reply.WriteUint64(retNum);
    }
    return 0;
}

int SendRequestReplaceString(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, std::string retStr, bool setRetStr)
{
    if (setError) {
        reply.WriteInt32(error);
    }
    if (setRetStr) {
        reply.WriteString(retStr);
    }
    return 0;
}

class TestSubscriber : public NotificationSubscriber {
public:
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
};

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

/*
 * @tc.name: RemoveSlotByTypeTest_0100
 * @tc.desc: test RemoveSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->RemoveSlotByType(slotType);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveSlotByTypeTest_0200
 * @tc.desc: test RemoveSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->RemoveSlotByType(slotType);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: RemoveSlotByTypeTest_0300
 * @tc.desc: test RemoveSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->RemoveSlotByType(slotType);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: RemoveSlotByTypeTest_0400
 * @tc.desc: test RemoveSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveSlotByTypeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->RemoveSlotByType(slotType);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveAllSlotsTest_0100
 * @tc.desc: test RemoveAllSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllSlotsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllSlotsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->RemoveAllSlots();
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveAllSlotsTest_0200
 * @tc.desc: test RemoveAllSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllSlotsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllSlotsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->RemoveAllSlots();
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: RemoveAllSlotsTest_0300
 * @tc.desc: test RemoveAllSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllSlotsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllSlotsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->RemoveAllSlots();
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: RemoveAllSlotsTest_0400
 * @tc.desc: test RemoveAllSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllSlotsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllSlotsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->RemoveAllSlots();
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

int SendRequestReplaceSlot(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, int32_t slotNum)
{
    if (setError) {
        reply.WriteInt32(error);
    }

    if (slotNum == 1) {
        sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
        reply.WriteParcelable(slot);
    }
    if (slotNum > 1) {
        reply.WriteInt32(slotNum);
        for (size_t i = 0; i < slotNum; i++) {
            sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
            reply.WriteStrongParcelable(slot);
        }
    }
    return 0;
}

/*
 * @tc.name: GetSlotByTypeTest_0100
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotByTypeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotByTypeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    sptr<NotificationSlot> slot = nullptr;
    int32_t result = proxy->GetSlotByType(slotType, slot);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotByTypeTest_0200
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotByTypeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotByTypeTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    sptr<NotificationSlot> slot = nullptr;
    int32_t result = proxy->GetSlotByType(slotType, slot);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_NE(nullptr, slot);
}
/*
 * @tc.name: GetSlotByTypeTest_0300
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotByTypeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotByTypeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    sptr<NotificationSlot> slot = nullptr;
    int32_t result = proxy->GetSlotByType(slotType, slot);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSlotByTypeTest_0400
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotByTypeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotByTypeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, false, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    sptr<NotificationSlot> slot = nullptr;
    int32_t result = proxy->GetSlotByType(slotType, slot);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotByTypeTest_0500
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotByTypeTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotByTypeTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, true, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    sptr<NotificationSlot> slot = nullptr;
    int32_t result = proxy->GetSlotByType(slotType, slot);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotsTest_0100
 * @tc.desc: test GetSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlots(slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotsTest_0200
 * @tc.desc: test GetSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, true, 2)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlots(slots);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(2, slots.size());
}
/*
 * @tc.name: GetSlotsTest_0300
 * @tc.desc: test GetSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlots(slots);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSlotsTest_0400
 * @tc.desc: test GetSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, false, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlots(slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotsTest_0500
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, true, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlots(slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotNumAsBundleTest_0100
 * @tc.desc: test GetSlotNumAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint64_t num = 0;
    int32_t result = proxy->GetSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotNumAsBundleTest_0200
 * @tc.desc: test PublishToDevice function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint64_t num = 0;
    int32_t result = proxy->GetSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: GetSlotNumAsBundleTest_0300
 * @tc.desc: test GetSlotNumAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint64_t num = 0;
    int32_t result = proxy->GetSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, num);
}

/*
 * @tc.name: GetSlotNumAsBundleTest_0400
 * @tc.desc: test GetSlotNumAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint64_t num = 0;
    int32_t result = proxy->GetSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSlotNumAsBundleTest_0500
 * @tc.desc: test GetSlotNumAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, false, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint64_t num = 0;
    int32_t result = proxy->GetSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotNumAsBundleTest_0600
 * @tc.desc: test GetSlotNumAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotNumAsBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint64_t num = 0;
    int32_t result = proxy->GetSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

int SendRequestReplaceNotifications(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, int32_t notificationNum)
{
    if (setError) {
        reply.WriteInt32(error);
    }

    if (notificationNum > 0) {
        reply.WriteInt32(notificationNum);
        for (size_t i = 0; i < notificationNum; i++) {
            sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(0);
            reply.WriteStrongParcelable(request);
        }
    }

    return 0;
}
/*
 * @tc.name: GetActiveNotificationsTest_0100
 * @tc.desc: test GetActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationRequest>> notifications;
    int32_t result = proxy->GetActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationsTest_0200
 * @tc.desc: test GetActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationRequest>> notifications;
    int32_t result = proxy->GetActiveNotifications(notifications);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, notifications.size());
}
/*
 * @tc.name: GetActiveNotificationsTest_0300
 * @tc.desc: test GetActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationRequest>> notifications;
    int32_t result = proxy->GetActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationsTest_0400
 * @tc.desc: test GetActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, false, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationRequest>> notifications;
    int32_t result = proxy->GetActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationsTest_0500
 * @tc.desc: test GetActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, true, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationRequest>> notifications;
    int32_t result = proxy->GetActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationNumsTest_0100
 * @tc.desc: test GetActiveNotificationNums function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint64_t num = 0;
    int32_t result = proxy->GetActiveNotificationNums(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationNumsTest_0200
 * @tc.desc: test GetActiveNotificationNums function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint64_t num = 0;
    int32_t result = proxy->GetActiveNotificationNums(num);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, num);
}

/*
 * @tc.name: GetActiveNotificationNumsTest_0300
 * @tc.desc: test GetActiveNotificationNums function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint64_t num = 0;
    int32_t result = proxy->GetActiveNotificationNums(num);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationNumsTest_0400
 * @tc.desc: test GetActiveNotificationNums function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, false, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint64_t num = 0;
    int32_t result = proxy->GetActiveNotificationNums(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationNumsTest_0500
 * @tc.desc: test GetActiveNotificationNums function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationNumsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    uint64_t num = 0;
    int32_t result = proxy->GetActiveNotificationNums(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetAllActiveNotificationsTest_0100
 * @tc.desc: test GetAllActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetAllActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetAllActiveNotificationsTest_0200
 * @tc.desc: test GetAllActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetAllActiveNotifications(notifications);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, notifications.size());
}
/*
 * @tc.name: GetAllActiveNotificationsTest_0300
 * @tc.desc: test GetAllActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetAllActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetAllActiveNotificationsTest_0400
 * @tc.desc: test GetAllActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, false, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetAllActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetAllActiveNotificationsTest_0500
 * @tc.desc: test GetAllActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllActiveNotificationsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, true, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetAllActiveNotifications(notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSpecialActiveNotificationsTest_0100
 * @tc.desc: test GetSpecialActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> key;
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetSpecialActiveNotifications(key, notifications);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: GetSpecialActiveNotificationsTest_0200
 * @tc.desc: test GetSpecialActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> key{"0", "1"};
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetSpecialActiveNotifications(key, notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSpecialActiveNotificationsTest_0300
 * @tc.desc: test GetSpecialActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> key{"0", "1"};
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetSpecialActiveNotifications(key, notifications);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, notifications.size());
}
/*
 * @tc.name: GetSpecialActiveNotificationsTest_0400
 * @tc.desc: test GetSpecialActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> key{"0", "1"};
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetSpecialActiveNotifications(key, notifications);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSpecialActiveNotificationsTest_0500
 * @tc.desc: test GetSpecialActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, false, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> key{"0", "1"};
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetSpecialActiveNotifications(key, notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSpecialActiveNotificationsTest_0600
 * @tc.desc: test GetSpecialActiveNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSpecialActiveNotificationsTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNotifications, _1, _2, _3, _4,
        ERR_OK, true, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> key{"0", "1"};
    std::vector<sptr<Notification>> notifications;
    int32_t result = proxy->GetSpecialActiveNotifications(key, notifications);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationAgentTest_0100
 * @tc.desc: test SetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationAgentTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationAgentTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent = "agent";
    int32_t result = proxy->SetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationAgentTest_0200
 * @tc.desc: test SetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationAgentTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationAgentTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent = "";
    int32_t result = proxy->SetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: SetNotificationAgentTest_0300
 * @tc.desc: test SetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationAgentTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationAgentTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent = "agent";
    int32_t result = proxy->SetNotificationAgent(agent);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetNotificationAgentTest_0400
 * @tc.desc: test SetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationAgentTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationAgentTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent = "agent";
    int32_t result = proxy->SetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetNotificationAgentTest_0500
 * @tc.desc: test SetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationAgentTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationAgentTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent = "agent";
    int32_t result = proxy->SetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetNotificationAgentTest_0100
 * @tc.desc: test GetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetNotificationAgentTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetNotificationAgentTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent;
    int32_t result = proxy->GetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetNotificationAgentTest_0200
 * @tc.desc: test GetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetNotificationAgentTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetNotificationAgentTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceString, _1, _2, _3, _4,
        ERR_OK, true, "0", true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent;
    int32_t result = proxy->GetNotificationAgent(agent);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: GetNotificationAgentTest_0300
 * @tc.desc: test GetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetNotificationAgentTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetNotificationAgentTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent;
    int32_t result = proxy->GetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetNotificationAgentTest_0400
 * @tc.desc: test GetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetNotificationAgentTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetNotificationAgentTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceString, _1, _2, _3, _4,
        ERR_OK, false, "0", true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent;
    int32_t result = proxy->GetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetNotificationAgentTest_0500
 * @tc.desc: test GetNotificationAgent function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetNotificationAgentTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetNotificationAgentTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceString, _1, _2, _3, _4,
        ERR_OK, true, "0", false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string agent;
    int32_t result = proxy->GetNotificationAgent(agent);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CanPublishAsBundleTest_0100
 * @tc.desc: test CanPublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CanPublishAsBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CanPublishAsBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string representativeBundle = "Bundle";
    bool canPublish = false;
    int32_t result = proxy->CanPublishAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CanPublishAsBundleTest_0200
 * @tc.desc: test CanPublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CanPublishAsBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CanPublishAsBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string representativeBundle = "";
    bool canPublish = false;
    int32_t result = proxy->CanPublishAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: CanPublishAsBundleTest_0300
 * @tc.desc: test CanPublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CanPublishAsBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CanPublishAsBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string representativeBundle = "Bundle";
    bool canPublish = false;
    int32_t result = proxy->CanPublishAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, canPublish);
}

/*
 * @tc.name: CanPublishAsBundleTest_0400
 * @tc.desc: test CanPublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CanPublishAsBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CanPublishAsBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string representativeBundle = "Bundle";
    bool canPublish = false;
    int32_t result = proxy->CanPublishAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CanPublishAsBundleTest_0500
 * @tc.desc: test CanPublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CanPublishAsBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CanPublishAsBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string representativeBundle = "Bundle";
    bool canPublish = false;
    int32_t result = proxy->CanPublishAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CanPublishAsBundleTest_0600
 * @tc.desc: test CanPublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CanPublishAsBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CanPublishAsBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string representativeBundle = "Bundle";
    bool canPublish = false;
    int32_t result = proxy->CanPublishAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishAsBundleTest_0100
 * @tc.desc: test PublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishAsBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishAsBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    std::string representativeBundle = "Bundle";
    int32_t result = proxy->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishAsBundleTest_0200
 * @tc.desc: test PublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishAsBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishAsBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationRequest> notification = nullptr;
    std::string representativeBundle = "Bundle";
    int32_t result = proxy->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: PublishAsBundleTest_0300
 * @tc.desc: test PublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishAsBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishAsBundleTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    std::string representativeBundle = "";
    int32_t result = proxy->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: PublishAsBundleTest_0400
 * @tc.desc: test PublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishAsBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishAsBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    std::string representativeBundle = "Bundle";
    int32_t result = proxy->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: PublishAsBundleTest_0500
 * @tc.desc: test PublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishAsBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishAsBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    std::string representativeBundle = "Bundle";
    int32_t result = proxy->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: PublishAsBundleTest_0600
 * @tc.desc: test PublishAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishAsBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishAsBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    std::string representativeBundle = "Bundle";
    int32_t result = proxy->PublishAsBundle(notification, representativeBundle);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationBadgeNumTest_0100
 * @tc.desc: test SetNotificationBadgeNum function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->SetNotificationBadgeNum(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationBadgeNumTest_0200
 * @tc.desc: test SetNotificationBadgeNum function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->SetNotificationBadgeNum(num);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetNotificationBadgeNumTest_0300
 * @tc.desc: test SetNotificationBadgeNum function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->SetNotificationBadgeNum(num);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetNotificationBadgeNumTest_0400
 * @tc.desc: test SetNotificationBadgeNum function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationBadgeNumTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->SetNotificationBadgeNum(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetBundleImportanceTest_0100
 * @tc.desc: test GetBundleImportance function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetBundleImportanceTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetBundleImportanceTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->GetBundleImportance(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetBundleImportanceTest_0200
 * @tc.desc: test GetBundleImportance function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetBundleImportanceTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetBundleImportanceTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->GetBundleImportance(num);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, num);
}

/*
 * @tc.name: GetBundleImportanceTest_0300
 * @tc.desc: test GetBundleImportance function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetBundleImportanceTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetBundleImportanceTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->GetBundleImportance(num);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetBundleImportanceTest_0400
 * @tc.desc: test GetBundleImportance function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetBundleImportanceTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetBundleImportanceTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, false, 1, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->GetBundleImportance(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetBundleImportanceTest_0500
 * @tc.desc: test GetBundleImportance function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetBundleImportanceTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetBundleImportanceTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t num = 0;
    int32_t result = proxy->GetBundleImportance(num);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}


/*
 * @tc.name: HasNotificationPolicyAccessPermissionTest_0100
 * @tc.desc: test HasNotificationPolicyAccessPermission function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool granted = false;
    int32_t result = proxy->HasNotificationPolicyAccessPermission(granted);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: HasNotificationPolicyAccessPermissionTest_0200
 * @tc.desc: test HasNotificationPolicyAccessPermission function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool granted = false;
    int32_t result = proxy->HasNotificationPolicyAccessPermission(granted);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, granted);
}

/*
 * @tc.name: HasNotificationPolicyAccessPermissionTest_0300
 * @tc.desc: test HasNotificationPolicyAccessPermission function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool granted = false;
    int32_t result = proxy->HasNotificationPolicyAccessPermission(granted);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: HasNotificationPolicyAccessPermissionTest_0400
 * @tc.desc: test HasNotificationPolicyAccessPermission function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool granted = false;
    int32_t result = proxy->HasNotificationPolicyAccessPermission(granted);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: HasNotificationPolicyAccessPermissionTest_0500
 * @tc.desc: test HasNotificationPolicyAccessPermission function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, HasNotificationPolicyAccessPermissionTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool granted = false;
    int32_t result = proxy->HasNotificationPolicyAccessPermission(granted);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetPrivateNotificationsAllowedTest_0100
 * @tc.desc: test SetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = true;
    int32_t result = proxy->SetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetPrivateNotificationsAllowedTest_0200
 * @tc.desc: test SetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = true;
    int32_t result = proxy->SetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetPrivateNotificationsAllowedTest_0300
 * @tc.desc: test SetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = true;
    int32_t result = proxy->SetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetPrivateNotificationsAllowedTest_0400
 * @tc.desc: test SetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetPrivateNotificationsAllowedTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = true;
    int32_t result = proxy->SetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetPrivateNotificationsAllowedTest_0100
 * @tc.desc: test GetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = false;
    int32_t result = proxy->GetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetPrivateNotificationsAllowedTest_0200
 * @tc.desc: test GetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = false;
    int32_t result = proxy->GetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, allow);
}

/*
 * @tc.name: GetPrivateNotificationsAllowedTest_0300
 * @tc.desc: test GetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = false;
    int32_t result = proxy->GetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetPrivateNotificationsAllowedTest_0400
 * @tc.desc: test GetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = false;
    int32_t result = proxy->GetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetPrivateNotificationsAllowedTest_0500
 * @tc.desc: test GetPrivateNotificationsAllowed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetPrivateNotificationsAllowedTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allow = false;
    int32_t result = proxy->GetPrivateNotificationsAllowed(allow);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveNotificationTest_0100
 * @tc.desc: test RemoveNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveNotificationTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveNotificationTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveNotification(bundleOption, 0, "0", 0);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveNotificationTest_0200
 * @tc.desc: test RemoveNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveNotificationTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveNotificationTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = nullptr;
    int32_t result = proxy->RemoveNotification(bundleOption, 0, "0", 0);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: RemoveNotificationTest_0300
 * @tc.desc: test RemoveNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveNotificationTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveNotificationTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveNotification(bundleOption, 0, "0", 0);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RemoveNotificationTest_0400
 * @tc.desc: test RemoveNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveNotificationTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveNotificationTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveNotification(bundleOption, 0, "0", 0);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: RemoveNotificationTest_0500
 * @tc.desc: test RemoveNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveNotificationTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveNotificationTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveNotification(bundleOption, 0, "0", 0);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveAllNotificationsTest_0100
 * @tc.desc: test RemoveAllNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveAllNotificationsTest_0200
 * @tc.desc: test RemoveAllNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = nullptr;
    int32_t result = proxy->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: RemoveAllNotificationsTest_0300
 * @tc.desc: test RemoveAllNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RemoveAllNotificationsTest_0400
 * @tc.desc: test RemoveAllNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: RemoveAllNotificationsTest_0500
 * @tc.desc: test RemoveAllNotifications function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveAllNotificationsTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteTest_0100
 * @tc.desc: test Delete function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->Delete("key", 0);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteTest_0200
 * @tc.desc: test Delete function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->Delete("", 0);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: DeleteTest_0300
 * @tc.desc: test Delete function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->Delete("key", 0);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: DeleteTest_0400
 * @tc.desc: test Delete function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->Delete("key", 0);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: DeleteTest_0500
 * @tc.desc: test Delete function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->Delete("key", 0);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteByBundleTest_0100
 * @tc.desc: test DeleteByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteByBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteByBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->DeleteByBundle(bundleOption);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteByBundleTest_0200
 * @tc.desc: test DeleteByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteByBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteByBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = nullptr;
    int32_t result = proxy->DeleteByBundle(bundleOption);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: DeleteByBundleTest_0300
 * @tc.desc: test DeleteByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteByBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteByBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->DeleteByBundle(bundleOption);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: DeleteByBundleTest_0400
 * @tc.desc: test DeleteByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteByBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteByBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->DeleteByBundle(bundleOption);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: DeleteByBundleTest_0500
 * @tc.desc: test DeleteByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteByBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteByBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->DeleteByBundle(bundleOption);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSupportTemplateTest_0100
 * @tc.desc: test IsSupportTemplate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSupportTemplateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSupportTemplateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string templateName = "TemplateName";
    bool support = false;
    int32_t result = proxy->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSupportTemplateTest_0200
 * @tc.desc: test IsSupportTemplate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSupportTemplateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSupportTemplateTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string templateName = "TemplateName";
    bool support = false;
    int32_t result = proxy->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSupportTemplateTest_0300
 * @tc.desc: test IsSupportTemplate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSupportTemplateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSupportTemplateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string templateName = "TemplateName";
    bool support = false;
    int32_t result = proxy->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, support);
}

/*
 * @tc.name: IsSupportTemplateTest_0400
 * @tc.desc: test IsSupportTemplate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSupportTemplateTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSupportTemplateTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string templateName = "TemplateName";
    bool support = false;
    int32_t result = proxy->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsSupportTemplateTest_0500
 * @tc.desc: test IsSupportTemplate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSupportTemplateTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSupportTemplateTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string templateName = "TemplateName";
    bool support = false;
    int32_t result = proxy->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSupportTemplateTest_0600
 * @tc.desc: test IsSupportTemplate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSupportTemplateTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSupportTemplateTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string templateName = "TemplateName";
    bool support = false;
    int32_t result = proxy->IsSupportTemplate(templateName, support);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialUserAllowedNotifyTest_0100
 * @tc.desc: test IsSpecialUserAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool allowed = false;
    int32_t result = proxy->IsSpecialUserAllowedNotify(userId, allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialUserAllowedNotifyTest_0200
 * @tc.desc: test IsSpecialUserAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool allowed = false;
    int32_t result = proxy->IsSpecialUserAllowedNotify(userId, allowed);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, allowed);
}

/*
 * @tc.name: IsSpecialUserAllowedNotifyTest_0300
 * @tc.desc: test IsSpecialUserAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool allowed = false;
    int32_t result = proxy->IsSpecialUserAllowedNotify(userId, allowed);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsSpecialUserAllowedNotifyTest_0400
 * @tc.desc: test IsSpecialUserAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool allowed = false;
    int32_t result = proxy->IsSpecialUserAllowedNotify(userId, allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialUserAllowedNotifyTest_0500
 * @tc.desc: test IsSpecialUserAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialUserAllowedNotifyTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool allowed = false;
    int32_t result = proxy->IsSpecialUserAllowedNotify(userId, allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledByUserTest_0100
 * @tc.desc: test SetNotificationsEnabledByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool enabled = true;
    int32_t result = proxy->SetNotificationsEnabledByUser(userId, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledByUserTest_0200
 * @tc.desc: test SetNotificationsEnabledByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool enabled = true;
    int32_t result = proxy->SetNotificationsEnabledByUser(userId, enabled);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetNotificationsEnabledByUserTest_0300
 * @tc.desc: test SetNotificationsEnabledByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool enabled = true;
    int32_t result = proxy->SetNotificationsEnabledByUser(userId, enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledByUserTest_0400
 * @tc.desc: test SetNotificationsEnabledByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledByUserTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    bool enabled = true;
    int32_t result = proxy->SetNotificationsEnabledByUser(userId, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteAllByUserTest_0100
 * @tc.desc: test DeleteAllByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllByUserTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllByUserTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    int32_t result = proxy->DeleteAllByUser(userId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteAllByUserTest_0200
 * @tc.desc: test DeleteAllByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllByUserTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllByUserTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    int32_t result = proxy->DeleteAllByUser(userId);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: DeleteAllByUserTest_0300
 * @tc.desc: test DeleteAllByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllByUserTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllByUserTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    int32_t result = proxy->DeleteAllByUser(userId);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: DeleteAllByUserTest_0400
 * @tc.desc: test DeleteAllByUser function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllByUserTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllByUserTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    int32_t result = proxy->DeleteAllByUser(userId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}
}  // namespace Notification
}  // namespace OHOS