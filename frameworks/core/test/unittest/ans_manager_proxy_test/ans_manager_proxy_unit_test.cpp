/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "ans_dialog_host_client.h"
#include "ans_manager_interface.h"
#include "ans_inner_errors.h"
#include "ans_subscriber_listener.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"
#include "notification.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;
using namespace std::placeholders;
using namespace OHOS::Media;

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
    std::shared_ptr<PixelMap> MakeNewPixelMap(int32_t width, int32_t height);
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

int SendRequestGetAllEnableNotifications(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option, int32_t error, int32_t retnum,  bool setError, int32_t notificationNum)
{
    if (setError) {
        reply.WriteInt32(error);
    }

    if (retnum) {
        reply.WriteInt32(retnum);
    }

    if (notificationNum > 0) {
        sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
        for (int32_t i = 0; i < notificationNum; i++) {
            reply.WriteParcelable(bundleOption);
        }
    }

    return 0;
}

class TestSubscriber : public NotificationSubscriber {
public:
    void OnDisconnected() override
    {}
    void OnDied() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnConnected() override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnCanceled(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnConsumed(const std::shared_ptr<Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}

    void OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
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
    ErrCode res = proxy->InnerTransact(static_cast<NotificationInterfaceCode>(code), flags, data, reply);
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
    ErrCode res = proxy->InnerTransact(static_cast<NotificationInterfaceCode>(code), flags, data, reply);
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
    ErrCode res = proxy->InnerTransact(static_cast<NotificationInterfaceCode>(code), flags, data, reply);
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
    ErrCode res = proxy->InnerTransact(static_cast<NotificationInterfaceCode>(code), flags, data, reply);
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

std::shared_ptr<PixelMap> AnsManagerProxyUnitTest::MakeNewPixelMap(int32_t width, int32_t height)
{
    const int32_t PIXEL_BYTES = 4;
    std::shared_ptr<PixelMap> pixelMap = std::make_shared<PixelMap>();
    if (pixelMap == nullptr) {
        return nullptr;
    }
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);
    int32_t rowDataSize = width * PIXEL_BYTES;
    uint32_t bufferSize = rowDataSize * height;
    void *buffer = malloc(bufferSize);
    if (buffer != nullptr) {
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    }
    return pixelMap;
}

/*
 * @tc.name: PublishTest_0700
 * @tc.desc: test Publish function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishTest_0700, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string label = "label";
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    NotificationRequest request(1);
    request.SetSlotType(slotType);
    request.SetNotificationId(1);

    int pictureWidth = 1024;
    int pictureLength = 1024 * 2 + 1;
    auto basicContent = std::make_shared<NotificationBasicContent>();
    basicContent->SetLockScreenPicture(MakeNewPixelMap(pictureWidth, pictureLength));
    auto result = request.CheckLockScreenPictureSizeForLiveView(basicContent);
    EXPECT_EQ(ERR_ANS_PICTURE_OVER_SIZE, result);

    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    liveContent->SetLockScreenPicture(MakeNewPixelMap(1, 1));
    auto content = std::make_shared<NotificationContent>(liveContent);
    request.SetContent(content);

    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    result = proxy->Publish(label, notification);
    EXPECT_EQ(ERR_OK, result);
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
    int32_t result = proxy->Cancel(notificationId, label, "");
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
    int32_t result = proxy->Cancel(notificationId, label, "");
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
    int32_t result = proxy->Cancel(notificationId, label, "");
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
    int32_t result = proxy->Cancel(notificationId, label, "");
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
    int32_t result = proxy->Cancel(notificationId, label, "");
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
    int32_t result = proxy->CancelAll("");
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
    int32_t result = proxy->CancelAll("");
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
    int32_t result = proxy->CancelAll("");
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
    int32_t result = proxy->CancelAll("");
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
 * @tc.name: CancelAsBundleTest_0600
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0600, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->CancelAsBundle(bundleOption, notificationId);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelAsBundleTest_0700
 * @tc.desc: test CancelAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelAsBundleTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelAsBundleTest_0700, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t notificationId = 0;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t userId = 0;
    int32_t result = proxy->CancelAsBundle(bundleOption, notificationId, userId);
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
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    EXPECT_CALL(*iremoteObjects, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
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
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    EXPECT_CALL(*iremoteObjects, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
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
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    int32_t result = proxy->RequestEnableNotification(deviceId, client, callerToken);
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
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    int32_t result = proxy->RequestEnableNotification(deviceId, client, callerToken);
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
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    int32_t result = proxy->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ERR_OK, result);
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
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    int32_t result = proxy->RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
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
        for (int32_t i = 0; i < slotNum; i++) {
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
    EXPECT_EQ(ERR_OK, result);
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
 * @tc.desc: test GetSlotNumAsBundle function
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
        for (int32_t i = 0; i < notificationNum; i++) {
            sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(0);
            reply.WriteStrongParcelable(request);
        }
    }

    return 0;
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0100
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0200
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint32_t soltFlags = 0;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_NE(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0300
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint32_t soltFlags = 0;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_NE(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0400
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_NE(ERR_OK, soltFlags);
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0500
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0600
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, false, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    uint32_t res = 1;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(res, result);
}

/*
 * @tc.name: GetSlotFlagsAsBundleTest_0700
 * @tc.desc: test GetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0700, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->GetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_NE(ERR_OK, result);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0100
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0200
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint32_t soltFlags = 0;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_NE(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0300
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    uint32_t soltFlags = 0;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_NE(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0400
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(ERR_OK, soltFlags);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0500
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0600
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotFlagsAsBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, false, 1, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    uint32_t res = 1;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(res, result);
}

/*
 * @tc.name: SetSlotFlagsAsBundleTest_0700
 * @tc.desc: test SetSlotFlagsAsBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSlotFlagsAsBundleTest_0700, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceNum, _1, _2, _3, _4,
        ERR_OK, true, 1, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    uint32_t soltFlags = 0;
    int32_t result = proxy->SetSlotFlagsAsBundle(bundleOption, soltFlags);
    EXPECT_EQ(ERR_OK, result);
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
    int32_t result = proxy->GetActiveNotifications(notifications, "");
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
    int32_t result = proxy->GetActiveNotifications(notifications, "");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
    EXPECT_EQ(0, notifications.size());
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
    int32_t result = proxy->GetActiveNotifications(notifications, "");
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
    int32_t result = proxy->GetActiveNotifications(notifications, "");
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
    int32_t result = proxy->GetActiveNotifications(notifications, "");
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
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
    EXPECT_EQ(0, notifications.size());
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
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
    EXPECT_EQ(0, notifications.size());
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
 * @tc.name: DeleteAllTest_0100
 * @tc.desc: test DeleteAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteAll();
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DeleteAllTest_0200
 * @tc.desc: test DeleteAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteAll();
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: DeleteAllTest_0300
 * @tc.desc: test DeleteAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteAll();
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: DeleteAllTest_0400
 * @tc.desc: test DeleteAll function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DeleteAllTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DeleteAllTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteAll();
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotsByBundleTest_0100
 * @tc.desc: test GetSlotsByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsByBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsByBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotsByBundleTest_0200
 * @tc.desc: test GetSlotsByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsByBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsByBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: GetSlotsByBundleTest_0300
 * @tc.desc: test GetSlotsByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsByBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsByBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, true, 2)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(2, slots.size());
}
/*
 * @tc.name: GetSlotsByBundleTest_0400
 * @tc.desc: test GetSlotsByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsByBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsByBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSlotsByBundleTest_0500
 * @tc.desc: test GetSlotsByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsByBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsByBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, false, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSlotsByBundleTest_0600
 * @tc.desc: test GetSlotByType function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSlotsByBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSlotsByBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceSlot, _1, _2, _3, _4,
        ERR_OK, true, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->GetSlotsByBundle(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: UpdateSlotsTest_0100
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: UpdateSlotsTest_0200
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: UpdateSlotsTest_0300
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: UpdateSlotsTest_0400
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0400, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    slots.resize(MAX_SLOT_NUM + 1);   // set MAX_SLOT_NUM + 1 slots
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: UpdateSlotsTest_0500
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0500, TestSize.Level1";
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
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: UpdateSlotsTest_0600
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    slots.push_back(slot);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: UpdateSlotsTest_0700
 * @tc.desc: test UpdateSlots function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateSlotsTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateSlotsTest_0700, TestSize.Level1";
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
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->UpdateSlots(bundleOption, slots);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForBundleTest_0100
 * @tc.desc: test SetNotificationsEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForBundle("DeviceId", true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForBundleTest_0200
 * @tc.desc: test SetNotificationsEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForBundle("DeviceId", true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetNotificationsEnabledForBundleTest_0300
 * @tc.desc: test SetNotificationsEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForBundle("DeviceId", true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForBundleTest_0400
 * @tc.desc: test SetNotificationsEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForBundle("DeviceId", true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForAllBundlesTest_0100
 * @tc.desc: test SetNotificationsEnabledForAllBundles function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForAllBundles("DeviceId", true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForAllBundlesTest_0200
 * @tc.desc: test SetNotificationsEnabledForAllBundles function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForAllBundles("DeviceId", true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetNotificationsEnabledForAllBundlesTest_0300
 * @tc.desc: test SetNotificationsEnabledForAllBundles function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForAllBundles("DeviceId", true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForAllBundlesTest_0400
 * @tc.desc: test SetNotificationsEnabledForAllBundles function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForAllBundlesTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNotificationsEnabledForAllBundles("DeviceId", true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForSpecialBundleTest_0100
 * @tc.desc: test SetNotificationsEnabledForSpecialBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetNotificationsEnabledForSpecialBundle("DeviceId", bundleOption, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForSpecialBundleTest_0200
 * @tc.desc: test SetNotificationsEnabledForSpecialBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetNotificationsEnabledForSpecialBundle("DeviceId", bundleOption, true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetNotificationsEnabledForSpecialBundleTest_0300
 * @tc.desc: test SetNotificationsEnabledForSpecialBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetNotificationsEnabledForSpecialBundle("DeviceId", bundleOption, true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForSpecialBundleTest_0400
 * @tc.desc: test SetNotificationsEnabledForSpecialBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetNotificationsEnabledForSpecialBundle("DeviceId", bundleOption, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetNotificationsEnabledForSpecialBundleTest_0500
 * @tc.desc: test SetNotificationsEnabledForSpecialBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetNotificationsEnabledForSpecialBundleTest_0500, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t result = proxy->SetNotificationsEnabledForSpecialBundle("DeviceId", bundleOption, true);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: SetShowBadgeEnabledForBundleTest_0100
 * @tc.desc: test SetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetShowBadgeEnabledForBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetShowBadgeEnabledForBundleTest_0200
 * @tc.desc: test SetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetShowBadgeEnabledForBundle(bundleOption, true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetShowBadgeEnabledForBundleTest_0300
 * @tc.desc: test SetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetShowBadgeEnabledForBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetShowBadgeEnabledForBundleTest_0400
 * @tc.desc: test SetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetShowBadgeEnabledForBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetShowBadgeEnabledForBundleTest_0500
 * @tc.desc: test SetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetShowBadgeEnabledForBundleTest_0500, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t result = proxy->SetShowBadgeEnabledForBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: GetShowBadgeEnabledForBundleTest_0100
 * @tc.desc: test GetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledForBundleTest_0200
 * @tc.desc: test GetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    EXPECT_CALL(*iremoteObjects, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: GetShowBadgeEnabledForBundleTest_0300
 * @tc.desc: test GetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledForBundleTest_0400
 * @tc.desc: test GetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledForBundleTest_0500
 * @tc.desc: test GetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledForBundleTest_0600
 * @tc.desc: test GetShowBadgeEnabledForBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledForBundleTest_0600, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t result = proxy->GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: GetShowBadgeEnabledTest_0100
 * @tc.desc: test GetShowBadgeEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledTest_0200
 * @tc.desc: test GetShowBadgeEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: GetShowBadgeEnabledTest_0300
 * @tc.desc: test GetShowBadgeEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledTest_0400
 * @tc.desc: test GetShowBadgeEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetShowBadgeEnabledTest_0500
 * @tc.desc: test GetShowBadgeEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetShowBadgeEnabledTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SubscribeTest_0100
 * @tc.desc: test Subscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SubscribeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SubscribeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Subscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SubscribeTest_0200
 * @tc.desc: test Subscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SubscribeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SubscribeTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    EXPECT_CALL(*iremoteObjects, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Subscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: SubscribeTest_0300
 * @tc.desc: test Subscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SubscribeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SubscribeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Subscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SubscribeTest_0400
 * @tc.desc: test Subscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SubscribeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SubscribeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Subscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SubscribeTest_0500
 * @tc.desc: test Subscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SubscribeTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SubscribeTest_0500, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Subscribe(nullptr, subInfo);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: UnsubscribeTest_0100
 * @tc.desc: test Unsubscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UnsubscribeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UnsubscribeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Unsubscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: UnsubscribeTest_0200
 * @tc.desc: test Unsubscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UnsubscribeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UnsubscribeTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Unsubscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: UnsubscribeTest_0300
 * @tc.desc: test Unsubscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UnsubscribeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UnsubscribeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Unsubscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: UnsubscribeTest_0400
 * @tc.desc: test Unsubscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UnsubscribeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UnsubscribeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    auto subscriber = new (std::nothrow) TestSubscriber();
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Unsubscribe(subscriber->GetImpl(), subInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: UnsubscribeTest_0500
 * @tc.desc: test Unsubscribe function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, UnsubscribeTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UnsubscribeTest_0500, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationSubscribeInfo> subInfo = new (std::nothrow) NotificationSubscribeInfo();
    int32_t result = proxy->Unsubscribe(nullptr, subInfo);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: IsAllowedNotifyTest_0100
 * @tc.desc: test IsAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifyTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifyTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotify(allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifyTest_0200
 * @tc.desc: test IsAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifyTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifyTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotify(allowed);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, allowed);
}

/*
 * @tc.name: IsAllowedNotifyTest_0300
 * @tc.desc: test IsAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifyTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifyTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotify(allowed);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifyTest_0400
 * @tc.desc: test IsAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifyTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifyTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotify(allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifyTest_0500
 * @tc.desc: test IsAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifyTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifyTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotify(allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifySelfTest_0100
 * @tc.desc: test IsAllowedNotifySelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifySelfTest_0200
 * @tc.desc: test IsAllowedNotifySelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, allowed);
}

/*
 * @tc.name: IsAllowedNotifySelfTest_0300
 * @tc.desc: test IsAllowedNotifySelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifySelfTest_0400
 * @tc.desc: test IsAllowedNotifySelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsAllowedNotifySelfTest_0500
 * @tc.desc: test IsAllowedNotifySelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsAllowedNotifySelfTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool allowed = false;
    int32_t result = proxy->IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialBundleAllowedNotifyTest_0100
 * @tc.desc: test IsSpecialBundleAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->IsSpecialBundleAllowedNotify(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialBundleAllowedNotifyTest_0200
 * @tc.desc: test IsSpecialBundleAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->IsSpecialBundleAllowedNotify(bundleOption, enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: IsSpecialBundleAllowedNotifyTest_0300
 * @tc.desc: test IsSpecialBundleAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->IsSpecialBundleAllowedNotify(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsSpecialBundleAllowedNotifyTest_0400
 * @tc.desc: test IsSpecialBundleAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->IsSpecialBundleAllowedNotify(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialBundleAllowedNotifyTest_0500
 * @tc.desc: test IsSpecialBundleAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->IsSpecialBundleAllowedNotify(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsSpecialBundleAllowedNotifyTest_0600
 * @tc.desc: test IsSpecialBundleAllowedNotify function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsSpecialBundleAllowedNotifyTest_0600, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t result = proxy->IsSpecialBundleAllowedNotify(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: CancelGroupTest_0100
 * @tc.desc: test CancelGroup function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelGroupTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelGroupTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelGroup("GroupName", "");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelGroupTest_0200
 * @tc.desc: test CancelGroup function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelGroupTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelGroupTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelGroup("GroupName", "");
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: CancelGroupTest_0300
 * @tc.desc: test CancelGroup function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelGroupTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelGroupTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelGroup("GroupName", "");
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CancelGroupTest_0400
 * @tc.desc: test CancelGroup function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelGroupTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelGroupTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelGroup("GroupName", "");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveGroupByBundleTest_0100
 * @tc.desc: test RemoveGroupByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveGroupByBundle(bundleOption, "GroupName");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: RemoveGroupByBundleTest_0200
 * @tc.desc: test RemoveGroupByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveGroupByBundle(bundleOption, "GroupName");
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: RemoveGroupByBundleTest_0300
 * @tc.desc: test RemoveGroupByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveGroupByBundle(bundleOption, "GroupName");
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: RemoveGroupByBundleTest_0400
 * @tc.desc: test RemoveGroupByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, RemoveGroupByBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->RemoveGroupByBundle(bundleOption, "GroupName");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_0100
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t result = proxy->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_0200
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t result = proxy->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_0300
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t result = proxy->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetDoNotDisturbDateTest_0400
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t result = proxy->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_0500
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t result = proxy->SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetDoNotDisturbDateTest_0100
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t result = proxy->GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetDoNotDisturbDateTest_0200
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t result = proxy->GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}
/*
 * @tc.name: GetDoNotDisturbDateTest_0300
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t result = proxy->GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetDoNotDisturbDateTest_0400
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t result = proxy->GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DoesSupportDoNotDisturbModeTest_0100
 * @tc.desc: test DoesSupportDoNotDisturbMode function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool doesSupport = false;
    int32_t result = proxy->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DoesSupportDoNotDisturbModeTest_0200
 * @tc.desc: test DoesSupportDoNotDisturbMode function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool doesSupport = false;
    int32_t result = proxy->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, doesSupport);
}

/*
 * @tc.name: DoesSupportDoNotDisturbModeTest_0300
 * @tc.desc: test DoesSupportDoNotDisturbMode function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool doesSupport = false;
    int32_t result = proxy->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: DoesSupportDoNotDisturbModeTest_0400
 * @tc.desc: test DoesSupportDoNotDisturbMode function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool doesSupport = false;
    int32_t result = proxy->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: DoesSupportDoNotDisturbModeTest_0500
 * @tc.desc: test DoesSupportDoNotDisturbMode function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DoesSupportDoNotDisturbModeTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool doesSupport = false;
    int32_t result = proxy->DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnabledTest_0100
 * @tc.desc: test IsDistributedEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnabledTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnabledTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnabled(enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnabledTest_0200
 * @tc.desc: test IsDistributedEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnabledTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnabledTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnabled(enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: IsDistributedEnabledTest_0300
 * @tc.desc: test IsDistributedEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnabledTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnabledTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnabled(enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnabledTest_0400
 * @tc.desc: test IsDistributedEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnabledTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnabledTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnabled(enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnabledTest_0500
 * @tc.desc: test IsDistributedEnabled function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnabledTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnabledTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnabled(enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: EnableDistributedTest_0100
 * @tc.desc: test EnableDistributed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributed(true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: EnableDistributedTest_0200
 * @tc.desc: test EnableDistributed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributed(true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: EnableDistributedTest_0300
 * @tc.desc: test EnableDistributed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributed(true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: EnableDistributedTest_0400
 * @tc.desc: test EnableDistributed function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributed(true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: EnableDistributedByBundleTest_0100
 * @tc.desc: test EnableDistributedByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->EnableDistributedByBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: EnableDistributedByBundleTest_0200
 * @tc.desc: test EnableDistributedByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = nullptr;
    int32_t result = proxy->EnableDistributedByBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: EnableDistributedByBundleTest_0300
 * @tc.desc: test EnableDistributedByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->EnableDistributedByBundle(bundleOption, true);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: EnableDistributedByBundleTest_0400
 * @tc.desc: test EnableDistributedByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->EnableDistributedByBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: EnableDistributedByBundleTest_0500
 * @tc.desc: test EnableDistributedByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedByBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->EnableDistributedByBundle(bundleOption, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: EnableDistributedSelfTest_0100
 * @tc.desc: test EnableDistributedSelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedSelfTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedSelfTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributedSelf(true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: EnableDistributedSelfTest_0200
 * @tc.desc: test EnableDistributedSelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedSelfTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedSelfTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributedSelf(true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: EnableDistributedSelfTest_0300
 * @tc.desc: test EnableDistributedSelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedSelfTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedSelfTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributedSelf(true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: EnableDistributedSelfTest_0400
 * @tc.desc: test EnableDistributedSelf function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, EnableDistributedSelfTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, EnableDistributedSelfTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->EnableDistributedSelf(true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnableByBundleTest_0100
 * @tc.desc: test IsDistributedEnableByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnableByBundleTest_0200
 * @tc.desc: test IsDistributedEnableByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: IsDistributedEnableByBundleTest_0300
 * @tc.desc: test IsDistributedEnableByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: IsDistributedEnableByBundleTest_0400
 * @tc.desc: test IsDistributedEnableByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnableByBundleTest_0500
 * @tc.desc: test IsDistributedEnableByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsDistributedEnableByBundleTest_0600
 * @tc.desc: test IsDistributedEnableByBundle function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsDistributedEnableByBundleTest_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bool enabled = false;
    int32_t result = proxy->IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishContinuousTaskNotificationTest_0100
 * @tc.desc: test PublishContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationRequest> notification = nullptr;
    int32_t result = proxy->PublishContinuousTaskNotification(notification);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: PublishContinuousTaskNotificationTest_0200
 * @tc.desc: test PublishContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    std::shared_ptr<AnsManagerProxy> ansManagerProxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, ansManagerProxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = ansManagerProxy->PublishContinuousTaskNotification(notification);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishContinuousTaskNotificationTest_0300
 * @tc.desc: test PublishContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->PublishContinuousTaskNotification(notification);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: PublishContinuousTaskNotificationTest_0400
 * @tc.desc: test PublishContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0400, TestSize.Level1";
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
    int32_t result = proxy->PublishContinuousTaskNotification(notification);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: PublishContinuousTaskNotificationTest_0500
 * @tc.desc: test PublishContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, PublishContinuousTaskNotificationTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    NotificationRequest request(1);
    sptr<NotificationRequest> notification = new (std::nothrow) NotificationRequest(request);
    ASSERT_NE(nullptr, notification);
    int32_t result = proxy->PublishContinuousTaskNotification(notification);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CancelContinuousTaskNotificationTest_0100
 * @tc.desc: test CancelContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelContinuousTaskNotification("label", 0);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: CancelContinuousTaskNotificationTest_0200
 * @tc.desc: test CancelContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelContinuousTaskNotification("label", 0);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: CancelContinuousTaskNotificationTest_0300
 * @tc.desc: test CancelContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelContinuousTaskNotification("label", 0);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: CancelContinuousTaskNotificationTest_0400
 * @tc.desc: test CancelContinuousTaskNotification function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, CancelContinuousTaskNotificationTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CancelContinuousTaskNotification("label", 0);
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

/*
 * @tc.name: SetDoNotDisturbDateTest_2_0100
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t userId = 100; // 100 default user
    int32_t result = proxy->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_2_0200
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t userId = 100; // 100 default user
    int32_t result = proxy->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_2_0300
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t userId = 100; // 100 default user
    int32_t result = proxy->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetDoNotDisturbDateTest_2_0400
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t userId = 100; // 100 default user
    int32_t result = proxy->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetDoNotDisturbDateTest_2_0500
 * @tc.desc: test SetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetDoNotDisturbDateTest_2_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = new (std::nothrow) NotificationDoNotDisturbDate();
    int32_t userId = 100; // 100 default user
    int32_t result = proxy->SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetDoNotDisturbDateTest_2_0100
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t userId = 0;
    int32_t result = proxy->GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetDoNotDisturbDateTest_2_0200
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t userId = 0;
    int32_t result = proxy->GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}
/*
 * @tc.name: GetDoNotDisturbDateTest_2_0300
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t userId = 0;
    int32_t result = proxy->GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetDoNotDisturbDateTest_2_0400
 * @tc.desc: test GetDoNotDisturbDate function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetDoNotDisturbDateTest_2_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> doNotDisturbDate = nullptr;
    int32_t userId = 0;
    int32_t result = proxy->GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetEnabledForBundleSlotTest_0100
 * @tc.desc: test SetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetEnabledForBundleSlot(
        bundleOption, NotificationConstant::SOCIAL_COMMUNICATION, true, false);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetEnabledForBundleSlotTest_0200
 * @tc.desc: test SetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = nullptr;
    int32_t result = proxy->SetEnabledForBundleSlot(
        bundleOption, NotificationConstant::SOCIAL_COMMUNICATION, true, false);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: SetEnabledForBundleSlotTest_0300
 * @tc.desc: test SetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetEnabledForBundleSlot(
        bundleOption, NotificationConstant::SOCIAL_COMMUNICATION, true, false);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: SetEnabledForBundleSlotTest_0400
 * @tc.desc: test SetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetEnabledForBundleSlot(
        bundleOption, NotificationConstant::SOCIAL_COMMUNICATION, true, false);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetEnabledForBundleSlotTest_0500
 * @tc.desc: test SetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetEnabledForBundleSlotTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption  = new (std::nothrow) NotificationBundleOption();
    int32_t result = proxy->SetEnabledForBundleSlot(
        bundleOption, NotificationConstant::SOCIAL_COMMUNICATION, true, false);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetEnabledForBundleSlotTest_0100
 * @tc.desc: test GetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetEnabledForBundleSlotTest_0200
 * @tc.desc: test GetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> ansManagerProxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, ansManagerProxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    bool enabled = false;
    int32_t result = ansManagerProxy->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: GetEnabledForBundleSlotTest_0300
 * @tc.desc: test GetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetEnabledForBundleSlotTest_0400
 * @tc.desc: test GetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetEnabledForBundleSlotTest_0500
 * @tc.desc: test GetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetEnabledForBundleSlotTest_0600
 * @tc.desc: test GetEnabledForBundleSlot function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetEnabledForBundleSlotTest_0600, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = nullptr;
    NotificationConstant::SlotType slotType = NotificationConstant::SOCIAL_COMMUNICATION;
    int32_t result = proxy->GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/*
 * @tc.name: SetSyncNotificationEnabledWithoutAppTest_0100
 * @tc.desc: test SetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetSyncNotificationEnabledWithoutApp(0, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetSyncNotificationEnabledWithoutAppTest_0200
 * @tc.desc: test SetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetSyncNotificationEnabledWithoutApp(0, true);
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetSyncNotificationEnabledWithoutAppTest_0300
 * @tc.desc: test SetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetSyncNotificationEnabledWithoutApp(0, true);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetSyncNotificationEnabledWithoutAppTest_0400
 * @tc.desc: test SetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetSyncNotificationEnabledWithoutAppTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetSyncNotificationEnabledWithoutApp(0, true);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSyncNotificationEnabledWithoutAppTest_0100
 * @tc.desc: test GetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetSyncNotificationEnabledWithoutApp(0, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSyncNotificationEnabledWithoutAppTest_0200
 * @tc.desc: test GetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0200, TestSize.Level1";
        MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetSyncNotificationEnabledWithoutApp(0, enabled);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(true, enabled);
}

/*
 * @tc.name: GetSyncNotificationEnabledWithoutAppTest_0300
 * @tc.desc: test GetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetSyncNotificationEnabledWithoutApp(0, enabled);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetSyncNotificationEnabledWithoutAppTest_0400
 * @tc.desc: test GetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetSyncNotificationEnabledWithoutApp(0, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetSyncNotificationEnabledWithoutAppTest_0500
 * @tc.desc: test GetSyncNotificationEnabledWithoutApp function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetSyncNotificationEnabledWithoutAppTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool enabled = false;
    int32_t result = proxy->GetSyncNotificationEnabledWithoutApp(0, enabled);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

int SendRequestReplaceDumpInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, int32_t num)
{
    if (setError) {
        reply.WriteInt32(error);
    }

    if (num > 0) {
        std::vector<std::string> vecDump;
        for (int32_t i = 0; i < num; i++) {
            std::string info = std::to_string(i);
            vecDump.push_back(info);
        }
        reply.WriteStringVector(vecDump);
    }

    return 0;
}
/*
 * @tc.name: ShellDumpTest_0100
 * @tc.desc: test ShellDump function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, ShellDumpTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, ShellDumpTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> dumpInfo;
    int32_t result = proxy->ShellDump("anm dump -A", "BundleName", 0, 0, dumpInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: ShellDumpTest_0200
 * @tc.desc: test ShellDump function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, ShellDumpTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, ShellDumpTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceDumpInfo, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> dumpInfo;
    int32_t result = proxy->ShellDump("anm dump -A", "BundleName", 0, 0, dumpInfo);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, dumpInfo.size());
}

/*
 * @tc.name: ShellDumpTest_0300
 * @tc.desc: test ShellDump function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, ShellDumpTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, ShellDumpTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObjects = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObjects);
    EXPECT_CALL(*iremoteObjects, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceDumpInfo, _1, _2, _3, _4,
        ERR_OK, false, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> ansManagerProxy = std::make_shared<AnsManagerProxy>(iremoteObjects);
    ASSERT_NE(nullptr, ansManagerProxy);
    std::vector<std::string> dumpInfo;
    int32_t result = ansManagerProxy->ShellDump("anm dump -A", "BundleName", 0, 0, dumpInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: ShellDumpTest_0400
 * @tc.desc: test ShellDump function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, ShellDumpTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, ShellDumpTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> dumpInfo;
    int32_t result = proxy->ShellDump("anm dump -A", "BundleName", 0, 0, dumpInfo);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: ShellDumpTest_0500
 * @tc.desc: test ShellDump function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, ShellDumpTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, ShellDumpTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceDumpInfo, _1, _2, _3, _4,
        ERR_OK, false, 0)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<std::string> dumpInfo;
    int32_t result = proxy->ShellDump("anm dump -A", "BundleName", 0, 0, dumpInfo);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetBadgeNumberTest_0100
 * @tc.desc: test SetBadgeNumber function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetBadgeNumberTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t userId = 0;
    int32_t result = proxy->SetBadgeNumber(userId, "");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: SetBadgeNumberTest_0200
 * @tc.desc: test SetBadgeNumber function
 * @tc.type: FUNC
 * @tc.require: #I6C2X9
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetBadgeNumberTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t badgeNumber = 0;
    int32_t result = proxy->SetBadgeNumber(badgeNumber, "");
    EXPECT_EQ(ERR_OK, result);
}
/*
 * @tc.name: SetBadgeNumberTest_0300
 * @tc.desc: test SetBadgeNumber function
 * @tc.type: FUNC
 * @tc.require: #I6C2X9
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetBadgeNumberTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t badgeNumber = 0;
    int32_t result = proxy->SetBadgeNumber(badgeNumber, "");
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: SetBadgeNumberTest_0400
 * @tc.desc: test SetBadgeNumber function
 * @tc.type: FUNC
 * @tc.require: #I6C2X9
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, SetBadgeNumberTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t badgeNumber = 0;
    int32_t result = proxy->SetBadgeNumber(badgeNumber, "");
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/**
 * @tc.name: SetBadgeNumberByBundleTest_0100
 * @tc.desc: test SetBadgeNumberByBundle with null bundleOption, expect ErrCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberByBundleTest_0100, TestSize.Level1)
{
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t badgeNumber = 0;
    int32_t result = proxy->SetBadgeNumberByBundle(nullptr, badgeNumber);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/**
 * @tc.name: SetBadgeNumberByBundleTest_0200
 * @tc.desc: test SetBadgeNumberByBundle with invalid proxy object, expect ErrCode ERR_ANS_PARCELABLE_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberByBundleTest_0200, TestSize.Level1)
{
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    ASSERT_NE(nullptr, bundleOption);
    std::string bundleName = "bundleName";
    bundleOption->SetBundleName(bundleName);
    int32_t badgeNumber = 0;
    int32_t result = proxy->SetBadgeNumberByBundle(bundleOption, badgeNumber);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/**
 * @tc.name: SetBadgeNumberByBundleTest_0300
 * @tc.desc: test SetBadgeNumberByBundle with empty bundleOption, expect ErrCode ERR_ANS_PARCELABLE_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, SetBadgeNumberByBundleTest_0300, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    ASSERT_NE(nullptr, bundleOption);
    std::string bundleName = "bundleName";
    bundleOption->SetBundleName(bundleName);
    int32_t badgeNumber = 0;
    int32_t result = proxy->SetBadgeNumberByBundle(bundleOption, badgeNumber);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: GetAllNotificationEnabledBundles_0100
 * @tc.desc: test GetAllNotificationEnabledBundles function
 * @tc.type: FUNC
 * @tc.require: #I92VGR
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<NotificationBundleOption> bundleOption;
    int32_t result = proxy->GetAllNotificationEnabledBundles(bundleOption);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetAllNotificationEnabledBundles_0200
 * @tc.desc: test GetAllNotificationEnabledBundles function
 * @tc.type: FUNC
 * @tc.require: #I92VGR
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestGetAllEnableNotifications, _1, _2, _3, _4,
        ERR_OK, true, 1, 1)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<NotificationBundleOption> bundleOption;
    int32_t result = proxy->GetAllNotificationEnabledBundles(bundleOption);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: GetAllNotificationEnabledBundles_0300
 * @tc.desc: test SetBadgeNumber function
 * @tc.type: FUNC
 * @tc.require: #I92VGR
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0300, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<NotificationBundleOption> bundleOption;
    int32_t result = proxy->GetAllNotificationEnabledBundles(bundleOption);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: GetAllNotificationEnabledBundles_0400
 * @tc.desc: test GetAllNotificationEnabledBundles function
 * @tc.type: FUNC
 * @tc.require: #I92VGR
 */
HWTEST_F(AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetAllNotificationEnabledBundles_0400, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<NotificationBundleOption> bundleOption;
    int32_t result = proxy->GetAllNotificationEnabledBundles(bundleOption);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationByFilterTest_0100
 * @tc.desc: test GetActiveNotificationByFilter function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationByFilterTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationByFilterTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    int32_t notificationId = 0;
    std::string label = "label";
    std::vector<std::string> extraInfoKeys;

    NotificationRequest request(1);
    sptr<NotificationRequest> liveViewRequest = new (std::nothrow) NotificationRequest(request);

    int32_t result = proxy->GetActiveNotificationByFilter(bundleOption, notificationId, label,
        extraInfoKeys, liveViewRequest);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: GetActiveNotificationByFilterTest_0200
 * @tc.desc: test GetActiveNotificationByFilter function
 * @tc.type: FUNC
 * @tc.require: #I5XO2O
 */
HWTEST_F(AnsManagerProxyUnitTest, GetActiveNotificationByFilterTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, GetActiveNotificationByFilterTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    sptr<NotificationBundleOption> bundleOption = nullptr;
    int32_t notificationId = 0;
    std::string label = "label";
    std::vector<std::string> extraInfoKeys;

    NotificationRequest request(1);
    sptr<NotificationRequest> liveViewRequest = new (std::nothrow) NotificationRequest(request);

    int32_t result = proxy->GetActiveNotificationByFilter(bundleOption, notificationId, label,
        extraInfoKeys, liveViewRequest);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, result);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0100
 * @tc.desc: test AddDoNotDisturbProfiles when profiles is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, AddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    auto res = proxy->AddDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, res);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0200
 * @tc.desc: test AddDoNotDisturbProfiles when WriteInterfaceToken return false.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, AddDoNotDisturbProfiles_0200, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t id = 1;
    std::string name = "Name";
    std::vector<NotificationBundleOption> trustlist;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> disturbProfile =
        new (std::nothrow) NotificationDoNotDisturbProfile(id, name, trustlist);
    profiles.emplace_back(disturbProfile);

    MockWriteInterfaceToken(false);
    auto res = proxy->AddDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, res);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0300
 * @tc.desc: test AddDoNotDisturbProfiles run success and return result.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, AddDoNotDisturbProfiles_0300, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t id = 1;
    std::string name = "Name";
    std::vector<NotificationBundleOption> trustlist;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> disturbProfile =
        new (std::nothrow) NotificationDoNotDisturbProfile(id, name, trustlist);
    profiles.emplace_back(disturbProfile);

    MockWriteInterfaceToken(true);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillRepeatedly(
            DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
            ERR_OK, false, true, true)), Return(NO_ERROR)));
    auto res = proxy->AddDoNotDisturbProfiles(profiles);
    EXPECT_NE(ERR_OK, res);
    EXPECT_NE(ERR_ANS_PARCELABLE_FAILED, res);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0100
 * @tc.desc: test RemoveDoNotDisturbProfiles when profiles is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveDoNotDisturbProfiles_0100, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    auto res = proxy->RemoveDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, res);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0200
 * @tc.desc: test RemoveDoNotDisturbProfiles when WriteInterfaceToken return false.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveDoNotDisturbProfiles_0200, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t id = 1;
    std::string name = "Name";
    std::vector<NotificationBundleOption> trustlist;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> disturbProfile =
        new (std::nothrow) NotificationDoNotDisturbProfile(id, name, trustlist);
    profiles.emplace_back(disturbProfile);

    MockWriteInterfaceToken(false);
    auto res = proxy->RemoveDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, res);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0300
 * @tc.desc: test RemoveDoNotDisturbProfiles run success and return result.
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, RemoveDoNotDisturbProfiles_0300, TestSize.Level1)
{
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t id = 1;
    std::string name = "Name";
    std::vector<NotificationBundleOption> trustlist;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> disturbProfile =
        new (std::nothrow) NotificationDoNotDisturbProfile(id, name, trustlist);
    profiles.emplace_back(disturbProfile);

    MockWriteInterfaceToken(true);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .Times(1)
        .WillRepeatedly(
            DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
            ERR_OK, false, true, true)), Return(NO_ERROR)));
    auto res = proxy->RemoveDoNotDisturbProfiles(profiles);
    EXPECT_NE(ERR_OK, res);
    EXPECT_NE(ERR_ANS_PARCELABLE_FAILED, res);
}

/*
 * @tc.name: IsNeedSilentInDoNotDisturbModeTest_0100
 * @tc.desc: test IsNeedSilentInDoNotDisturbMode function
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t result = proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsNeedSilentInDoNotDisturbModeTest_0200
 * @tc.desc: test IsNeedSilentInDoNotDisturbMode function
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0200, TestSize.Level1";
    MockWriteInterfaceToken(true);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, true)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t result = proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: IsNeedSilentInDoNotDisturbModeTest_0300
 * @tc.desc: test IsNeedSilentInDoNotDisturbMode function
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t result = proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ERR_ANS_TRANSACT_FAILED, result);
}

/*
 * @tc.name: IsNeedSilentInDoNotDisturbModeTest_0400
 * @tc.desc: test IsNeedSilentInDoNotDisturbMode function
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, false, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t result = proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ERR_ANS_PARCELABLE_FAILED, result);
}

/*
 * @tc.name: IsNeedSilentInDoNotDisturbModeTest_0500
 * @tc.desc: test IsNeedSilentInDoNotDisturbMode function
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, IsNeedSilentInDoNotDisturbModeTest_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, true, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    int32_t result = proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: UpdateNotificationTimerByUid_0100
 * @tc.desc: test UpdateNotificationTimerByUid function
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, UpdateNotificationTimerByUid_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, UpdateNotificationTimerByUid_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t uid = 20099999;
    bool isPaused = true;
    int32_t result = proxy->UpdateNotificationTimerByUid(uid, isPaused);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: DisableNotificationFeature_0100
 * @tc.desc: test DisableNotificationFeature
 * @tc.type: FUNC
 */
HWTEST_F(AnsManagerProxyUnitTest, DisableNotificationFeature_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsManagerProxyUnitTest, DisableNotificationFeature_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true, false, false)), Return(NO_ERROR)));
    std::shared_ptr<AnsManagerProxy> proxy = std::make_shared<AnsManagerProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    sptr<NotificationDisable> notificationDisable = nullptr;
    ErrCode res = proxy->DisableNotificationFeature(notificationDisable);
    EXPECT_EQ(res, ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
