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
#include "ans_subscriber_proxy.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "ipc_types.h"
#include "mock_i_remote_object.h"
#include "notification.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsSubscriberProxyUnitTest : public testing::Test {
public:
    AnsSubscriberProxyUnitTest() {}

    virtual ~AnsSubscriberProxyUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AnsSubscriberProxyUnitTest::SetUpTestCase() {}

void AnsSubscriberProxyUnitTest::TearDownTestCase() {}

void AnsSubscriberProxyUnitTest::SetUp() {}

void AnsSubscriberProxyUnitTest::TearDown() {}

/*
 * @tc.name: InnerTransactTest_0100
 * @tc.desc: test if AnsSubscriberProxy's InnerTransact function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, InnerTransactTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, InnerTransactTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).WillOnce(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
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
 * @tc.desc: test AnsSubscriberProxy's InnerTransact function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, InnerTransactTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, InnerTransactTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).WillOnce(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
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
 * @tc.desc: test AnsSubscriberProxy's InnerTransact function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, InnerTransactTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, InnerTransactTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).WillOnce(DoAll(Return(-1)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
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
 * @tc.desc: test AnsSubscriberProxy's InnerTransact function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, InnerTransactTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, InnerTransactTest_0400, TestSize.Level1";
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(nullptr);
    ASSERT_NE(nullptr, proxy);
    uint32_t code = 0;
    MessageOption flags;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = proxy->InnerTransact(code, flags, data, reply);
    EXPECT_EQ(ERR_DEAD_OBJECT, res);
}

/*
 * @tc.name: OnConsumed_0100
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    proxy->OnConsumed(notification);
}

/*
 * @tc.name: OnConsumed_0200
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    proxy->OnConsumed(notification);
}

/*
 * @tc.name: OnConsumed_0300
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(0);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnConsumed(nullptr);
}

/*
 * @tc.name: OnConsumed_0400
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    proxy->OnConsumed(notification, notificationMap);
}

/*
 * @tc.name: OnConsumed_0500
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    proxy->OnConsumed(notification, notificationMap);
}

/*
 * @tc.name: OnConsumed_0600
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(0);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    proxy->OnConsumed(nullptr, notificationMap);
}

/*
 * @tc.name: OnConsumed_0700
 * @tc.desc: test AnsSubscriberProxy's OnConsumed function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConsumed_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConsumed_0700, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    proxy->OnConsumed(notification, nullptr);
}

/*
 * @tc.name: OnCanceled_0400
 * @tc.desc: test AnsSubscriberProxy's OnCanceled function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnCanceled_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnCanceled_0400, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    int32_t deleteReason = 0;
    proxy->OnCanceled(notification, notificationMap, deleteReason);
}

/*
 * @tc.name: OnCanceled_0500
 * @tc.desc: test AnsSubscriberProxy's OnCanceled function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnCanceled_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnCanceled_0500, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    int32_t deleteReason = 0;
    proxy->OnCanceled(notification, notificationMap, deleteReason);
}

/*
 * @tc.name: OnCanceled_0600
 * @tc.desc: test AnsSubscriberProxy's OnCanceled function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnCanceled_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnCanceled_0600, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(0);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    int32_t deleteReason = 0;
    proxy->OnCanceled(nullptr, notificationMap, deleteReason);
}

/*
 * @tc.name: OnCanceled_0700
 * @tc.desc: test AnsSubscriberProxy's OnCanceled function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnCanceled_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnCanceled_0700, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification();
    ASSERT_NE(nullptr, notification);
    int32_t deleteReason = 0;
    proxy->OnCanceled(notification, nullptr, deleteReason);
}

/*
 * @tc.name: OnUpdated_0100
 * @tc.desc: test AnsSubscriberProxy's OnUpdated function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnUpdated_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnUpdated_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    proxy->OnUpdated(notificationMap);
}

/*
 * @tc.name: OnUpdated_0200
 * @tc.desc: test AnsSubscriberProxy's OnUpdated function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnUpdated_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnUpdated_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    ASSERT_NE(nullptr, notificationMap);
    proxy->OnUpdated(notificationMap);
}

/*
 * @tc.name: OnOnUpdated_0300
 * @tc.desc: test AnsSubscriberProxy's OnUpdated function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnOnUpdated_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnOnUpdated_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(0);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnUpdated(nullptr);
}

/*
 * @tc.name: OnDoNotDisturbDateChange_0100
 * @tc.desc: test AnsSubscriberProxy's OnDoNotDisturbDateChange function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnDoNotDisturbDateChange_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnDoNotDisturbDateChange_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> date = new (std::nothrow) NotificationDoNotDisturbDate();
    ASSERT_NE(nullptr, date);
    proxy->OnDoNotDisturbDateChange(date);
}

/*
 * @tc.name: OnDoNotDisturbDateChange_0200
 * @tc.desc: test AnsSubscriberProxy's OnDoNotDisturbDateChange function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnDoNotDisturbDateChange_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnDoNotDisturbDateChange_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationDoNotDisturbDate> date = new (std::nothrow) NotificationDoNotDisturbDate();
    ASSERT_NE(nullptr, date);
    proxy->OnDoNotDisturbDateChange(date);
}

/*
 * @tc.name: OnEnabledNotificationChanged_0100
 * @tc.desc: test AnsSubscriberProxy's OnEnabledNotificationChanged function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnEnabledNotificationChanged_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnEnabledNotificationChanged_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<EnabledNotificationCallbackData> callbackData = new (std::nothrow) EnabledNotificationCallbackData();
    ASSERT_NE(nullptr, callbackData);
    proxy->OnEnabledNotificationChanged(callbackData);
}

/*
 * @tc.name: OnEnabledNotificationChanged_0200
 * @tc.desc: test AnsSubscriberProxy's OnEnabledNotificationChanged function
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnEnabledNotificationChanged_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnEnabledNotificationChanged_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<EnabledNotificationCallbackData> callbackData = new (std::nothrow) EnabledNotificationCallbackData();
    ASSERT_NE(nullptr, callbackData);
    proxy->OnEnabledNotificationChanged(callbackData);
}

/*
 * @tc.name: OnConnected_0100
 * @tc.desc: test AnsSubscriberProxy's OnConnected function
 * @tc.type: FUNC
 * @tc.require: issueI62D8C
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConnected_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConnected_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnConnected();
}

/*
 * @tc.name: OnConnected_0200
 * @tc.desc: test AnsSubscriberProxy's OnConnected function
 * @tc.type: FUNC
 * @tc.require: #issueI62D8C
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnConnected_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnConnected_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnConnected();
}

/*
 * @tc.name: OnDisconnected_0100
 * @tc.desc: test AnsSubscriberProxy's OnDisconnected function
 * @tc.type: FUNC
 * @tc.require: issueI62D8C
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnDisconnected_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnDisconnected_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(NO_ERROR)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnDisconnected();
}

/*
 * @tc.name: OnDisconnected_0200
 * @tc.desc: test AnsSubscriberProxy's OnDisconnected function
 * @tc.type: FUNC
 * @tc.require: issueI62D8C
 */
HWTEST_F(AnsSubscriberProxyUnitTest, OnDisconnected_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyUnitTest, OnDisconnected_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(DEAD_OBJECT)));
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnDisconnected();
}