/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "notification_request.h"
#include "notification_subscriber_extension.h"
#include "notification_subscriber_stub_impl.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSubscriberStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: OnReceiveMessage_0100
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0100, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(request, retResult);
    ASSERT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnReceiveMessage_0200
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0200, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(nullptr, retResult);
    ASSERT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnReceiveMessage_0300
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0300, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    std::weak_ptr<NotificationSubscriberExtension> extension = subscriberExtension;
    subscriberExtension.reset();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(request, retResult);
    ASSERT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnReceiveMessage_0400
 * @tc.desc: OnReceiveMessage.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnReceiveMessage_0400, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    int32_t retResult = 0;

    ErrCode result = stub.OnReceiveMessage(request, retResult);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OnCancelMessages_0100
 * @tc.desc: OnCancelMessages.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnCancelMessages_0100, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    std::weak_ptr<NotificationSubscriberExtension> extension = subscriberExtension;
    subscriberExtension.reset();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    std::vector<std::string> hashCode = {"testHash1", "testHash2"};
    int32_t retResult = 0;

    ErrCode result = stub.OnCancelMessages(hashCode, retResult);
    ASSERT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: OnCancelMessages_0200
 * @tc.desc: OnCancelMessages.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, OnCancelMessages_0200, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    std::vector<std::string> hashCode = {"testHash1", "testHash2"};
    int32_t retResult = 0;

    ErrCode result = stub.OnCancelMessages(hashCode, retResult);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ConvertNotificationRequest_0100
 * @tc.desc: ConvertNotificationRequest.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, ConvertNotificationRequest_0100, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);

    auto notificationInfo = stub.ConvertNotificationRequest(request);
    ASSERT_EQ(notificationInfo, nullptr);
}

/**
 * @tc.name: ConvertNotificationRequest_0200
 * @tc.desc: ConvertNotificationRequest.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, ConvertNotificationRequest_0200, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto content = std::make_shared<NotificationContent>(std::shared_ptr<NotificationNormalContent>(nullptr));
    request->SetContent(content);

    auto notificationInfo = stub.ConvertNotificationRequest(request);
    ASSERT_EQ(notificationInfo, nullptr);
}

/**
 * @tc.name: ConvertNotificationRequest_0300
 * @tc.desc: ConvertNotificationRequest.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSubscriberStubTest, ConvertNotificationRequest_0300, Function | SmallTest | Level1)
{
    auto subscriberExtension = std::make_shared<NotificationSubscriberExtension>();
    NotificationSubscriberStubImpl stub(subscriberExtension);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetText("TestText");
    normalContent->SetTitle("TestTitle");
    auto content = std::make_shared<NotificationContent>(normalContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    request->SetCreatorBundleName("TestBundleName");
    request->SetAppName("TestAppName");
    request->SetDeliveryTime(1);
    request->SetGroupName("TestGroupName");

    auto notificationInfo = stub.ConvertNotificationRequest(request);
    ASSERT_NE(notificationInfo, nullptr);
    ASSERT_NE(notificationInfo->GetNotificationExtensionContent(), nullptr);
    ASSERT_EQ(notificationInfo->GetNotificationExtensionContent()->GetText(), "TestText");
    ASSERT_EQ(notificationInfo->GetNotificationExtensionContent()->GetTitle(), "TestTitle");
    ASSERT_NE(notificationInfo->GetHashCode(), "");
    ASSERT_EQ(notificationInfo->GetNotificationSlotType(), NotificationConstant::SlotType::CONTENT_INFORMATION);
    ASSERT_EQ(notificationInfo->GetBundleName(), "TestBundleName");
    ASSERT_EQ(notificationInfo->GetAppName(), "TestAppName");
    ASSERT_EQ(notificationInfo->GetDeliveryTime(), 1);
    ASSERT_EQ(notificationInfo->GetGroupName(), "TestGroupName");
}
}
}
