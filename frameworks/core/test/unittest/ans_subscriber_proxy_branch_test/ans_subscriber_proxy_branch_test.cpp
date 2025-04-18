/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "notification_request.h"
#include <gtest/gtest.h>

#define protected public
#define private public
#include "ans_subscriber_proxy.h"
#undef protected
#undef private
#include "ans_inner_errors.h"
#include "ipc_types.h"
#include "mock_i_remote_object.h"
#include "notification.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsSubscriberProxyBranchTest : public testing::Test {
public:
    AnsSubscriberProxyBranchTest() {}

    virtual ~AnsSubscriberProxyBranchTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AnsSubscriberProxyBranchTest::SetUpTestCase() {}

void AnsSubscriberProxyBranchTest::TearDownTestCase() {}

void AnsSubscriberProxyBranchTest::SetUp() {}

void AnsSubscriberProxyBranchTest::TearDown() {}

/*
 * @tc.name: OnCanceledList_0100
 * @tc.desc: Test OnCanceledList function and notifications is empty
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyBranchTest, OnCanceledList_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyBranchTest, OnCanceledList_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    int32_t deleteReason = 1;
    proxy->OnCanceledList(notifications, notificationMap, deleteReason);
}

/*
 * @tc.name: OnCanceledList_0200
 * @tc.desc: 1.Test OnCanceledList function and notifications is not empty
 *           2.notificationMap is nullptr
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyBranchTest, OnCanceledList_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyBranchTest, OnCanceledList_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationRequest> request = new (std::nothrow) OHOS::Notification::NotificationRequest();
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification(request);
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    sptr<NotificationSortingMap> notificationMap = nullptr;
    int32_t deleteReason = 1;
    proxy->OnCanceledList(notifications, notificationMap, deleteReason);
}

/*
 * @tc.name: OnCanceledList_0300
 * @tc.desc: 1.Test OnCanceledList function and notifications is not empty
 *           2.notificationMap is not nullptr
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsSubscriberProxyBranchTest, OnCanceledList_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsSubscriberProxyBranchTest, OnCanceledList_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<AnsSubscriberProxy> proxy = std::make_shared<AnsSubscriberProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    sptr<NotificationRequest> request = new (std::nothrow) OHOS::Notification::NotificationRequest();
    sptr<OHOS::Notification::Notification> notification = new (std::nothrow) OHOS::Notification::Notification(request);
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    notifications.emplace_back(notification);
    sptr<NotificationSortingMap> notificationMap = new (std::nothrow) NotificationSortingMap();
    int32_t deleteReason = 1;
    proxy->OnCanceledList(notifications, notificationMap, deleteReason);
}
