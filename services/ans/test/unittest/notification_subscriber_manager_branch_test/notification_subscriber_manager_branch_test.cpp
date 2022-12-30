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

#include "ans_ut_constant.h"
#define private public
#define protected public
#include "notification_subscriber_manager.h"
#undef private
#undef protected
#include "ans_inner_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSubscriberManagerBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : NotificationSubscriberManager_00100
 * @tc.name      : NotificationSubscriberManager_00100
 * @tc.desc      : test NotifyConsumed function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00100, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyConsumed(notification, notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00200
 * @tc.name      : NotificationSubscriberManager_00200
 * @tc.desc      : test NotifyCanceled function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00200, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<Notification> notification = nullptr;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    int32_t deleteReason = 1;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyCanceled(notification, notificationMap, deleteReason);
}

/**
 * @tc.number    : NotificationSubscriberManager_00300
 * @tc.name      : NotificationSubscriberManager_00300
 * @tc.desc      : test NotifyUpdated function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00300, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationSortingMap> notificationMap = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyUpdated(notificationMap);
}

/**
 * @tc.number    : NotificationSubscriberManager_00400
 * @tc.name      : NotificationSubscriberManager_00400
 * @tc.desc      : test NotifyDoNotDisturbDateChanged function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00400, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<NotificationDoNotDisturbDate> date = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyDoNotDisturbDateChanged(date);
}

/**
 * @tc.number    : NotificationSubscriberManager_00500
 * @tc.name      : NotificationSubscriberManager_00500
 * @tc.desc      : test NotifyEnabledNotificationChanged function and handler_ == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00500, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<EnabledNotificationCallbackData> callbackData = nullptr;
    notificationSubscriberManager.handler_ = nullptr;
    notificationSubscriberManager.NotifyEnabledNotificationChanged(callbackData);
}

/**
 * @tc.number    : NotificationSubscriberManager_00600
 * @tc.name      : NotificationSubscriberManager_00600
 * @tc.desc      : test OnRemoteDied function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00600, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    wptr<IRemoteObject> object = nullptr;
    notificationSubscriberManager.OnRemoteDied(object);
}

/**
 * @tc.number    : NotificationSubscriberManager_00700
 * @tc.name      : NotificationSubscriberManager_00700
 * @tc.desc      : test AddRecordInfo function and subscribeInfo == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00700, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> record =
        notificationSubscriberManager.CreateSubscriberRecord(nullptr);
    sptr<NotificationSubscribeInfo> subscribeInfo = nullptr;
    notificationSubscriberManager.AddRecordInfo(record, subscribeInfo);
}

/**
 * @tc.number    : NotificationSubscriberManager_00800
 * @tc.name      : NotificationSubscriberManager_00800
 * @tc.desc      : test RemoveSubscriberInner function and record == nullptr
 */
HWTEST_F(NotificationSubscriberManagerBranchTest, NotificationSubscriberManager_00800, Function | SmallTest | Level1)
{
    NotificationSubscriberManager notificationSubscriberManager;
    sptr<AnsSubscriberInterface> subscriber = nullptr;
    sptr<NotificationSubscribeInfo> subscribeInfo = nullptr;
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, notificationSubscriberManager.RemoveSubscriberInner(subscriber, subscribeInfo));
}
}  // namespace Notification
}  // namespace OHOS
