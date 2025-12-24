/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "notification_slot.h"
#undef private 
#undef protected
#include "ans_inner_errors.h"
#include "notification_slot_filter.h"
#include "notification_subscribe_info.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSlotFilterTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : NotificationSlotFilterTest_00100
 * @tc.name      : ANS_OnStart_0100
 * @tc.desc      : Test OnStart function
 */
HWTEST_F(NotificationSlotFilterTest, NotificationSlotFilterTest_00100, Function | SmallTest | Level1)
{
    NotificationSlotFilter notificationSlotFilter;
    notificationSlotFilter.OnStart();

    // NotificationSlot Marshalling TDD test
    Parcel p;
    NotificationConstant::SlotType type = NotificationConstant::SlotType::CUSTOM;
    NotificationSlot notificationSlot(type);
    auto result = notificationSlot.Marshalling(p);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number    : NotificationSlotFilterTest_00200
 * @tc.name      : ANS_OnStop_0100
 * @tc.desc      : Test OnStop function
 */
HWTEST_F(NotificationSlotFilterTest, NotificationSlotFilterTest_00200, Function | SmallTest | Level1)
{
    NotificationSlotFilter notificationSlotFilter;
    notificationSlotFilter.OnStop();

    // NotificationSlot ReadFromParcel TDD test
    Parcel p;
    NotificationConstant::SlotType type = NotificationConstant::SlotType::CUSTOM;
    NotificationSlot notificationSlot(type);
    auto result = notificationSlot.ReadFromParcel(p);
    ASSERT_EQ(result, false);
}

/**
 * @tc.number    : NotificationSlotFilterTest_00300
 * @tc.name      : ANS_OnPublish_0100
 * @tc.desc      : Test OnPublish function
 */
HWTEST_F(NotificationSlotFilterTest, NotificationSlotFilterTest_00300, Function | SmallTest | Level1)
{
    NotificationSlotFilter notificationSlotFilter;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    AnsStatus ansStatus = notificationSlotFilter.OnPublish(record);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST);
}


/**
 * @tc.number    : NotificationSlotFilterTest_00400
 * @tc.name      : ANS_OnPublish_0200
 * @tc.desc      : Test OnPublish function
 */
HWTEST_F(NotificationSlotFilterTest, NotificationSlotFilterTest_00400, Function | SmallTest | Level1)
{
    NotificationSlotFilter notificationSlotFilter;
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    record->notification = new Notification(record->request);
    record->slot = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    notificationSlotFilter.OnPublish(record);

    // NotificationSubscribeInfo Marshalling TDD test
    Parcel p;
    NotificationSubscribeInfo notificationSubscribeInfo;
    auto result = notificationSubscribeInfo.Marshalling(p);
    ASSERT_EQ(result, true);
}
}  // namespace Notification
}  // namespace OHOS
