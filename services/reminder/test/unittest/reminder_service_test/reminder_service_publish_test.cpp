/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "errors.h"
#include "notification_content.h"
#include "notification_request.h"
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#include "reminder_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "reminder_ut_constant.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"

#include "reminder_bundle_manager_helper.h"

extern void MockIsOsAccountExists(bool mockRet);

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);
extern void MockIsVerfyPermisson(bool isVerify);

class ReminderServicePublishTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddSlot(NotificationConstant::SlotType type);
    void TestAddLiveViewSlot(bool isForceControl);
    void MockSystemApp();

private:
    static sptr<ReminderService> reminderService_;
};

sptr<ReminderService> ReminderServicePublishTest::reminderService_ = nullptr;

void ReminderServicePublishTest::SetUpTestCase()
{
    MockIsOsAccountExists(true);
}

void ReminderServicePublishTest::TearDownTestCase() {}

void ReminderServicePublishTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    reminderService_ = new (std::nothrow) ReminderService();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    GTEST_LOG_(INFO) << "SetUp end";
}

void ReminderServicePublishTest::TearDown()
{
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    reminderService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

inline void SleepForFC()
{
    // For ANS Flow Control
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void ReminderServicePublishTest::MockSystemApp()
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
}

/**
 * @tc.number    : ReminderServicePublishTest_13200
 * @tc.name      : ANS_PublishReminder_0100
 * @tc.desc      : Test PublishReminder function
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServicePublishTest, ReminderServicePublishTest_13200, Function | SmallTest | Level1)
{
    int32_t reminderId = 0;
    ReminderRequest reminder;
    ASSERT_EQ(reminderService_->PublishReminder(reminder, reminderId), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : ReminderServicePublishTest_13300
 * @tc.name      : ANS_CancelReminder_0100
 * @tc.desc      : Test CancelReminder function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServicePublishTest, ReminderServicePublishTest_13300, Function | SmallTest | Level1)
{
    int32_t reminderId = 1;
    ASSERT_EQ(reminderService_->CancelReminder(reminderId), (int)ERR_NO_INIT);
}

/**
 * @tc.number    : ReminderServicePublishTest_13400
 * @tc.name      : ANS_CancelAllReminders_0100
 * @tc.desc      : Test CancelAllReminders function when the result is ERR_NO_INIT
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(ReminderServicePublishTest, ReminderServicePublishTest_13400, Function | SmallTest | Level1)
{
    ASSERT_EQ(reminderService_->CancelAllReminders(), (int)ERR_NO_INIT);
}

/**
 * @tc.number    : ReminderServicePublishTest_17900
 * @tc.name      : PublishReminder_1000
 * @tc.desc      : Test PublishReminder function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(ReminderServicePublishTest, ReminderServicePublishTest_17900, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test start";

    int32_t reminderId = 1;
    ReminderRequest reminder;
    ASSERT_NE(reminderService_->PublishReminder(reminder, reminderId), ERR_OK);

    GTEST_LOG_(INFO) << "GetAppTargetBundle_1000 test end";
}

/**
 * @tc.number    : ReminderServicePublishTest_18000
 * @tc.name      : PublishReminder_2000
 * @tc.desc      : Test PublishReminder function.
 * @tc.require   : #I61RF2
 */
HWTEST_F(ReminderServicePublishTest, ReminderServicePublishTest_18000, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test start";

    MockIsNonBundleName(true);
    int32_t reminderId = 1;
    ReminderRequest reminder;
    ASSERT_NE(reminderService_->PublishReminder(reminder, reminderId), ERR_OK);
    MockIsNonBundleName(false);
    GTEST_LOG_(INFO) << "GetAppTargetBundle_2000 test end";
}
}  // namespace Notification
}  // namespace OHOS
