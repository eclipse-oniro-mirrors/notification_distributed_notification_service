/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "reminder_request.h"
#undef private
#undef protected


extern void MockNowInstantMilli(bool mockRet);
using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderRequestBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}

    // static const uint8_t REMINDER_STATUS_SHOWING;
};

// const uint8_t ReminderRequestBranchTest::REMINDER_STATUS_SHOWING = 4;

/**
 * @tc.name: ShouldShowImmediately_00100
 * @tc.desc: ShouldShowImmediately.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, ShouldShowImmediately_00100, Function | SmallTest | Level1)
{
    MockNowInstantMilli(false);
    ReminderRequest reminderRequest;
    bool ret = reminderRequest.ShouldShowImmediately();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ShouldShowImmediately_00200
 * @tc.desc: ShouldShowImmediately.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, ShouldShowImmediately_00200, Function | SmallTest | Level1)
{
    MockNowInstantMilli(true);
    ReminderRequest reminderRequest;
    uint64_t triggerTimeInMilli = 1675876480001;
    reminderRequest.SetTriggerTimeInMilli(triggerTimeInMilli);
    bool ret = reminderRequest.ShouldShowImmediately();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CanShow_00100
 * @tc.desc: CanShow.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, CanShow_00100, Function | SmallTest | Level1)
{
    MockNowInstantMilli(false);
    ReminderRequest reminderRequest;
    bool ret = reminderRequest.CanShow();
    EXPECT_EQ(ret, false);
}
}
}
