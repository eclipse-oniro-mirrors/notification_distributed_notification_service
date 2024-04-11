/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "gtest/gtest.h"
#include "reminder_swing_decision_center.h"
#include "mock_swing_callback_stub.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class ReminderSwingDecisionCenterTest : public testing::Test {
public:
    ReminderSwingDecisionCenterTest()
    {}
    ~ReminderSwingDecisionCenterTest()
    {}
    static void SetUpTestCas(void) {};
    static void TearDownTestCase(void) {};
    void SetUp();
    void TearDown() {};
public:
    ReminderSwingDecisionCenter reminderSwingDecisionCenter_;
};

void ReminderSwingDecisionCenterTest::SetUp(void)
{
    reminderSwingDecisionCenter_ = ReminderSwingDecisionCenter::GetInstance();
}

/**
 * @tc.name: RegisterSwingCallback_00001
 * @tc.desc: Test RegisterSwingCallback
 * @tc.type: FUNC
 */
HWTEST_F(ReminderSwingDecisionCenterTest, RegisterSwingCallback_00001, Function | SmallTest | Level1)
{
    sptr<IRemoteObject> swingCallback = nullptr;
    auto ret = reminderSwingDecisionCenter_.RegisterSwingCallback(swingCallback);
    EXPECT_EQ(ret, (int)ERR_INVALID_VALUE);
}

/**
 * @tc.name: RegisterSwingCallback_00002
 * @tc.desc: Test RegisterSwingCallback
 * @tc.type: FUNC
 */
HWTEST_F(ReminderSwingDecisionCenterTest, RegisterSwingCallback_00002, Function | SmallTest | Level1)
{
    auto swingCallbackProxy = new (std::nothrow)MockSwingCallBackStub();
    EXPECT_NE(swingCallbackProxy, nullptr);
    sptr<IRemoteObject> swingCallback = swingCallbackProxy->AsObject();
    int ret = reminderSwingDecisionCenter_.RegisterSwingCallback(swingCallback);
    EXPECT_EQ(ret, (int)ERR_OK);
}
}   //namespace Notification
}   //namespace OHOS
#endif