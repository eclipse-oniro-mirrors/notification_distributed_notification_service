/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#define private public
#include "reminder_swing_decision_center.h"
#include "notification_preferences.h"
#include "smart_reminder_center.h"
#include "reminder_affected.h"
#undef private
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
    ASSERT_EQ(ret, (int)ERR_INVALID_VALUE);
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
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: RegisterSwingCallback_00003
 * @tc.desc: Test RegisterSwingCallback repeated with the same callback, expect idempotent.
 * @tc.type: FUNC
 */
HWTEST_F(ReminderSwingDecisionCenterTest, RegisterSwingCallback_00003, Function | SmallTest | Level1)
{
    auto swingCallbackProxy = new (std::nothrow)MockSwingCallBackStub();
    ASSERT_NE(swingCallbackProxy, nullptr);
    sptr<IRemoteObject> swingCallback = swingCallbackProxy->AsObject();
    EXPECT_EQ(reminderSwingDecisionCenter_.RegisterSwingCallback(swingCallback), (int)ERR_OK);
    sptr<IRemoteObject::DeathRecipient> recipient = reminderSwingDecisionCenter_.swingRecipient_;
    EXPECT_TRUE(recipient != nullptr);
    EXPECT_EQ(reminderSwingDecisionCenter_.RegisterSwingCallback(swingCallback), (int)ERR_OK);
    EXPECT_EQ(reminderSwingDecisionCenter_.swingRecipient_, recipient);
}

/**
 * @tc.name: RegisterSwingCallback_00004
 * @tc.desc: Test RegisterSwingCallback concurrently, expect no crash and all succeed.
 * @tc.type: FUNC
 */
HWTEST_F(ReminderSwingDecisionCenterTest, RegisterSwingCallback_00004, Function | SmallTest | Level1)
{
    constexpr int32_t threadNum = 8;
    constexpr int32_t loopNum = 200;
    std::vector<std::thread> threads;
    std::vector<int32_t> results(threadNum, static_cast<int32_t>(ERR_INVALID_VALUE));
    for (int32_t i = 0; i < threadNum; i++) {
        threads.emplace_back([this, &results, i]() {
            auto stub = new (std::nothrow)MockSwingCallBackStub();
            if (stub == nullptr) {
                return;
            }
            sptr<IRemoteObject> callback = stub->AsObject();
            for (int32_t j = 0; j < loopNum; j++) {
                results[i] = reminderSwingDecisionCenter_.RegisterSwingCallback(callback);
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(reminderSwingDecisionCenter_.swingRecipient_ != nullptr);
    for (int32_t i = 0; i < threadNum; i++) {
        EXPECT_EQ(results[i], (int)ERR_OK);
    }
}

HWTEST_F(ReminderSwingDecisionCenterTest, NormalResetSwingCallbackProxyTest, Function | SmallTest | Level1)
{
    // Arrange
    reminderSwingDecisionCenter_.swingCallback_ = new (std::nothrow)MockSwingCallBackStub();
    reminderSwingDecisionCenter_.swingRecipient_ = new (std::nothrow)SwingCallbackRecipient();

    // Act
    reminderSwingDecisionCenter_.ResetSwingCallbackProxy();

    // Assert
    EXPECT_EQ(reminderSwingDecisionCenter_.swingCallback_, nullptr);
    EXPECT_NE(reminderSwingDecisionCenter_.swingRecipient_, nullptr);
}

// 测试ResetSwingCallbackProxy方法 - swingCallback_为nullptr
HWTEST_F(ReminderSwingDecisionCenterTest, NullSwingCallbackResetSwingCallbackProxyTest, Function | SmallTest | Level1)
{
    // Arrange
    reminderSwingDecisionCenter_.swingCallback_ = nullptr;
    reminderSwingDecisionCenter_.swingRecipient_ = new (std::nothrow)SwingCallbackRecipient();

    // Act
    reminderSwingDecisionCenter_.ResetSwingCallbackProxy();

    // Assert
    EXPECT_EQ(reminderSwingDecisionCenter_.swingCallback_, nullptr);
    EXPECT_NE(reminderSwingDecisionCenter_.swingRecipient_, nullptr);
}

// 测试ResetSwingCallbackProxy方法 - swingRecipient_为nullptr
HWTEST_F(ReminderSwingDecisionCenterTest, NullSwingRecipientResetSwingCallbackProxyTest, Function | SmallTest | Level1)
{
    // Arrange
    reminderSwingDecisionCenter_.swingCallback_ = new (std::nothrow)MockSwingCallBackStub();
    reminderSwingDecisionCenter_.swingRecipient_ = nullptr;

    // Act
    reminderSwingDecisionCenter_.ResetSwingCallbackProxy();

    // Assert
    EXPECT_EQ(reminderSwingDecisionCenter_.swingCallback_, nullptr);
    EXPECT_EQ(reminderSwingDecisionCenter_.swingRecipient_, nullptr);
}

// 测试ResetSwingCallbackProxy方法 - 所有指针都为nullptr
HWTEST_F(ReminderSwingDecisionCenterTest, AllNullResetSwingCallbackProxyTest, Function | SmallTest | Level1)
{
    // Arrange
    reminderSwingDecisionCenter_.swingCallback_ = nullptr;
    reminderSwingDecisionCenter_.swingRecipient_ = nullptr;

    // Act
    reminderSwingDecisionCenter_.ResetSwingCallbackProxy();

    // Assert
    EXPECT_EQ(reminderSwingDecisionCenter_.swingCallback_, nullptr);
    EXPECT_EQ(reminderSwingDecisionCenter_.swingRecipient_, nullptr);
}
}   //namespace Notification
}   //namespace OHOS
#endif