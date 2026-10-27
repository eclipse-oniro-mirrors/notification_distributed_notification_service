/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "single_timer_scheduler.h"

#include <cstdint>
#include <functional>
#include <vector>

#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace {
class FakeArmScheduler : public SingleTimerScheduler {
public:
    bool ArmOnce(int64_t triggerTime) override
    {
        armedCalls_.push_back(triggerTime);
        return armResult_;
    }

    std::vector<int64_t> armedCalls_;
    bool armResult_ {true};
};
} // namespace

class SingleTimerSchedulerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ReArm_UnchangedTargetNoOp_00001
 * @tc.desc: Test the unchanged-target no-op guard: repeated ReArm calls with the same
 *           next trigger time arm the timer exactly once (no redundant arm calls, no
 *           binder round trips).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(SingleTimerSchedulerTest, ReArm_UnchangedTargetNoOp_00001, Function | SmallTest | Level1)
{
    FakeArmScheduler scheduler;
    int64_t nextTime = 1000;
    scheduler.Init("testTimer", [&nextTime]() { return nextTime; },
        []() -> std::function<void()> { return nullptr; });

    scheduler.ReArm();
    scheduler.ReArm();
    scheduler.ReArm();

    EXPECT_EQ(scheduler.armedCalls_.size(), static_cast<size_t>(1));
    EXPECT_EQ(scheduler.armedCalls_.front(), 1000);
}

/**
 * @tc.name: ReArm_MovedTargetRearms_00002
 * @tc.desc: Test the moved-target re-arm: every target change (earlier or later than
 *           the armed one) arms a fresh timer with the new absolute trigger time.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(SingleTimerSchedulerTest, ReArm_MovedTargetRearms_00002, Function | SmallTest | Level1)
{
    FakeArmScheduler scheduler;
    int64_t nextTime = 1000;
    scheduler.Init("testTimer", [&nextTime]() { return nextTime; },
        []() -> std::function<void()> { return nullptr; });

    scheduler.ReArm();
    nextTime = 500;
    scheduler.ReArm();
    nextTime = 2000;
    scheduler.ReArm();

    EXPECT_EQ(scheduler.armedCalls_.size(), static_cast<size_t>(3));
    EXPECT_EQ(scheduler.armedCalls_[0], 1000);
    EXPECT_EQ(scheduler.armedCalls_[1], 500);
    EXPECT_EQ(scheduler.armedCalls_[2], 2000);
}

/**
 * @tc.name: ReArm_ZeroTargetDisarms_00003
 * @tc.desc: Test the zero-target disarm: a next trigger time of 0 disarms the timer
 *           without an arm call, and the bookkeeping reset makes a later target arm
 *           again even when it equals the previously armed one.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(SingleTimerSchedulerTest, ReArm_ZeroTargetDisarms_00003, Function | SmallTest | Level1)
{
    FakeArmScheduler scheduler;
    int64_t nextTime = 1000;
    scheduler.Init("testTimer", [&nextTime]() { return nextTime; },
        []() -> std::function<void()> { return nullptr; });

    scheduler.ReArm();
    nextTime = 0;
    scheduler.ReArm();
    EXPECT_EQ(scheduler.armedCalls_.size(), static_cast<size_t>(1));

    nextTime = 1000;
    scheduler.ReArm();
    EXPECT_EQ(scheduler.armedCalls_.size(), static_cast<size_t>(2));
    EXPECT_EQ(scheduler.armedCalls_[1], 1000);
}

/**
 * @tc.name: ReArm_FailedArmRetries_00004
 * @tc.desc: Test the failed-arm retry: a failed arm keeps the scheduler unarmed, so
 *           the next ReArm retries even with the SAME target (the no-op guard does
 *           not swallow the retry); a later successful arm restores the guard.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(SingleTimerSchedulerTest, ReArm_FailedArmRetries_00004, Function | SmallTest | Level1)
{
    FakeArmScheduler scheduler;
    scheduler.armResult_ = false;
    int64_t nextTime = 1000;
    scheduler.Init("testTimer", [&nextTime]() { return nextTime; },
        []() -> std::function<void()> { return nullptr; });

    scheduler.ReArm();
    scheduler.ReArm();
    EXPECT_EQ(scheduler.armedCalls_.size(), static_cast<size_t>(2));
    EXPECT_EQ(scheduler.armedCalls_[0], 1000);
    EXPECT_EQ(scheduler.armedCalls_[1], 1000);

    scheduler.armResult_ = true;
    scheduler.ReArm();
    scheduler.ReArm();
    EXPECT_EQ(scheduler.armedCalls_.size(), static_cast<size_t>(3));
    EXPECT_EQ(scheduler.armedCalls_[2], 1000);
}

/**
 * @tc.name: ReArm_UninitializedIgnored_00005
 * @tc.desc: Test the uninitialized guard: a scheduler that was never initialized
 *           silently ignores ReArm and Disarm without any arm call or crash.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(SingleTimerSchedulerTest, ReArm_UninitializedIgnored_00005, Function | SmallTest | Level1)
{
    FakeArmScheduler scheduler;

    scheduler.ReArm();
    scheduler.Disarm();

    EXPECT_TRUE(scheduler.armedCalls_.empty());
}
} // namespace Notification
} // namespace OHOS
