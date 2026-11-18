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

#include <thread>
#include <functional>
#include "gtest/gtest.h"
#define private public
#define protected public
#include "timer_impl.h"
#include "itimer_info.h"
#undef private
#undef protected
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace Infra {

class TimerInfoTest : public MiscServices::ITimerInfo {
public:
    TimerInfoTest() {};
    virtual ~TimerInfoTest() {};
    void OnTrigger() override {};

    /**
     * Indicates the timing type.
     */
    void SetType(const int32_t &timerInfoType) override
    {
        type = timerInfoType;
    }

    /**
     * Indicates the repeat policy.
     */
    void SetRepeat(bool timerInfoRepeat) override
    {
        repeat = timerInfoRepeat;
    }

    /**
     * Indicates the interval time for repeat timing.
     */
    void SetInterval(const uint64_t &timerInfoInterval) override
    {
        interval = timerInfoInterval;
    }

    /**
     * Indicates the want agent information.
     */
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> timerInfoWantAgent) override
    {
        wantAgent = timerInfoWantAgent;
    }
};

class TimerImplTest : public Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
protected:
    std::unique_ptr<TimerImpl> timerImpl_;
};

void TimerImplTest::SetUpTestCase() {}

void TimerImplTest::TearDownTestCase() {}

void TimerImplTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    timerImpl_ = std::make_unique<TimerImpl>();
    GTEST_LOG_(INFO) << "SetUp end";
}

void TimerImplTest::TearDown()
{
    timerImpl_.reset();
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.number    : CreateTimer_0001
 * @tc.name      : CreateTimer_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(TimerImplTest, CreateTimer_0001, Function | MediumTest | Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerImpl_->CreateTimer(timerInfo);
    timerImpl_->CreateTimer(timerInfo);
    EXPECT_GT(timerImpl_->timerId_, true);

    timerImpl_->DestroyTimer();
}

/**
 * @tc.number    : StartTimer_0001
 * @tc.name      : StartTimer_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(TimerImplTest, StartTimer_0001, Function | MediumTest | Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerImpl_->CreateTimer(timerInfo);
    timerImpl_->StartTimer(10);
    EXPECT_GT(timerImpl_->timerId_, true);

    timerImpl_->StopTimer();
    timerImpl_->DestroyTimer();
}

/**
 * @tc.number    : StopTimer_0001
 * @tc.name      : StopTimer_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(TimerImplTest, StopTimer_0001, Function | MediumTest | Level1)
{
    timerImpl_->StopTimer();
    EXPECT_NE(timerImpl_->timer_, nullptr);
    EXPECT_EQ(timerImpl_->timerId_, 0);
}

/**
 * @tc.number    : DestroyTimer_0001
 * @tc.name      : DestroyTimer_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(TimerImplTest, DestroyTimer_0001, Function | MediumTest | Level1)
{
    timerImpl_->DestroyTimer();
    EXPECT_NE(timerImpl_->timer_, nullptr);
    EXPECT_EQ(timerImpl_->timerId_, 0);
}

/**
 * @tc.number    : DestroyTimer_0002
 * @tc.name      : DestroyTimer_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(TimerImplTest, DestroyTimer_0002, Function | MediumTest | Level1)
{
    timerImpl_->timer_ = nullptr;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerImpl_->CreateTimer(timerInfo);
    timerImpl_->StartTimer(10);
    timerImpl_->StopTimer();

    EXPECT_EQ(timerImpl_->timerId_, 0);
    timerImpl_->DestroyTimer();
}
}  // Infra
}  // namespace Notification
}  // namespace OHOS
