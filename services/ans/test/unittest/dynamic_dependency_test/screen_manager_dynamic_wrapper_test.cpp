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

#include <gtest/gtest.h>
#include <memory>

#define private public

#include "screen_manager_dynamic_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Notification;

namespace OHOS {
namespace Rosen {
static ScreenPowerState g_mockScreenPowerState_ = ScreenPowerState::POWER_OFF;

static void MockScreenPowerState(ScreenPowerState state)
{
    g_mockScreenPowerState_ = state;
}

ScreenPowerState ScreenManager::GetScreenPower()
{
    return g_mockScreenPowerState_;
}
} // Rosen
} // OHOS

namespace OHOS {
namespace Notification {

class ScreenManagerDynamicWrapperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ScreenManagerDynamicWrapperTest::SetUpTestCase() {}

void ScreenManagerDynamicWrapperTest::TearDownTestCase() {}

void ScreenManagerDynamicWrapperTest::SetUp() {}

void ScreenManagerDynamicWrapperTest::TearDown() {}

HWTEST_F(ScreenManagerDynamicWrapperTest, GetScreenPower_00001, Function | SmallTest | Level1)
{
    Rosen::MockScreenPowerState(Rosen::ScreenPowerState::POWER_ON);
    
    NotificationScreenPowerState result = ScreenManagerDynamicWrapper::GetInstance().GetScreenPower();
    EXPECT_EQ(result, NotificationScreenPowerState::POWER_ON);
}

HWTEST_F(ScreenManagerDynamicWrapperTest, GetScreenPower_00002, Function | SmallTest | Level1)
{
    Rosen::MockScreenPowerState(Rosen::ScreenPowerState::POWER_OFF);
    
    NotificationScreenPowerState result = ScreenManagerDynamicWrapper::GetInstance().GetScreenPower();
    EXPECT_EQ(result, NotificationScreenPowerState::POWER_OFF);
}

HWTEST_F(ScreenManagerDynamicWrapperTest, GetScreenPower_00003, Function | SmallTest | Level1)
{
    Rosen::MockScreenPowerState(Rosen::ScreenPowerState::POWER_STAND_BY);
    
    NotificationScreenPowerState result = ScreenManagerDynamicWrapper::GetInstance().GetScreenPower();
    EXPECT_EQ(result, NotificationScreenPowerState::POWER_STAND_BY);
}

HWTEST_F(ScreenManagerDynamicWrapperTest, GetScreenPower_00004, Function | SmallTest | Level1)
{
    Rosen::MockScreenPowerState(Rosen::ScreenPowerState::POWER_SUSPEND);
    
    NotificationScreenPowerState result = ScreenManagerDynamicWrapper::GetInstance().GetScreenPower();
    EXPECT_EQ(result, NotificationScreenPowerState::POWER_SUSPEND);
}

HWTEST_F(ScreenManagerDynamicWrapperTest, GetScreenPower_00005, Function | SmallTest | Level1)
{
    Rosen::MockScreenPowerState(Rosen::ScreenPowerState::POWER_BUTT);
    
    NotificationScreenPowerState result = ScreenManagerDynamicWrapper::GetInstance().GetScreenPower();
    EXPECT_EQ(result, NotificationScreenPowerState::POWER_OFF);
}
}
}
