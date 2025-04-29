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

#include <memory>
#include "ans_inner_errors.h"
#include "gtest/gtest.h"
#define private public
#include "distributed_screen_status_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedScreenStatusManagerTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
protected:
    std::shared_ptr<DistributedScreenStatusManager> distributedScreenStatusManager_;
};

void DistributedScreenStatusManagerTest::SetUp()
{
    distributedScreenStatusManager_ = DistributedScreenStatusManager::GetInstance();
    distributedScreenStatusManager_->OnDeviceConnected("test");
}

void DistributedScreenStatusManagerTest::TearDown()
{
    distributedScreenStatusManager_->OnDeviceDisconnected("test");
    distributedScreenStatusManager_ = nullptr;
    DistributedScreenStatusManager::DestroyInstance();
}

/**
 * @tc.name      : DistributedScreenStatusManager_CheckRemoteDevicesIsUsing_00100
 * @tc.number    : CheckRemoteDevicesIsUsing_00100
 * @tc.desc      : Test CheckRemoteDevicesIsUsing function.
 */
HWTEST_F(DistributedScreenStatusManagerTest, CheckRemoteDevicesIsUsing_00100, Function | SmallTest | Level1)
{
    bool isUsing = true;

    EXPECT_EQ(distributedScreenStatusManager_->CheckRemoteDevicesIsUsing(isUsing),
        ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedScreenStatusManager_SetLocalScreenStatus_00100
 * @tc.number    : SetLocalScreenStatus_00100
 * @tc.desc      : Get distributed notification enable.
 */
HWTEST_F(DistributedScreenStatusManagerTest, SetLocalScreenStatus_00100, Function | SmallTest | Level1)
{
    bool screenOn = false;

    EXPECT_EQ(distributedScreenStatusManager_->SetLocalScreenStatus(screenOn), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}
}  // namespace Notification
}  // namespace OHOS