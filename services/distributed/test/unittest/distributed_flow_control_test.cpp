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

#include <memory>

#include "gtest/gtest.h"

#define private public
#include "distributed_flow_control.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedFlowControlTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
};

void DistributedFlowControlTest::SetUp()
{}

void DistributedFlowControlTest::TearDown()
{}

/**
 * @tc.name      : DistributedFlowControl_00100
 * @tc.number    : DistributedFlowControl_00100
 * @tc.desc      : test KvManagerFlowControl function and listSize >= kvManagerMinuteMaxinum_ .
 */
HWTEST_F(DistributedFlowControlTest, DistributedFlowControl_00100, Function | SmallTest | Level1)
{
    size_t kvManagerSecondMaxinum = 0;
    size_t kvManagerMinuteMaxinum = 0;
    size_t kvStoreSecondMaxinum = 0;
    size_t kvStoreMinuteMaxinum = 0;
    DistributedFlowControl distributedFlowControl(
        kvManagerSecondMaxinum, kvManagerMinuteMaxinum, kvStoreSecondMaxinum, kvStoreMinuteMaxinum);
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    distributedFlowControl.kvStoreTimestampList_.push_front(now);
    EXPECT_EQ(false, distributedFlowControl.KvManagerFlowControl());
}

/**
 * @tc.name      : DistributedFlowControl_00200
 * @tc.number    : DistributedFlowControl_00200
 * @tc.desc      : test KvStoreFlowControl function and listSize >= kvStoreMinuteMaxinum_ .
 */
HWTEST_F(DistributedFlowControlTest, DistributedFlowControl_00200, Function | SmallTest | Level1)
{
    size_t kvManagerSecondMaxinum = 0;
    size_t kvManagerMinuteMaxinum = 0;
    size_t kvStoreSecondMaxinum = 0;
    size_t kvStoreMinuteMaxinum = 0;
    DistributedFlowControl distributedFlowControl(
        kvManagerSecondMaxinum, kvManagerMinuteMaxinum, kvStoreSecondMaxinum, kvStoreMinuteMaxinum);
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    distributedFlowControl.kvStoreTimestampList_.push_front(now);
    EXPECT_EQ(false, distributedFlowControl.KvStoreFlowControl());
}
}  // namespace Notification
}  // namespace OHOS