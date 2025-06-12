/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#define private public

#include "ans_inner_errors.h"
#include "mock_distributed_operation_callback.h"
#include "notification_operation_service.h"
#include "mock_distributed_operation_callback.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;

class DistributedOperationServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void DistributedOperationServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUp Case start";
    GTEST_LOG_(INFO) << "SetUp end";
}

void DistributedOperationServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDown case";
}

/**
 * @tc.name: Device sync switch check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedOperationServiceTest, DeviceData_00001, Function | SmallTest | Level1)
{
    MockOperationCallback::ResetOperationResult();
    // add operation.
    sptr<MockOperationCallback> callback = new (std::nothrow) MockOperationCallback();
    DistributedOperationService::GetInstance().AddOperation("abcd", callback);
    // remove operation.
    DistributedOperationService::GetInstance().RemoveOperationResponse("abcd");
    // not return operation result.
    int32_t result = MockOperationCallback::GetOperationResult();
    ASSERT_EQ(result, -1);
}

/**
 * @tc.name: Device sync switch check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedOperationServiceTest, DeviceData_00002, Function | SmallTest | Level1)
{
    MockOperationCallback::ResetOperationResult();
    // add operation.
    sptr<MockOperationCallback> callback = new (std::nothrow) MockOperationCallback();
    DistributedOperationService::GetInstance().AddOperation("abcd", callback);
    // invoke time out operation.
    DistributedOperationService::GetInstance().HandleOperationTimeOut("abcd");
    // time out operation result.
    sleep(1);
    int32_t result = MockOperationCallback::GetOperationResult();
    ASSERT_EQ(result, (int)ERR_ANS_OPERATION_TIMEOUT);
}

/**
 * @tc.name: Device sync switch check
 * @tc.desc: Test device data service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedOperationServiceTest, DeviceData_00003, Function | SmallTest | Level1)
{
    MockOperationCallback::ResetOperationResult();
    // add operation.
    sptr<MockOperationCallback> callback = new (std::nothrow) MockOperationCallback();
    DistributedOperationService::GetInstance().AddOperation("abcd", callback);
    // invoke successful operation.
    DistributedOperationService::GetInstance().ReplyOperationResponse("abcd", 0);
    // invoke successful.
    int32_t result = MockOperationCallback::GetOperationResult();
    ASSERT_EQ(result, 0);
}
}
}
