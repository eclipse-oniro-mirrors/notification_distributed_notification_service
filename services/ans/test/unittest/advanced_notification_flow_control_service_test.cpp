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

#include "advanced_notification_flow_control_service.h"

#include "gtest/gtest.h"

#include "ans_const_define.h"
#include "ans_inner_errors.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace {
    constexpr int32_t NON_SYSTEM_APP_UID = 1000;
}
class FlowControlServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FlowControlServiceTest::SetUpTestCase() {}

void FlowControlServiceTest::TearDownTestCase() {}

void FlowControlServiceTest::SetUp() {}

void FlowControlServiceTest::TearDown() {}

/**
 * @tc.number    : FlowControl_00001
 * @tc.name      : Test FlowControl
 * @tc.desc      : Test FlowControl
 */
HWTEST_F(FlowControlServiceTest, FlowControl_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    int32_t callingUid = DEFAULT_UID;

    // create flow control
    // single app flow control test
    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    // global flow control test
    int gap = MAX_CREATE_NUM_PERSECOND - MAX_CREATE_NUM_PERSECOND_PERAPP;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    // update flow control
    // single app flow control test
    callingUid = DEFAULT_UID;
    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);

    // global flow control test
    gap = MAX_UPDATE_NUM_PERSECOND - MAX_UPDATE_NUM_PERSECOND_PERAPP;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
}
}  // namespace Notification
}  // namespace OHOS