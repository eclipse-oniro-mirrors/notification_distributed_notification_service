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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#ifdef DISTRIBUTED_FEATURE_MASTER
#include "ans_inner_errors.h"
#define private public
#define protected public
#include "distributed_unlock_listener_oper_service.h"
#undef private
#undef protected
#include "dm_device_info.h"
#include "notification_constant.h"
#include "notification_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
constexpr int32_t SYSTEM_APP_UID = 100;
class DistributedUnlockListenerOperServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};
 
/**
 * @tc.name: TriggerByJumpType_0100
 * @tc.desc: Test TriggerByJumpType with invalid hashCode.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedUnlockListenerOperServiceTest, TriggerByJumpType_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationNormalContent> implContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(implContent);
    NotificationRequest req(0);
    req.SetLabel("Label0");
    req.SetContent(content);
    std::string hashCode = req.GetNotificationHashCode();
    int32_t jumpType = NotificationConstant::DISTRIBUTE_JUMP_BY_NTF;
    int32_t peerDeviceType = DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD;
    int32_t btnIndex = 0;
    UnlockListenerOperService::GetInstance().TriggerByJumpType(hashCode, jumpType, peerDeviceType, btnIndex);
    sptr<NotificationRequest> notificationRequest = nullptr;
    auto result = NotificationHelper::GetNotificationRequestByHashCode(hashCode, notificationRequest);
    EXPECT_EQ(result, ERR_ANS_NON_SYSTEM_APP);
    EXPECT_EQ(notificationRequest, nullptr);
}
}
}
#endif