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

#include "errors.h"
#include "notification_content.h"
#include "notification_record.h"
#include "notification_request.h"
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#define private public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "disturb_manager.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_push_callback_stub.h"
#include "system_event_observer.h"
#include "notification_constant.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "bundle_manager_helper.h"

extern void MockIsOsAccountExists(bool mockRet);
extern void MockVerifyNativeToken(bool mockRet);
extern void MockVerifyShellToken(bool mockRet);

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {
extern void MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsNonBundleName(bool isNonBundleName);
extern void MockIsVerfyPermisson(bool isVerify);

class DisturbManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void TestAddSlot(NotificationConstant::SlotType type);
    void TestAddLiveViewSlot(bool isForceControl);
    void MockSystemApp();

private:
    static sptr<DisturbManager> disturbManager_;
};

void DisturbManagerTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    disturbManager_ = new (std::nothrow) DisturbManager();
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

/**
 * @tc.number    : SetDoNotDisturbDate_1000
 * @tc.name      : SetDoNotDisturbDate_1000
 * @tc.desc      : Test SetDoNotDisturbDate function return ERR_ANS_NON_SYSTEM_APP.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(DisturbManagerTest, SetDoNotDisturbDate_1000, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    ASSERT_EQ(disturbManager_->SetDoNotDisturbDate(date), ERR_ANS_NON_SYSTEM_APP);
    ASSERT_EQ(disturbManager_->GetDoNotDisturbDate(date), ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.number    : SetDoNotDisturbDate_2000
 * @tc.name      : SetDoNotDisturbDate_2000
 * @tc.desc      : Test SetDoNotDisturbDate function return ERR_ANS_PERMISSION_DENIED.
 * @tc.require   : #I6P8UI
 */
HWTEST_F(DisturbManagerTest, SetDoNotDisturbDate_2000, Function | SmallTest | Level1)
{
    MockVerifyNativeToken(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(false);

    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
    ASSERT_EQ(disturbManager_->SetDoNotDisturbDate(date), ERR_ANS_PERMISSION_DENIED);
    ASSERT_EQ(disturbManager_->GetDoNotDisturbDate(date), ERR_ANS_PERMISSION_DENIED);
}

}
}