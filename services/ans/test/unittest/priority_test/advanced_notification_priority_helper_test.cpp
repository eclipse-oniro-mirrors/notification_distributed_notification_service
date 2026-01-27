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
#include <iostream>

#define private public
#define protected public
#include "advanced_notification_priority_helper.h"
#undef private
#undef protected
#include "ans_const_define.h"
#include "notification_ai_extension_wrapper.h"
#include "notification_constant.h"
#include "notification_preferences.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class AdvancedNotificationPriorityHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
/**
 * @tc.name: IsNeedUpdatePriorityType_0100
 * @tc.desc: Test IsNeedUpdatePriorityType when request is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, IsNeedUpdatePriorityType_0100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    NotificationPreferences::GetInstance()->SetPriorityEnabled(NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    AdvancedNotificationPriorityHelper::GetInstance()->UpdatePriorityType(nullptr);
    EXPECT_FALSE(AdvancedNotificationPriorityHelper::GetInstance()->IsNeedUpdatePriorityType(request));
}

/**
 * @tc.name: SetPriorityTypeToExtendInfo_0100
 * @tc.desc: Test SetPriorityTypeToExtendInfo success.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, SetPriorityTypeToExtendInfo_0100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    AdvancedNotificationPriorityHelper::GetInstance()->SetPriorityTypeToExtendInfo(request);
    EXPECT_NE(request->GetExtendInfo(), nullptr);
    std::string priorityType = request->GetExtendInfo()->GetStringParam(EXTENDINFO_PRIORITY_TYPE);
    EXPECT_EQ(priorityType, NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
}

/**
 * @tc.name: RefreshPriorityType_0100
 * @tc.desc: Test RefreshPriorityType success.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, RefreshPriorityType_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationRequest>> requests;
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        requests, NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE),
        NotificationAiExtensionWrapper::ErrorCode::ERR_OK);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    AdvancedNotificationPriorityHelper::GetInstance()->SetPriorityTypeToExtendInfo(request);
    requests.push_back(request);
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        requests, NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE),
        NotificationAiExtensionWrapper::ErrorCode::ERR_OK);
}
#endif
}
}