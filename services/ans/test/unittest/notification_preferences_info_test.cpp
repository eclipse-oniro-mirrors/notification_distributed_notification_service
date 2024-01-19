/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ans_inner_errors.h"
#include "ans_ut_constant.h"
#include "notification_constant.h"
#define private public
#define protected public
#include "notification_preferences_info.h"
#include "advanced_notification_service.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GetSlotFlagsKeyFromType_00001
 * @tc.desc: Test GetSlotFlagsKeyFromType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationPreferencesInfoTest, GetSlotFlagsKeyFromType_00001, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    const char *res= bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::string resStr(res);
    EXPECT_EQ(resStr, "Social_communication");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::SERVICE_REMINDER);
    resStr = res;
    EXPECT_EQ(resStr, "Service_reminder");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    resStr = res;
    EXPECT_EQ(resStr, "Content_information");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::OTHER);
    resStr = res;
    EXPECT_EQ(resStr, "Other");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CUSTOM);
    resStr = res;
    EXPECT_EQ(resStr, "Custom");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::LIVE_VIEW);
    resStr = res;
    EXPECT_EQ(resStr, "Live_view");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    resStr = res;
    EXPECT_EQ(resStr, "Custom_service");
}


/**
 * @tc.name: SetSlotFlagsForSlot_00001
 * @tc.desc: Test SetSlotFlagsForSlot
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationPreferencesInfoTest, SetSlotFlagsForSlot_00001, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetSlotFlags(1);
    bundleInfo.SetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    int res = bundleInfo.GetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    EXPECT_NE(res, 0);
}
}
}
