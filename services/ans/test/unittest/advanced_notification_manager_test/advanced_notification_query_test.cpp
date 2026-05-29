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

#include "gtest/gtest.h"
#define private public
#include "advanced_notification_service.h"
#include "notification_bundle_option.h"
#include "notification_request.h"
#include "notification_record.h"
#include "notification_parameters.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

class AdvancedNotificationQueryTest : public testing::Test {
public:
    void SetUp() override
    {
        MockIsSystemApp(true);
        MockIsVerfyPermisson(true);
    }
    void TearDown() override {}
};

static sptr<AdvancedNotificationService> GetService()
{
    return new AdvancedNotificationService();
}

/**
 * @tc.name: GetActiveNotifications_SynchronizerNullptr_00001
 * @tc.desc: Test GetActiveNotifications with nullptr synchronizer
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotifications_SynchronizerNullptr_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->GetActiveNotifications("", nullptr);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetAllActiveNotifications_PermissionDenied_00001
 * @tc.desc: Test GetAllActiveNotifications with permission denied
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetAllActiveNotifications_PermissionDenied_00001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    MockIsSystemApp(false);
    auto service = GetService();
    std::vector<sptr<Notification>> notifications;
    
    auto result = service->GetAllActiveNotifications(notifications);
    EXPECT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: ExtractWantAgentInfo_NullWantAgent_00001
 * @tc.desc: Test ExtractWantAgentInfo with nullptr wantAgent
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, ExtractWantAgentInfo_NullWantAgent_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    
    service->ExtractWantAgentInfo(record, parameters);
    EXPECT_NE(parameters, nullptr);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_CheckPermissionFailed_00001
 * @tc.desc: Test GetAllNotificationsBySlotType with permission check failed
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest,
    GetAllNotificationsBySlotType_CheckPermissionFailed_00001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    MockIsSystemApp(false);
    auto service = GetService();
    std::vector<sptr<Notification>> notifications;
    int32_t userId = 100;
    
    auto result = service->GetAllNotificationsBySlotType(notifications,
        static_cast<int32_t>(NotificationConstant::SlotType::SERVICE_REMINDER), userId);
    EXPECT_EQ(result, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: QueryNotificationParameters_NullRecord_00001
 * @tc.desc: Test QueryNotificationParameters with null record
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, QueryNotificationParameters_NullRecord_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->QueryNotificationParameters(1, "testLabel", bundle, parameters);
    EXPECT_NE(result, ERR_OK);
}

}  // namespace Notification
}  // namespace OHOS