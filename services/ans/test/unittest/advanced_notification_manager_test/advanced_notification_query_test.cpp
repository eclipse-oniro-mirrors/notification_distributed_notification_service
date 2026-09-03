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
#include "ans_service_errors.h"
#include "mock_accesstoken_kit.h"
#include "notification_bundle_option.h"
#include "notification_request.h"
#include "notification_record.h"
#include "notification_parameters.h"

using namespace testing::ext;
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

namespace OHOS {
namespace Notification {
class AdvancedNotificationQueryTest : public testing::Test {
public:
    void SetUp() override
    {
        MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
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
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
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
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
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
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
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

/**
 * @tc.name: QueryNotificationParameters_GetOsAccountFailed_00001
 * @tc.desc: Test QueryNotificationParameters when GetOsAccountLocalIdFromUid fails
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, QueryNotificationParameters_GetOsAccountFailed_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    MockGetOsAccountLocalIdFromUid(false, 0);
    auto result = service->QueryNotificationParameters(1, "testLabel", bundle, parameters);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: QueryNotificationParameters_InvalidUserId_00001
 * @tc.desc: Test QueryNotificationParameters when userId is invalid (<= 0)
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, QueryNotificationParameters_InvalidUserId_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = service->QueryNotificationParameters(1, "testLabel", bundle, parameters);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: GetActiveNotificationByFilter_NullBundleOption_00001
 * @tc.desc: Test GetActiveNotificationByFilter with nullptr bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotificationByFilter_NullBundleOption_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request;
    std::vector<std::string> extraInfoKeys;

    auto result = service->GetActiveNotificationByFilter(nullptr, 1, "label", 0, extraInfoKeys, request);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name: GetActiveNotificationByFilter_InvalidBundleWithUserIdInit_00001
 * @tc.desc: Test GetActiveNotificationByFilter with invalid bundleOption and userId -1
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotificationByFilter_InvalidBundleWithUserIdInit_00001,
    Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    auto service = GetService();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundleName", 0);
    sptr<NotificationRequest> request;
    std::vector<std::string> extraInfoKeys;

    auto result = service->GetActiveNotificationByFilter(bundleOption, 1, "label", -1, extraInfoKeys, request);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_BUNDLE);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: GetActiveNotificationByFilter_FallbackBundleCreated_00001
 * @tc.desc: Test GetActiveNotificationByFilter creates fallback bundle when bundleOption is valid
 *           but GenerateValidBundleOption fails
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotificationByFilter_FallbackBundleCreated_00001,
    Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    auto service = GetService();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundleName", 0);
    sptr<NotificationRequest> request;
    std::vector<std::string> extraInfoKeys;

    auto result = service->GetActiveNotificationByFilter(bundleOption, 1, "label", 0, extraInfoKeys, request);
    EXPECT_NE(result, ERR_ANS_INNER_INVALID_BUNDLE);
    MockQueryForgroundOsAccountId(true, 0);
}

}  // namespace Notification
}  // namespace OHOS
