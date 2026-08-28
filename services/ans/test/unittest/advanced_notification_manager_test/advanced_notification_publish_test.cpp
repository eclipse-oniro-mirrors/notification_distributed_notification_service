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
#include "accesstoken_kit.h"
#define private public
#include "advanced_notification_service.h"
#include "notification_bundle_option.h"
#include "notification_request.h"
#include "notification_content.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

namespace OHOS {
namespace Notification {

extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);

class AdvancedNotificationPublishTest : public testing::Test {
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
 * @tc.name: CheckNotificationRequest_NullRequest_00001
 * @tc.desc: Test CheckNotificationRequest with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, CheckNotificationRequest_NullRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;
    
    auto result = service->CheckNotificationRequest(nullRequest);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: SetControlFlagsByFlags_NullRequest_00001
 * @tc.desc: Test SetControlFlagsByFlags with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, SetControlFlagsByFlags_NullRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;
    
    service->SetControlFlagsByFlags(nullRequest);
    EXPECT_EQ(nullRequest, nullptr);
}

/**
 * @tc.name: SetControlFlagsByFlags_NullFlags_00001
 * @tc.desc: Test SetControlFlagsByFlags with request without flags
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, SetControlFlagsByFlags_NullFlags_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    
    service->SetControlFlagsByFlags(request);
    EXPECT_NE(request, nullptr);
}

/**
 * @tc.name: SetIsFromSAToExtendInfo_NullRequest_00001
 * @tc.desc: Test SetIsFromSAToExtendInfo with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, SetIsFromSAToExtendInfo_NullRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;
    
    service->SetIsFromSAToExtendInfo(nullRequest);
    EXPECT_EQ(nullRequest, nullptr);
}

/**
 * @tc.name: SetIsFromSAToExtendInfo_NullExtendInfo_00001
 * @tc.desc: Test SetIsFromSAToExtendInfo with nullptr extendInfo
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, SetIsFromSAToExtendInfo_NullExtendInfo_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    
    service->SetIsFromSAToExtendInfo(request);
    EXPECT_NE(request, nullptr);
}

/**
 * @tc.name: GrantSoundPermission_NullRequest_00001
 * @tc.desc: Test GrantSoundPermission with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GrantSoundPermission_NullRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->GrantSoundPermission(nullRequest, bundle);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GrantSoundPermission_NullBundleOption_00001
 * @tc.desc: Test GrantSoundPermission with nullptr bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GrantSoundPermission_NullBundleOption_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<NotificationBundleOption> nullBundle = nullptr;
    
    auto result = service->GrantSoundPermission(request, nullBundle);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GrantSoundPermission_EmptySoundPath_00001
 * @tc.desc: Test GrantSoundPermission with empty soundPath
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GrantSoundPermission_EmptySoundPath_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSound("");
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);
    
    auto result = service->GrantSoundPermission(request, bundle);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: UpdateNotificationTimerByUid_NonSystemService_00001
 * @tc.desc: Test UpdateNotificationTimerByUid with non-system service
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    UpdateNotificationTimerByUid_NonSystemService_00001, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    auto service = GetService();
    
    auto result = service->UpdateNotificationTimerByUid(100, 1);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: GetUri_NullRequest_00001
 * @tc.desc: Test GetUri with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GetUri_NullRequest_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;
    
    auto result = service->GetUri(nullRequest);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: GetUri_NullAdditionalData_00001
 * @tc.desc: Test GetUri with nullptr additionalData
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GetUri_NullAdditionalData_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    
    auto result = service->GetUri(request);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: GetUri_NullWantAgent_00001
 * @tc.desc: Test GetUri with nullptr wantAgent
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GetUri_NullWantAgent_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    request->SetAdditionalData(additionalData);
    
    auto result = service->GetUri(request);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: CheckNotificationRequest_PublishDelayTimeTooLarge_00001
 * @tc.desc: Test CheckNotificationRequest with publishDelayTime > MAX_PUBLISH_DELAY_TIME
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_PublishDelayTimeTooLarge_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();

    request->SetPublishDelayTime(MAX_PUBLISH_DELAY_TIME + 1);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: PublishContinuousTaskNotification_GetOsAccountFailed_00001
 * @tc.desc: Test PublishContinuousTaskNotification returns early when GetOsAccountLocalIdFromUid fails
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    PublishContinuousTaskNotification_GetOsAccountFailed_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockGetOsAccountLocalIdFromUid(false, 1); // resolution fails
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();

    auto result = service->PublishContinuousTaskNotification(request);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED); // resolution failure is rejected
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set

    MockGetOsAccountLocalIdFromUid(true, 0);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
}

/**
 * @tc.name: PublishContinuousTaskNotification_InvalidUserId_00001
 * @tc.desc: Test PublishContinuousTaskNotification returns early when resolved userId is invalid
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    PublishContinuousTaskNotification_InvalidUserId_00001, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();

    auto result = service->PublishContinuousTaskNotification(request);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED); // invalid resolved userId is rejected
    EXPECT_EQ(request->GetCreatorUserId(), SUBSCRIBE_USER_INIT); // creatorUserId is not set

    MockGetOsAccountLocalIdFromUid(true, 0);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
}

/**
 * @tc.name: GrantSoundPermission_GetOsAccountFailed_00001
 * @tc.desc: Test GrantSoundPermission returns false when GetOsAccountLocalIdFromUid fails
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GrantSoundPermission_GetOsAccountFailed_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSound("uri::com.test.bundle/files/sound.mp3");
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    MockGetOsAccountLocalIdFromUid(false, 0); // resolution fails
    auto result = service->GrantSoundPermission(request, bundle);
    EXPECT_FALSE(result); // resolution failure is rejected
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: GrantSoundPermission_InvalidUserId_00001
 * @tc.desc: Test GrantSoundPermission returns false when resolved userId is invalid (< 0)
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, GrantSoundPermission_InvalidUserId_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSound("uri::com.test.bundle/files/sound.mp3");
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = service->GrantSoundPermission(request, bundle);
    EXPECT_FALSE(result); // invalid resolved userId is rejected
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

}  // namespace Notification
}  // namespace OHOS