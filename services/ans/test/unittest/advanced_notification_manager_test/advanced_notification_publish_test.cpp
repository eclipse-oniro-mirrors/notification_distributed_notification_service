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
 * @tc.name: BuildRequestWithUri_NullRequest_00001
 * @tc.desc: Test BuildRequestWithUri with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, BuildRequestWithUri_NullRequest_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;

    auto result = service->BuildRequestWithUri(nullRequest);
    EXPECT_EQ(result.GetRefPtr(), nullptr);
}

/**
 * @tc.name: BuildRequestWithUri_NullAdditionalData_00001
 * @tc.desc: Test BuildRequestWithUri with nullptr additionalData
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, BuildRequestWithUri_NullAdditionalData_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetAdditionalData(), nullptr);
}

/**
 * @tc.name: BuildRequestWithUri_NullWantAgent_00001
 * @tc.desc: Test BuildRequestWithUri with nullptr wantAgent
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, BuildRequestWithUri_NullWantAgent_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    request->SetAdditionalData(additionalData);

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_FALSE(additionalData->HasParam("ohos.notificationManager.wantUri"));
    auto resultData = result->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    EXPECT_TRUE(resultData->HasParam("ohos.notificationManager.wantUri"));
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

/**
 * @tc.name: CheckNotificationRequest_UserDeletableOnly_00001
 * @tc.desc: Test CheckNotificationRequest downgrades userDeletableOnly for unprivileged caller
 * @tc.type: FUNC
 * @tc.require: issue#4424
 */
HWTEST_F(AdvancedNotificationPublishTest, CheckNotificationRequest_UserDeletableOnly_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    request->SetUserDeletableOnly(true);
    EXPECT_EQ(service->CheckNotificationRequest(request), ERR_OK);
    EXPECT_TRUE(request->IsUserDeletableOnly());

    MockIsVerfyPermisson(false);
    request->SetUserDeletableOnly(true);
    EXPECT_EQ(service->CheckNotificationRequest(request), ERR_OK);
    EXPECT_FALSE(request->IsUserDeletableOnly());

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsVerfyPermisson(true);
    request->SetUserDeletableOnly(true);
    EXPECT_EQ(service->CheckNotificationRequest(request), ERR_OK);
    EXPECT_FALSE(request->IsUserDeletableOnly());

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
}

/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_NullRequest_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp with nullptr request
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_NullRequest_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> nullRequest = nullptr;
 
    service->ResetIdentityInfoForNonSystemApp(nullRequest, false, false);
    EXPECT_EQ(nullRequest, nullptr);
}
 
/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_ResetForgedOwnerInfo_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp resets forged owner uid/bundleName to default
 *           values but keeps ownerUserId, which alone does not identify another bundle.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_ResetForgedOwnerInfo_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerUid(200); // forged ownerUid, e.g. uid of the victim app
    request->SetOwnerBundleName("com.victim.bundle"); // forged ownerBundleName
    request->SetOwnerUserId(100); // ownerUserId is kept, not reset
 
    service->ResetIdentityInfoForNonSystemApp(request, false, false);
    EXPECT_EQ(request->GetOwnerUid(), DEFAULT_UID);
    EXPECT_TRUE(request->GetOwnerBundleName().empty());
    EXPECT_EQ(request->GetOwnerUserId(), 100);
}
 
/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_DefaultValueNotChanged_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp keeps default owner info unchanged
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_DefaultValueNotChanged_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
 
    service->ResetIdentityInfoForNonSystemApp(request, false, false);
    EXPECT_EQ(request->GetOwnerUid(), DEFAULT_UID);
    EXPECT_TRUE(request->GetOwnerBundleName().empty());
    EXPECT_EQ(request->GetOwnerUserId(), SUBSCRIBE_USER_INIT);
}
 
/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_PartialForged_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp only resets the forged field
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_PartialForged_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerUid(200); // only ownerUid is forged
 
    service->ResetIdentityInfoForNonSystemApp(request, false, false);
    EXPECT_EQ(request->GetOwnerUid(), DEFAULT_UID);
    EXPECT_TRUE(request->GetOwnerBundleName().empty());
    EXPECT_EQ(request->GetOwnerUserId(), SUBSCRIBE_USER_INIT);
}
 
/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_ResetForgedCreatorInfo_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp resets forged creator uid/bundleName to default
 *           values but keeps creatorUserId. Creator fields are restored from IPC parcels and must
 *           be controlled the same way as owner fields, otherwise a non-system client could spoof
 *           creatorBundleName and pollute per-bundle statistics.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_ResetForgedCreatorInfo_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetCreatorUid(300); // forged creatorUid, e.g. uid of the victim app
    request->SetCreatorBundleName("com.victim.bundle"); // forged creatorBundleName
    request->SetCreatorUserId(100); // creatorUserId is kept, not reset
 
    service->ResetIdentityInfoForNonSystemApp(request, false, false);
    EXPECT_EQ(request->GetCreatorUid(), DEFAULT_UID);
    EXPECT_TRUE(request->GetCreatorBundleName().empty());
    EXPECT_EQ(request->GetCreatorUserId(), 100);
}
 
/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_KeepIdentityForSystemApp_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp keeps owner/creator identity when the caller is
 *           a system app, so that agent/proxy publish capability is not broken by the reset.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_KeepIdentityForSystemApp_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerUid(200); // owner specified by trusted agent
    request->SetOwnerBundleName("com.proxied.bundle");
    request->SetCreatorUid(300);
    request->SetCreatorBundleName("com.agent.bundle");
 
    service->ResetIdentityInfoForNonSystemApp(request, true, false);
    // identity kept: system app is exempt from the reset
    EXPECT_EQ(request->GetOwnerUid(), 200);
    EXPECT_EQ(request->GetOwnerBundleName(), "com.proxied.bundle");
    EXPECT_EQ(request->GetCreatorUid(), 300);
    EXPECT_EQ(request->GetCreatorBundleName(), "com.agent.bundle");
}
 
/**
 * @tc.name: ResetIdentityInfoForNonSystemApp_KeepIdentityForSubsystem_00001
 * @tc.desc: Test ResetIdentityInfoForNonSystemApp keeps owner/creator identity when the caller is
 *           a subsystem (native token), matching the system-app exemption.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, ResetIdentityInfoForNonSystemApp_KeepIdentityForSubsystem_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerUid(200);
    request->SetOwnerBundleName("com.proxied.bundle");
    request->SetOwnerUserId(100);
 
    service->ResetIdentityInfoForNonSystemApp(request, false, true);
    // identity kept: subsystem is exempt from the reset
    EXPECT_EQ(request->GetOwnerUid(), 200);
    EXPECT_EQ(request->GetOwnerBundleName(), "com.proxied.bundle");
    EXPECT_EQ(request->GetOwnerUserId(), 100);
}
 
/**
 * @tc.name: CheckNotificationRequest_ResetForgedIdentityForNonSystemApp_00001
 * @tc.desc: Test CheckNotificationRequest resets forged owner/creator uid/bundleName for a
 *           non-system app before entering the publish flow, so that early failure-reporting
 *           branches can no longer forward a spoofed bundle name to analytics, while
 *           ownerUserId/creatorUserId are kept.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, CheckNotificationRequest_ResetForgedIdentityForNonSystemApp_00001,
    Function | SmallTest | Level1)
{
    MockIsSystemApp(false); // non-system app
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID); // non-native token
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerUid(200);
    request->SetOwnerBundleName("com.victim.bundle");
    request->SetOwnerUserId(100);
    request->SetCreatorUid(300);
    request->SetCreatorBundleName("com.victim.bundle");
    request->SetCreatorUserId(101);
 
    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_OK);
    // owner identity reset, ownerUserId kept
    EXPECT_EQ(request->GetOwnerUid(), DEFAULT_UID);
    EXPECT_TRUE(request->GetOwnerBundleName().empty());
    EXPECT_EQ(request->GetOwnerUserId(), 100);
    // creator identity reset, creatorUserId kept
    EXPECT_EQ(request->GetCreatorUid(), DEFAULT_UID);
    EXPECT_TRUE(request->GetCreatorBundleName().empty());
    EXPECT_EQ(request->GetCreatorUserId(), 101);
    MockIsSystemApp(true); // restore mock for subsequent tests
}
 
/**
 * @tc.name: CheckNotificationRequest_KeepIdentityForSystemApp_00001
 * @tc.desc: Test CheckNotificationRequest keeps owner/creator identity for a system app, so that
 *           agent/proxy publish capability (owner specified by a trusted system component) is not
 *           broken by the anti-spoofing reset.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest, CheckNotificationRequest_KeepIdentityForSystemApp_00001,
    Function | SmallTest | Level1)
{
    MockIsSystemApp(true); // system app
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP); // HAP token, so IsSystemApp() consults the system-app mock
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerUid(200);
    request->SetOwnerBundleName("com.proxied.bundle"); // owner specified by trusted agent
    request->SetCreatorBundleName("com.agent.bundle");

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_OK);
    // identity kept: system app is exempt from the reset
    EXPECT_EQ(request->GetOwnerUid(), 200);
    EXPECT_EQ(request->GetOwnerBundleName(), "com.proxied.bundle");
    EXPECT_EQ(request->GetCreatorBundleName(), "com.agent.bundle");
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID); // restore mock for subsequent tests
}

}  // namespace Notification
}  // namespace OHOS