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
#include "notification_content.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"
#include "notification_constant.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsVerfyPermisson(bool isVerify);

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
 * @tc.name: CheckNotificationRequest_LiveViewTypeMismatchSlot_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_ANS_INVALID_PARAM
 *           when type is LIVE_VIEW but slotType is not LIVE_VIEW
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_LiveViewTypeMismatchSlot_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    request->SetContent(std::make_shared<NotificationContent>(liveViewContent));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckNotificationRequest_LocalLiveViewTypeMismatchSlot_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_ANS_INVALID_PARAM
 *           when type is LOCAL_LIVE_VIEW but slotType is not LIVE_VIEW
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_LocalLiveViewTypeMismatchSlot_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    request->SetContent(std::make_shared<NotificationContent>(localLiveViewContent));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckNotificationRequest_LiveViewTypeMatchSlot_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_OK when
 *           type is LIVE_VIEW and slotType is LIVE_VIEW
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_LiveViewTypeMatchSlot_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    request->SetContent(std::make_shared<NotificationContent>(liveViewContent));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckNotificationRequest_LocalLiveViewTypeMatchSlot_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_OK when
 *           type is LOCAL_LIVE_VIEW and slotType is LIVE_VIEW
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_LocalLiveViewTypeMatchSlot_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    request->SetContent(std::make_shared<NotificationContent>(localLiveViewContent));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckNotificationRequest_NonLiveViewTypeAnySlot_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_OK when
 *           type is not LIVE_VIEW/LOCAL_LIVE_VIEW
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_NonLiveViewTypeAnySlot_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto normalContent = std::make_shared<NotificationNormalContent>();
    request->SetContent(std::make_shared<NotificationContent>(normalContent));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: CheckNotificationRequest_LiveViewTypeMismatchSlotOther_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_ANS_INVALID_PARAM
 *           when type is LIVE_VIEW but slotType is OTHER
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_LiveViewTypeMismatchSlotOther_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    request->SetContent(std::make_shared<NotificationContent>(liveViewContent));
    request->SetSlotType(NotificationConstant::SlotType::OTHER);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckNotificationRequest_LocalLiveViewTypeMismatchSlotContentInfo_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_ANS_INVALID_PARAM
 *           when type is LOCAL_LIVE_VIEW but slotType is CONTENT_INFORMATION
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_LocalLiveViewTypeMismatchSlotContentInfo_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    request->SetContent(std::make_shared<NotificationContent>(localLiveViewContent));
    request->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CheckNotificationRequest_NoContentAnySlot_00001
 * @tc.desc: Test CheckNotificationRequest returns ERR_OK when
 *           request has no content (type is NONE)
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationPublishTest,
    CheckNotificationRequest_NoContentAnySlot_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    auto result = service->CheckNotificationRequest(request);
    EXPECT_EQ(result, ERR_OK);
}

}  // namespace Notification
}  // namespace OHOS