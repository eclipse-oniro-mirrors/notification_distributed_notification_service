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

#include <gtest/gtest.h>
#include <iostream>

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_inner_errors.h"
#include "mock_accesstoken_kit.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class PriorityManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SetPriorityEnabled_0100
 * @tc.desc: Test SetPriorityEnabled success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabled_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabled(false);
    bool enable = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityEnabled(enable), ERR_OK);
    EXPECT_FALSE(enable);
}

/**
 * @tc.name: SetPriorityEnabled_0200
 * @tc.desc: Test SetPriorityEnabled return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabled_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabled(false), ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetPriorityEnabledByBundle_0100
 * @tc.desc: Test SetPriorityEnabledByBundle success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 2);
    int32_t enableStatusInt = 1;
    EXPECT_EQ(
        AdvancedNotificationService::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatusInt), ERR_OK);
    EXPECT_EQ(enableStatusInt, 2);
}

/**
 * @tc.name: SetPriorityEnabledByBundle_0200
 * @tc.desc: Test SetPriorityEnabledByBundle return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 2),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetPriorityEnabledByBundle_0300
 * @tc.desc: Test SetPriorityEnabledByBundle return ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 2),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetPriorityEnabledByBundle_0400
 * @tc.desc: Test SetPriorityEnabledByBundle return ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 3),
        ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsPriorityEnabledByBundle_0100
 * @tc.desc: Test IsPriorityEnabledByBundle return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, IsPriorityEnabledByBundle_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    int32_t enableStatusInt;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatusInt),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: IsPriorityEnabledByBundle_0200
 * @tc.desc: Test IsPriorityEnabledByBundle return ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, IsPriorityEnabledByBundle_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    int32_t enableStatusInt;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatusInt),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetBundlePriorityConfig_0100
 * @tc.desc: Test SetBundlePriorityConfig success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetBundlePriorityConfig_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, "keyword1\nkeyword2");
    std::string value;
    EXPECT_EQ(
        AdvancedNotificationService::GetInstance()->GetBundlePriorityConfig(bundleOption, value), ERR_OK);
    EXPECT_EQ(value, "");
}

/**
 * @tc.name: SetBundlePriorityConfig_0200
 * @tc.desc: Test SetBundlePriorityConfig return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetBundlePriorityConfig_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, "keyword1\nkeyword2"),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetBundlePriorityConfig_0300
 * @tc.desc: Test SetBundlePriorityConfig return ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetBundlePriorityConfig_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, "keyword1\nkeyword2"),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetBundlePriorityConfig_0100
 * @tc.desc: Test GetBundlePriorityConfig return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetBundlePriorityConfig_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    std::string value;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetBundlePriorityConfig(bundleOption, value),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetBundlePriorityConfig_0200
 * @tc.desc: Test GetBundlePriorityConfig return ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetBundlePriorityConfig_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::string value;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetBundlePriorityConfig(bundleOption, value),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: TriggerUpdatePriorityType_0100
 * @tc.desc: Test TriggerUpdatePriorityType invalid request.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, TriggerUpdatePriorityType_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetInnerPriorityNotificationType(NotificationConstant::PriorityNotificationType::PAYMENT_DUE);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->TriggerUpdatePriorityType(request), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: TriggerUpdatePriorityType_0200
 * @tc.desc: Test TriggerUpdatePriorityType success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, TriggerUpdatePriorityType_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(10001);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new (std::nothrow) Notification(request);
    AdvancedNotificationService::GetInstance()->AddToNotificationList(record);
    request->SetInnerPriorityNotificationType(NotificationConstant::PriorityNotificationType::PAYMENT_DUE);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->TriggerUpdatePriorityType(request), ERR_OK);
    AdvancedNotificationService::GetInstance()->RemoveNotificationList(record);
}

/**
 * @tc.name: TriggerUpdatePriorityType_0300
 * @tc.desc: Test TriggerUpdatePriorityType return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, TriggerUpdatePriorityType_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->TriggerUpdatePriorityType(request),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: TriggerUpdatePriorityType_0400
 * @tc.desc: Test TriggerUpdatePriorityType with empty cache request.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, TriggerUpdatePriorityType_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(10001);
    sptr<Notification> notification = new (std::nothrow) Notification(nullptr);
    notification->SetKey(request->GetBaseKey(""));
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = notification;
    record->request = request;
    AdvancedNotificationService::GetInstance()->AddToNotificationList(record);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->TriggerUpdatePriorityType(request), ERR_ANS_INVALID_PARAM);
    AdvancedNotificationService::GetInstance()->RemoveNotificationList(record);
}
}
}