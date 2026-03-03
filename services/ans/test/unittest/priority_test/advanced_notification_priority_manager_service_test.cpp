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
#include "bool_wrapper.h"
#include "mock_accesstoken_kit.h"

extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

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
    AdvancedNotificationService::GetInstance()->SetPriorityEnabled(true);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityEnabled(enable), ERR_OK);
    EXPECT_TRUE(enable);
}

/**
 * @tc.name: SetPriorityEnabled_0200
 * @tc.desc: Test SetPriorityEnabled return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabled_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
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
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 1);
    EXPECT_EQ(
        AdvancedNotificationService::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatusInt), ERR_OK);
    EXPECT_EQ(enableStatusInt, 1);
}

/**
 * @tc.name: SetPriorityEnabledByBundle_0200
 * @tc.desc: Test SetPriorityEnabledByBundle return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
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
 * @tc.name: SetPriorityEnabledByBundle_0500
 * @tc.desc: Test SetPriorityEnabledByBundle param ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundle_0500, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    bundleOption->SetUid(2000);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundle(bundleOption, 2),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: IsPriorityEnabledByBundle_0100
 * @tc.desc: Test IsPriorityEnabledByBundle return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, IsPriorityEnabledByBundle_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
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
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
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
 * @tc.name: SetBundlePriorityConfig_0400
 * @tc.desc: Test SetBundlePriorityConfig param ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetBundlePriorityConfig_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    bundleOption->SetUid(2000);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, ""),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetBundlePriorityConfigInner_0100
 * @tc.desc: Test SetBundlePriorityConfigInner with empty value success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetBundlePriorityConfigInner_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, ""), ERR_OK);
}

/**
 * @tc.name: GetBundlePriorityConfig_0100
 * @tc.desc: Test GetBundlePriorityConfig return ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetBundlePriorityConfig_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
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
    NotificationSubscriberManager::GetInstance()->NotifySystemUpdate(nullptr);
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
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
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

/**
 * @tc.name: GetRequestsFromNotification_0100
 * @tc.desc: Test GetRequestsFromNotification success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetRequestsFromNotification_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<Notification> notification = new (std::nothrow) Notification(nullptr);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(10001);
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    extendInfo->SetParam(ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG, AAFwk::Boolean::Box(true));
    request->SetExtendInfo(extendInfo);
    sptr<Notification> notification1 = new (std::nothrow) Notification(request);
    sptr<NotificationRequest> request2 = new (std::nothrow) NotificationRequest(10002);
    request2->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<Notification> notification2 = new (std::nothrow) Notification(request2);
    sptr<NotificationRequest> request3 = new (std::nothrow) NotificationRequest(10003);
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    request3->SetContent(content);
    sptr<Notification> notification3 = new (std::nothrow) Notification(request3);
    notifications.push_back(nullptr);
    notifications.push_back(notification);
    notifications.push_back(notification1);
    notifications.push_back(notification2);
    notifications.push_back(notification3);
    std::vector<sptr<NotificationRequest>> requests;
    AdvancedNotificationService::GetInstance()->GetRequestsFromNotification(notifications, requests);
    EXPECT_EQ(requests.size(), 1);
}

/**
 * @tc.name: SetPriorityEnabledByBundles_0100
 * @tc.desc: Test SetPriorityEnabledByBundles ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundles_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundles(priorityEnable),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetPriorityEnabledByBundles_0200
 * @tc.desc: Test SetPriorityEnabledByBundles param ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundles_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    priorityEnable[bundleOption] = false;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundles(priorityEnable),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetPriorityEnabledByBundles_0300
 * @tc.desc: Test SetPriorityEnabledByBundles param ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundles_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    bundleOption->SetUid(2000);
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    priorityEnable[bundleOption] = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundles(priorityEnable),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetPriorityEnabledByBundles_0400
 * @tc.desc: Test SetPriorityEnabledByBundles success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityEnabledByBundles_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    priorityEnable[bundleOption] = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundles(priorityEnable), ERR_OK);
}

/**
 * @tc.name: GetPriorityEnabledByBundles_0100
 * @tc.desc: Test GetPriorityEnabledByBundles ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityEnabledByBundles_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityEnabledByBundles(bundleOptions, priorityEnable),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetPriorityEnabledByBundles_0200
 * @tc.desc: Test GetPriorityEnabledByBundles param ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityEnabledByBundles_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityEnabledByBundles(bundleOptions, priorityEnable),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetPriorityEnabledByBundles_0300
 * @tc.desc: Test GetPriorityEnabledByBundles param ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityEnabledByBundles_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    bundleOption->SetUid(2000);
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityEnabledByBundles(bundleOptions, priorityEnable),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetPriorityEnabledByBundles_0400
 * @tc.desc: Test GetPriorityEnabledByBundles success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityEnabledByBundles_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    std::map<sptr<NotificationBundleOption>, bool> priorityEnable;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityEnabledByBundles(bundleOptions, priorityEnable),
        ERR_OK);
}

/**
 * @tc.name: SetPriorityIntelligentEnabled_0100
 * @tc.desc: Test SetPriorityIntelligentEnabled ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityIntelligentEnabled_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    bool enabled = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityIntelligentEnabled(enabled),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetPriorityIntelligentEnabled_0200
 * @tc.desc: Test SetPriorityIntelligentEnabled db fail.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityIntelligentEnabled_0200, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 3);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    bool enabled = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityIntelligentEnabled(enabled),
        ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: SetPriorityIntelligentEnabled_0300
 * @tc.desc: Test SetPriorityIntelligentEnabled success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityIntelligentEnabled_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    bool enabled = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityIntelligentEnabled(enabled), ERR_OK);
}

/**
 * @tc.name: IsPriorityIntelligentEnabled_0100
 * @tc.desc: Test IsPriorityIntelligentEnabled ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, IsPriorityIntelligentEnabled_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    bool enabled = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityIntelligentEnabled(enabled),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: IsPriorityIntelligentEnabled_0200
 * @tc.desc: Test IsPriorityIntelligentEnabled db fail.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, IsPriorityIntelligentEnabled_0200, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 3);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    bool enabled = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityIntelligentEnabled(enabled),
        ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: IsPriorityIntelligentEnabled_0300
 * @tc.desc: Test IsPriorityIntelligentEnabled success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, IsPriorityIntelligentEnabled_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    bool enabled = true;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->IsPriorityIntelligentEnabled(enabled), ERR_OK);
}

/**
 * @tc.name: SetPriorityStrategyByBundles_0100
 * @tc.desc: Test SetPriorityStrategyByBundles ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityStrategyByBundles_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundles(strategies),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetPriorityStrategyByBundles_0200
 * @tc.desc: Test SetPriorityStrategyByBundles ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityStrategyByBundles_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    bundleOption->SetUid(2000);
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    strategies[bundleOption] = 32;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundles(strategies),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetPriorityStrategyByBundles_0300
 * @tc.desc: Test SetPriorityStrategyByBundles ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityStrategyByBundles_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    strategies[bundleOption] = -1;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundles(strategies),
        ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetPriorityStrategyByBundles_0400
 * @tc.desc: Test SetPriorityStrategyByBundles ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityStrategyByBundles_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    strategies[bundleOption] = 32;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundles(strategies),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetPriorityStrategyByBundles_0500
 * @tc.desc: Test SetPriorityStrategyByBundles success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, SetPriorityStrategyByBundles_0500, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    strategies[bundleOption] = 32;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->SetPriorityStrategyByBundles(strategies), ERR_OK);
}

/**
 * @tc.name: GetPriorityStrategyByBundles_0100
 * @tc.desc: Test GetPriorityStrategyByBundles ERR_ANS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityStrategyByBundles_0100, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityStrategyByBundles(bundleOptions, strategies),
        ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetPriorityStrategyByBundles_0200
 * @tc.desc: Test GetPriorityStrategyByBundles ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityStrategyByBundles_0200, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    bundleOption->SetUid(2000);
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityStrategyByBundles(bundleOptions, strategies),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetPriorityStrategyByBundles_0300
 * @tc.desc: Test GetPriorityStrategyByBundles ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityStrategyByBundles_0300, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("testBundleName");
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityStrategyByBundles(bundleOptions, strategies),
        ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetPriorityStrategyByBundles_0400
 * @tc.desc: Test GetPriorityStrategyByBundles success.
 * @tc.type: FUNC
 */
HWTEST_F(PriorityManagerServiceTest, GetPriorityStrategyByBundles_0400, Function | SmallTest | Level1)
{
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    bundleOption->SetBundleName("bundleName");
    std::map<sptr<NotificationBundleOption>, int64_t> strategies;
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    EXPECT_EQ(AdvancedNotificationService::GetInstance()->GetPriorityStrategyByBundles(bundleOptions, strategies),
        ERR_OK);
}
}
}