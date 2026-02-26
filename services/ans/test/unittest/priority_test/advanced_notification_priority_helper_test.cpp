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

extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

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
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    AdvancedNotificationPriorityHelper::GetInstance()->SetPriorityTypeToExtendInfo(request);
    requests.push_back(request);
    std::vector<int32_t> results;
    AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        NotificationAiExtensionWrapper::REFRESH_KEYWORD_PRIORITY_TYPE, requests, results);
    requests.clear();
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results), ERR_OK);
}

/**
 * @tc.name: RefreshPriorityType_0200
 * @tc.desc: Test RefreshPriorityType success when USER_MODIFIED_OFF.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, RefreshPriorityType_0200, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    int32_t uid = 1000;
    NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    sptr<NotificationBundleOption> notification = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(notification, priorityStatus);
    NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(notification, 31);
    std::vector<sptr<NotificationRequest>> requests;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorBundleName(bundleName);
    request->SetCreatorUid(uid);
    request->SetOwnerBundleName("");
    request->SetOwnerUid(uid);
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    requests.push_back(request);
    std::vector<int32_t> results;
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results), ERR_OK);
}

/**
 * @tc.name: RefreshPriorityType_0300
 * @tc.desc: Test RefreshPriorityType success when STATUS_ALL_PRIORITY.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, RefreshPriorityType_0300, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    int32_t uid = 1000;
    NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    sptr<NotificationBundleOption> notification = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(notification, priorityStatus);
    NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(notification, 32);
    std::vector<sptr<NotificationRequest>> requests;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorBundleName("");
    request->SetCreatorUid(uid);
    request->SetOwnerBundleName(bundleName);
    request->SetOwnerUid(uid);
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    requests.push_back(request);
    std::vector<int32_t> results;
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results), ERR_OK);
}

/**
 * @tc.name: RefreshPriorityType_0400
 * @tc.desc: Test RefreshPriorityType success.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, RefreshPriorityType_0400, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    int32_t uid = 1000;
    NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    sptr<NotificationBundleOption> notification = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(notification, priorityStatus);
    NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(notification, 31);
    std::vector<sptr<NotificationRequest>> requests;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorBundleName("");
    request->SetCreatorUid(uid);
    request->SetOwnerBundleName(bundleName);
    request->SetOwnerUid(uid);
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    requests.push_back(request);
    std::vector<int32_t> results;
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results), ERR_OK);
}

/**
 * @tc.name: RefreshPriorityType_0500
 * @tc.desc: Test RefreshPriorityType fail.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, RefreshPriorityType_0500, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 3);
    std::string bundleName = "bundleName";
    int32_t uid = 1000;
    NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    sptr<NotificationBundleOption> notification = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(notification, priorityStatus);
    NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(notification, 31);
    std::vector<sptr<NotificationRequest>> requests;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorBundleName("");
    request->SetCreatorUid(uid);
    request->SetOwnerBundleName(bundleName);
    request->SetOwnerUid(uid);
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    requests.push_back(request);
    std::vector<int32_t> results;
    EXPECT_EQ(AdvancedNotificationPriorityHelper::GetInstance()->RefreshPriorityType(
        NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE, requests, results),
       ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: UpdatePriorityType_0100
 * @tc.desc: Test UpdatePriorityType erased priorityType.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationPriorityHelperTest, UpdatePriorityType_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "bundleName";
    int32_t uid = 1000;
    NotificationConstant::SWITCH_STATE priorityStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    sptr<NotificationBundleOption> notification = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    NotificationPreferences::GetInstance()->PutPriorityEnabledByBundleV2(notification, priorityStatus);
    NotificationPreferences::GetInstance()->PutPriorityStrategyByBundle(notification, 32);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetCreatorBundleName("");
    request->SetCreatorUid(uid);
    request->SetOwnerBundleName(bundleName);
    request->SetOwnerUid(uid);
    request->SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::PRIMARY_CONTACT);
    AdvancedNotificationPriorityHelper::GetInstance()->UpdatePriorityType(nullptr);
    AdvancedNotificationPriorityHelper::GetInstance()->UpdatePriorityType(request);
    EXPECT_EQ(request->GetPriorityNotificationType(), NotificationConstant::PriorityNotificationType::OTHER);
}
#endif
}
}