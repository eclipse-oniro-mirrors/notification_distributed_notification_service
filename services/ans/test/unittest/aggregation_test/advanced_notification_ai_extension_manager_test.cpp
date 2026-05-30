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
#include <string>

#define private public
#define protected public
#include "advanced_notification_ai_extension_manager.h"
#include "notification_subscriber_manager.h"
#include "notification_ai_extension_wrapper.h"
#undef protected
#undef private

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "notification_classification.h"
#include "notification_constant.h"
#include "notification_preferences.h"
#include "notification_request.h"
#include "nlohmann/json.hpp"
#include "bool_wrapper.h"
#include "want_params.h"

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class AdvancedNotificationAiExtensionManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

/**
 * @tc.name: IsCollaborationNotification_0100
 * @tc.desc: Test IsCollaborationNotification returns false when extendInfo is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, IsCollaborationNotification_0100, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    // extendInfo is nullptr by default
    EXPECT_EQ(request->GetExtendInfo(), nullptr);

    bool result = manager->IsCollaborationNotification(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsCollaborationNotification_0200
 * @tc.desc: Test IsCollaborationNotification returns true when extendInfo has collaboration flag set to true
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, IsCollaborationNotification_0200, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);

    // Set extendInfo with collaboration flag = true
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    std::string flagKey = ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG;
    extendInfo->SetParam(flagKey, AAFwk::Boolean::Box(true));
    request->SetExtendInfo(extendInfo);

    bool result = manager->IsCollaborationNotification(request);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsCollaborationNotification_0300
 * @tc.desc: Test IsCollaborationNotification returns false when extendInfo has collaboration flag set to false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, IsCollaborationNotification_0300, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);

    // Set extendInfo with collaboration flag = false
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    std::string flagKey = ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG;
    extendInfo->SetParam(flagKey, AAFwk::Boolean::Box(false));
    request->SetExtendInfo(extendInfo);

    bool result = manager->IsCollaborationNotification(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsCollaborationNotification_0400
 * @tc.desc: Test IsCollaborationNotification returns false when extendInfo has no collaboration flag param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, IsCollaborationNotification_0400, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);

    // Set extendInfo without collaboration flag param
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    request->SetExtendInfo(extendInfo);

    bool result = manager->IsCollaborationNotification(request);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: BuildCommandForUpdate_0100
 * @tc.desc: Test BuildCommandForUpdate with nullptr request, command should remain unchanged
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, BuildCommandForUpdate_0100, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    nlohmann::json command = nlohmann::json::object();
    command[manager->HAS_COMMAND] = false;
    command[manager->AI_STATUS] = 1;

    manager->BuildCommandForUpdate(nullptr, command);

    // Command should remain unchanged when request is nullptr
    EXPECT_EQ(command[manager->HAS_COMMAND].get<bool>(), false);
    EXPECT_EQ(command[manager->AI_STATUS].get<uint32_t>(), 1);
}

/**
 * @tc.name: BuildCommandForUpdate_0200
 * @tc.desc: Test BuildCommandForUpdate with LIVE_VIEW slot type, command should not contain aggregation key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, BuildCommandForUpdate_0200, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    nlohmann::json command = nlohmann::json::object();
    command[manager->HAS_COMMAND] = false;
    command[manager->AI_STATUS] = 1;

    manager->BuildCommandForUpdate(request, command);

    // LIVE_VIEW slot type should skip command building, command should not contain aggregation key
    EXPECT_FALSE(command.contains(NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE));
}

/**
 * @tc.name: BuildCommandForUpdate_0300
 * @tc.desc: Test BuildCommandForUpdate with collaboration notification, command should not contain aggregation key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, BuildCommandForUpdate_0300, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);

    // Set extendInfo with collaboration flag = true to make it a collaboration notification
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    std::string flagKey = ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG;
    extendInfo->SetParam(flagKey, AAFwk::Boolean::Box(true));
    request->SetExtendInfo(extendInfo);

    nlohmann::json command = nlohmann::json::object();
    command[manager->HAS_COMMAND] = false;
    command[manager->AI_STATUS] = 1;

    manager->BuildCommandForUpdate(request, command);

    // Collaboration notification should skip command building
    EXPECT_FALSE(command.contains(NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE));
}

/**
 * @tc.name: BuildCommandForUpdate_0400
 * @tc.desc: Test BuildCommandForUpdate with normal request, command should contain aggregation key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, BuildCommandForUpdate_0400, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    // Set up aggregation subscriber count so BuildAggregationCommand can proceed
    NotificationSubscriberManager::GetInstance()->IncrementAggregationSubscriberCount();
    MockQueryForgroundOsAccountId(true, 0);

    // Set switches to ON for userId 100
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::OTHER);
    request->SetReceiverUserId(100);

    nlohmann::json command = nlohmann::json::object();
    command[manager->HAS_COMMAND] = false;
    command[manager->AI_STATUS] = 1;

    manager->BuildCommandForUpdate(request, command);

    // Normal request should trigger aggregation command building
    EXPECT_TRUE(command.contains(NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE));
    EXPECT_EQ(command[manager->HAS_COMMAND].get<bool>(), true);

    // Clean up
    NotificationSubscriberManager::GetInstance()->DecrementAggregationSubscriberCount();
}

/**
 * @tc.name: UpdateNotification_0100
 * @tc.desc: Test UpdateNotification returns ERR_OK when GetPriorityIntelligentEnabled with no results
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, UpdateNotification_0100, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    // Clear preferences to ensure GetPriorityIntelligentEnabled returns ERR_OK
    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();

    std::vector<sptr<NotificationRequest>> requests;
    std::vector<sptr<NotificationClassification>> classifications;

    int32_t result = manager->UpdateNotification(requests, classifications);
    // When GetPriorityIntelligentEnabled with no results, result should be ERR_OK
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: UpdateNotification_0200
 * @tc.desc: Test UpdateNotification returns ERR_OK when no requests need updating (all LIVE_VIEW)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, UpdateNotification_0200, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    // Set priority intelligent enabled to ON
    NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);

    // Create a LIVE_VIEW request that will not need updating
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    std::vector<sptr<NotificationRequest>> requests = {request};
    std::vector<sptr<NotificationClassification>> classifications;

    int32_t result = manager->UpdateNotification(requests, classifications);
    // When needUpdateCount == 0, should return ERR_OK without calling AI extension
    EXPECT_EQ(result, NotificationAiExtensionWrapper::ErrorCode::ERR_OK);
}

/**
 * @tc.name: UpdateNotification_0300
 * @tc.desc: Test UpdateNotification with empty requests vector and enabled switch
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, UpdateNotification_0300, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    // Set priority intelligent enabled to ON
    NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    std::vector<sptr<NotificationRequest>> requests;
    std::vector<sptr<NotificationClassification>> classifications;

    int32_t result = manager->UpdateNotification(requests, classifications);
    // Empty requests vector means needUpdateCount == 0, should return ERR_OK
    EXPECT_EQ(result, NotificationAiExtensionWrapper::ErrorCode::ERR_OK);
}

/**
 * @tc.name: UpdateNotification_0400
 * @tc.desc: Test UpdateNotification with collaboration notification requests (no update needed)
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, UpdateNotification_0400, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    // Set priority intelligent enabled to ON
    NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);

    // Create a collaboration notification request
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    std::shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    std::string flagKey = ANS_EXTENDINFO_INFO_PRE + EXTENDINFO_FLAG;
    extendInfo->SetParam(flagKey, AAFwk::Boolean::Box(true));
    request->SetExtendInfo(extendInfo);

    std::vector<sptr<NotificationRequest>> requests = {request};
    std::vector<sptr<NotificationClassification>> classifications;

    int32_t result = manager->UpdateNotification(requests, classifications);
    // Collaboration notification should not need updating, needUpdateCount == 0
    EXPECT_EQ(result, NotificationAiExtensionWrapper::ErrorCode::ERR_OK);
}

/**
 * @tc.name: UpdateNotification_0500
 * @tc.desc: Test UpdateNotification with normal request that needs updating,
 *           AI extension wrapper returns ERR_FAIL when updateNotification_ is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationAiExtensionManagerTest, UpdateNotification_0500, Function | SmallTest | Level1)
{
    auto manager = DelayedSingleton<AdvancedNotificationAiExtensionManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    // Set priority intelligent enabled to ON
    NotificationPreferences::GetInstance()->PutPriorityIntelligentEnabled(
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);

    // Set up aggregation subscriber count so BuildAggregationCommand can proceed
    NotificationSubscriberManager::GetInstance()->IncrementAggregationSubscriberCount();
    MockQueryForgroundOsAccountId(true, 0);
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::DEAL,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);
    NotificationPreferences::GetInstance()->SetNotificationSwitch(
        NotificationConstant::NotificationSwitch::LOGISTICS,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON, 100);

    // Create a normal request that will need updating
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    request->SetSlotType(NotificationConstant::SlotType::OTHER);
    request->SetReceiverUserId(100);

    std::vector<sptr<NotificationRequest>> requests = {request};
    std::vector<sptr<NotificationClassification>> classifications;

    // Set updateNotification_ to nullptr to simulate AI extension call failure
    NOTIFICATION_AI_EXTENSION_WRAPPER->updateNotification_ = nullptr;

    int32_t result = manager->UpdateNotification(requests, classifications);
    // When AI extension wrapper fails, should return ERR_FAIL
    EXPECT_EQ(result, NotificationAiExtensionWrapper::ErrorCode::ERR_FAIL);

    // Restore AI extension wrapper
    NOTIFICATION_AI_EXTENSION_WRAPPER->InitExtensionWrapper();

    // Clean up
    NotificationSubscriberManager::GetInstance()->DecrementAggregationSubscriberCount();
}
}  // namespace Notification
}  // namespace OHOS