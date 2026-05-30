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

#include "nlohmann/json.hpp"

#define private public
#define protected public
#include "notification_ai_extension_wrapper.h"
#undef private
#undef protected
#include "ans_const_define.h"
#include "notification_classification.h"
#include "notification_preferences.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace Notification {
class NotificationAiExtensionWrapperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SyncRules_0100
 * @tc.desc: Test SyncRules fail.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAiExtensionWrapperTest, SyncRules_0100, Function | SmallTest | Level1)
{
    std::string priorityRule = NotificationPreferences::GetInstance()->GetAdditionalConfig(PRIORITY_RULE_CONFIG_KEY);
    NotificationPreferences::GetInstance()->SetKvToDb(PRIORITY_RULE_CONFIG_KEY, "test", SUBSCRIBE_USER_INIT);
    NOTIFICATION_AI_EXTENSION_WRAPPER->Init();
    NotificationPreferences::GetInstance()->SetKvToDb(PRIORITY_RULE_CONFIG_KEY, priorityRule, SUBSCRIBE_USER_INIT);
    EXPECT_NE(NOTIFICATION_AI_EXTENSION_WRAPPER->SyncRules("test"), 0);
}

/**
 * @tc.name: SyncRules_0200
 * @tc.desc: Test SyncRules when syncRules_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAiExtensionWrapperTest, SyncRules_0200, Function | SmallTest | Level1)
{
    NOTIFICATION_AI_EXTENSION_WRAPPER->syncRules_ = nullptr;
    std::string priorityRule = "test";
    EXPECT_EQ(NOTIFICATION_AI_EXTENSION_WRAPPER->SyncRules(priorityRule),
        NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: SyncBundleKeywords_0100
 * @tc.desc: Test SyncBundleKeywords fail.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAiExtensionWrapperTest, SyncBundleKeywords_0100, Function | SmallTest | Level1)
{
    NOTIFICATION_AI_EXTENSION_WRAPPER->syncBundleKeywords_ = nullptr;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    EXPECT_EQ(NOTIFICATION_AI_EXTENSION_WRAPPER->SyncBundleKeywords(bundleOption, "keyword1\nkeyword2"),
        NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: NotifyPriorityEvent_0100
 * @tc.desc: Test NotifyPriorityEvent fail.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAiExtensionWrapperTest, NotifyPriorityEvent_0100, Function | SmallTest | Level1)
{
    NOTIFICATION_AI_EXTENSION_WRAPPER->notifyPriorityEvent_ = nullptr;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 200202);
    std::vector<sptr<NotificationBundleOption>> bundleOptions;
    bundleOptions.emplace_back(bundleOption);
    std::vector<sptr<NotificationRequest>> requests;
    EXPECT_EQ(NOTIFICATION_AI_EXTENSION_WRAPPER->NotifyPriorityEvent("event", bundleOptions, requests),
        NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL);
}

/**
 * @tc.name: UpdateNotification_0100
 * @tc.desc: Test UpdateNotification when updateNotification_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAiExtensionWrapperTest, UpdateNotification_0100, Function | SmallTest | Level1)
{
    NOTIFICATION_AI_EXTENSION_WRAPPER->updateNotification_ = nullptr;
    std::vector<sptr<NotificationRequest>> requests;
    std::vector<nlohmann::json> commands;
    std::vector<sptr<NotificationClassification>> notificationClassifications;
    std::vector<int32_t> results;
    NOTIFICATION_AI_EXTENSION_WRAPPER->Init();
    EXPECT_EQ(NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(requests,
        commands, notificationClassifications, results),
        NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL);
    NOTIFICATION_AI_EXTENSION_WRAPPER->InitExtensionWrapper();
}

/**
 * @tc.name: UpdateNotification_0200
 * @tc.desc: Test UpdateNotification with valid commands and notificationClassifications.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationAiExtensionWrapperTest, UpdateNotification_0200, Function | SmallTest | Level1)
{
    NOTIFICATION_AI_EXTENSION_WRAPPER->updateNotification_ = nullptr;
    std::vector<sptr<NotificationRequest>> requests;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    requests.push_back(request);
    std::vector<nlohmann::json> commands;
    nlohmann::json command = nlohmann::json::object();
    nlohmann::json params = nlohmann::json::object();
    params["strategy"] = 1;
    command[NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE] = params;
    command["aiStatus"] = 1;
    commands.push_back(command);
    std::vector<sptr<NotificationClassification>> notificationClassifications;
    notificationClassifications.push_back(nullptr);
    std::vector<int32_t> results;
    EXPECT_EQ(NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(requests,
        commands, notificationClassifications, results),
        NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL);
    NOTIFICATION_AI_EXTENSION_WRAPPER->InitExtensionWrapper();
}

/**
 * @tc.name: UPDATE_AGGREGATION_TYPE_0100
 * @tc.desc: Test UPDATE_AGGREGATION_TYPE constant value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationAiExtensionWrapperTest, UPDATE_AGGREGATION_TYPE_0100, Function | SmallTest | Level1)
{
    EXPECT_EQ(NotificationAiExtensionWrapper::UPDATE_AGGREGATION_TYPE, "update.aggregationNotificationType");
}

/**
 * @tc.name: UPDATE_PRIORITY_TYPE_0100
 * @tc.desc: Test UPDATE_PRIORITY_TYPE constant value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationAiExtensionWrapperTest, UPDATE_PRIORITY_TYPE_0100, Function | SmallTest | Level1)
{
    EXPECT_EQ(NotificationAiExtensionWrapper::UPDATE_PRIORITY_TYPE, "update.priorityNotificationType");
}

/**
 * @tc.name: REFRESH_KEYWORD_PRIORITY_TYPE_0100
 * @tc.desc: Test REFRESH_KEYWORD_PRIORITY_TYPE constant value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationAiExtensionWrapperTest, REFRESH_KEYWORD_PRIORITY_TYPE_0100, Function | SmallTest | Level1)
{
    EXPECT_EQ(NotificationAiExtensionWrapper::REFRESH_KEYWORD_PRIORITY_TYPE,
        "refresh.keyword.priorityNotificationType");
}

/**
 * @tc.name: REFRESH_SWITCH_PRIORITY_TYPE_0100
 * @tc.desc: Test REFRESH_SWITCH_PRIORITY_TYPE constant value.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationAiExtensionWrapperTest, REFRESH_SWITCH_PRIORITY_TYPE_0100, Function | SmallTest | Level1)
{
    EXPECT_EQ(NotificationAiExtensionWrapper::REFRESH_SWITCH_PRIORITY_TYPE,
        "refresh.switch.priorityNotificationType");
}
}
}
