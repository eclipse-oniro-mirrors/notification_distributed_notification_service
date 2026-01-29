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
#include "notification_ai_extension_wrapper.h"
#undef private
#undef protected
#include "ans_const_define.h"
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
    EXPECT_EQ(
        NOTIFICATION_AI_EXTENSION_WRAPPER->NotifyPriorityEvent("event", bundleOption),
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
    std::vector<int32_t> results;
    NOTIFICATION_AI_EXTENSION_WRAPPER->Init();
    EXPECT_EQ(NOTIFICATION_AI_EXTENSION_WRAPPER->UpdateNotification(
        requests, NotificationAiExtensionWrapper::REFRESH_KEYWORD_PRIORITY_TYPE, results),
        NOTIFICATION_AI_EXTENSION_WRAPPER->ErrorCode::ERR_FAIL);
    NOTIFICATION_AI_EXTENSION_WRAPPER->InitExtensionWrapper();
}
}
}