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
#include "gmock/gmock.h"

#define private public
#define protected public
#include "notification_clone_priority_service.h"
#undef private
#undef protected
#include "advanced_notification_service.h"
#include "notification_clone_util.h"
#include "notification_preferences.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
// Test suite class
class NotificationClonePriorityTest : public ::testing::Test {
protected:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: OnBackUp_00001
 * @tc.desc: Test clone OnBackUp.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnBackUp_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfigInner(bundleOption, "test1\\ntest2\\ntest3");
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bundleOption, 0);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->OnBackup(jsonObject), ERR_OK);
}

/**
 * @tc.name: OnRestoreStart_00001
 * @tc.desc: Test clone OnRestoreStart success.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreStart_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationClonePriorityInfo priorityInfo;
    priorityInfo.bundleName_ = "bundleName";
    priorityInfo.appIndex_ = 0;
    priorityInfo.enableStatus_ = 0;
    priorityInfo.clonePriorityType_ = NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE;
    cloneInfos.push_back(priorityInfo);
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationPreferences::GetInstance()->UpdateClonePriorityInfos(userId, cloneInfos);
    NotificationClonePriority::GetInstance()->OnUserSwitch(userId);
    NotificationClonePriority::GetInstance()->OnRestoreStart("bundleName", 0, userId, 1000);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreStart_00002
 * @tc.desc: Test clone OnRestoreStart after OnRestore.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreStart_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationClonePriorityInfo priorityInfo;
    priorityInfo.bundleName_ = "bundleName";
    priorityInfo.appIndex_ = 0;
    priorityInfo.enableStatus_ = 0;
    priorityInfo.clonePriorityType_ = NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE;
    cloneInfos.push_back(priorityInfo);
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
    }
    std::set<std::string> systemApps = {"bundleName"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationClonePriority::GetInstance()->OnRestoreStart("bundleName", 0, userId, 1000);
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    EXPECT_EQ(NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatus), ERR_OK);
    EXPECT_EQ(enableStatus, NotificationConstant::PriorityEnableStatus::DISABLE);
}

/**
 * @tc.name: OnRestore_00001
 * @tc.desc: Test clone OnRestore with systemApp priorityInfo success.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestore_00001, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bundleOption, 2);
    std::vector<NotificationClonePriorityInfo> cloneInfos;
    NotificationClonePriorityInfo priorityInfo;
    priorityInfo.bundleName_ = "bundleName";
    priorityInfo.appIndex_ = 0;
    priorityInfo.enableStatus_ = 0;
    priorityInfo.clonePriorityType_ = NotificationClonePriorityInfo::CLONE_PRIORITY_TYPE::PRIORITY_ENABLE_FOR_BUNDLE;
    cloneInfos.push_back(priorityInfo);
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    for (auto &cloneInfo : cloneInfos) {
        nlohmann::json jsonNode;
        cloneInfo.ToJson(jsonNode);
        jsonObject.emplace_back(jsonNode);
    }
    std::set<std::string> systemApps = {"bundleName"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
    EXPECT_EQ(NotificationPreferences::GetInstance()->IsPriorityEnabledByBundle(bundleOption, enableStatus), ERR_OK);
    EXPECT_EQ(enableStatus, NotificationConstant::PriorityEnableStatus::DISABLE);
}

/**
 * @tc.name: OnRestore_00002
 * @tc.desc: Test clone OnRestore when old device not support priority.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestore_00002, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bundleOption, 2);
    std::string keyword = "keyword1\nkeyword2";
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, keyword);
    NotificationClonePriority::GetInstance()->OnRestoreEnd(100);
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationClonePriority::GetInstance()->OnRestoreStart("bundleName", 0, userId, 1000);
    EXPECT_NE(NotificationClonePriority::GetInstance()->coverdPriorityInfo_.size(), 0);
    nlohmann::json jsonObject;
    std::set<std::string> systemApps = {"bundleName"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->coverdPriorityInfo_.size(), 0);
}

/**
 * @tc.name: OnRestore_00003
 * @tc.desc: Test clone OnRestore when old device jsonObject invalid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestore_00003, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption("bundleName", 1000);
    AdvancedNotificationService::GetInstance()->SetPriorityEnabledByBundleInner(bundleOption, 2);
    std::string keyword = "keyword1\nkeyword2";
    AdvancedNotificationService::GetInstance()->SetBundlePriorityConfig(bundleOption, keyword);
    NotificationClonePriority::GetInstance()->OnRestoreEnd(100);
    int32_t userId = NotificationCloneUtil::GetActiveUserId();
    NotificationClonePriority::GetInstance()->OnRestoreStart("bundleName", 0, userId, 1000);
    EXPECT_NE(NotificationClonePriority::GetInstance()->coverdPriorityInfo_.size(), 0);
    nlohmann::json jsonObject;
    jsonObject = nlohmann::json::array();
    NotificationCloneBundleInfo cloneBundle;
    nlohmann::json jsonNode;
    cloneBundle.ToJson(jsonNode);
    jsonObject.emplace_back(jsonNode);
    std::set<std::string> systemApps = {"bundleName"};
    NotificationClonePriority::GetInstance()->OnRestore(jsonObject, systemApps);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->coverdPriorityInfo_.size(), 0);
}

/**
 * @tc.name: OnRestoreEnd_Test_001
 * @tc.desc: Test that clear priority info.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationClonePriorityTest, OnRestoreEnd_Test_001, Function | SmallTest | Level1)
{
    NotificationClonePriority::GetInstance()->priorityInfo_.clear();
    NotificationClonePriority::GetInstance()->OnRestoreEnd(100);

    NotificationClonePriorityInfo priorityInfo;
    NotificationClonePriority::GetInstance()->priorityInfo_.push_back(priorityInfo);
    NotificationClonePriority::GetInstance()->OnRestoreEnd(100);
    EXPECT_EQ(NotificationClonePriority::GetInstance()->priorityInfo_.empty(), true);
}
}
}
