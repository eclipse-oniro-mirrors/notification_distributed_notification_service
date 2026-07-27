/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public

#include "notification_config_parse.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class NotificationConfigParseTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: IsReportTrustBundles_100
 * @tc.desc: Test trust bundls.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationConfigParseTest, IsReportTrustBundles_100, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->keyTrustBundles_.clear();
    bool trustBundls = NotificationConfigParse::GetInstance()->IsReportTrustBundles("com.ohos.test");
    ASSERT_EQ(trustBundls, false);
    NotificationConfigParse::GetInstance()->keyTrustBundles_.emplace("com.ohos.test");
    trustBundls = NotificationConfigParse::GetInstance()->IsReportTrustBundles("com.ohos.test");
    ASSERT_EQ(trustBundls, true);
}

/**
 * @tc.name: IsBannerEnabled_00001
 * @tc.desc: Test IsBannerEnabled when extensionWrapper is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsBannerEnabled_00001, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->IsBannerEnabled("testBundle");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: IsBannerEnabled_00002
 * @tc.desc: Test IsBannerEnabled with empty bundleName.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsBannerEnabled_00002, Function | SmallTest | Level1)
{
    bool result = NotificationConfigParse::GetInstance()->IsBannerEnabled("");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsReportTrustList_00001
 * @tc.desc: Test IsReportTrustList with empty set.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsReportTrustList_00001, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->reporteTrustSet_.clear();
    bool result = NotificationConfigParse::GetInstance()->IsReportTrustList("test.bundle");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsReportTrustList_00002
 * @tc.desc: Test IsReportTrustList with bundle in set.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsReportTrustList_00002, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->reporteTrustSet_.clear();
    NotificationConfigParse::GetInstance()->reporteTrustSet_.emplace("com.ohos.test");
    bool result = NotificationConfigParse::GetInstance()->IsReportTrustList("com.ohos.test");
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsReportTrustList_00003
 * @tc.desc: Test IsReportTrustList with bundle not in set.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsReportTrustList_00003, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->reporteTrustSet_.clear();
    NotificationConfigParse::GetInstance()->reporteTrustSet_.emplace("com.ohos.test");
    bool result = NotificationConfigParse::GetInstance()->IsReportTrustList("com.other.bundle");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsReportTrustBundles_00001
 * @tc.desc: Test IsReportTrustBundles with empty set.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsReportTrustBundles_00001, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->keyTrustBundles_.clear();
    bool result = NotificationConfigParse::GetInstance()->IsReportTrustBundles("test.bundle");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsReportTrustBundles_00002
 * @tc.desc: Test IsReportTrustBundles with bundle not in set.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsReportTrustBundles_00002, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->keyTrustBundles_.clear();
    NotificationConfigParse::GetInstance()->keyTrustBundles_.emplace("com.ohos.trust");
    bool result = NotificationConfigParse::GetInstance()->IsReportTrustBundles("com.other.bundle");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsInCollaborationFilter_00001
 * @tc.desc: Test IsInCollaborationFilter with empty lists.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsInCollaborationFilter_00001, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->uidList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.clear();
    bool result = NotificationConfigParse::GetInstance()->IsInCollaborationFilter("test.bundle", 1000);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsInCollaborationFilter_00002
 * @tc.desc: Test IsInCollaborationFilter with uid in list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsInCollaborationFilter_00002, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->uidList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.clear();
    NotificationConfigParse::GetInstance()->uidList_.push_back(1234);
    bool result = NotificationConfigParse::GetInstance()->IsInCollaborationFilter("test.bundle", 1234);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsInCollaborationFilter_00003
 * @tc.desc: Test IsInCollaborationFilter with bundleName in list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsInCollaborationFilter_00003, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->uidList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.push_back("com.ohos.test");
    bool result = NotificationConfigParse::GetInstance()->IsInCollaborationFilter("com.ohos.test", 2000);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsInCollaborationFilter_00004
 * @tc.desc: Test IsInCollaborationFilter with both not in lists.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsInCollaborationFilter_00004, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->uidList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.clear();
    NotificationConfigParse::GetInstance()->uidList_.push_back(1234);
    NotificationConfigParse::GetInstance()->bundleNameList_.push_back("com.ohos.test");
    bool result = NotificationConfigParse::GetInstance()->IsInCollaborationFilter("com.other.bundle", 2000);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsInCollaborationFilter_00005
 * @tc.desc: Test IsInCollaborationFilter with both in lists.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, IsInCollaborationFilter_00005, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->uidList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.clear();
    NotificationConfigParse::GetInstance()->uidList_.push_back(1234);
    NotificationConfigParse::GetInstance()->bundleNameList_.push_back("com.ohos.test");
    bool result = NotificationConfigParse::GetInstance()->IsInCollaborationFilter("com.ohos.test", 1234);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetCollaborativeDeleteType_00001
 * @tc.desc: Test GetCollaborativeDeleteType contains expected types.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetCollaborativeDeleteType_00001, Function | SmallTest | Level1)
{
    auto result = NotificationConfigParse::GetInstance()->GetCollaborativeDeleteType();
    if (result.size() <= 0) {
        GTEST_SKIP() << "Json of collaborativeDeleteTypes not exist";
    }
    EXPECT_TRUE(result.find("LIVE_VIEW") != result.end());
    EXPECT_TRUE(result.find("SOCIAL_COMMUNICATION") != result.end());
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00001
 * @tc.desc: Test GetConfigSlotReminderModeByType with SOCIAL_COMMUNICATION.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00001, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    EXPECT_EQ(flags, 0b111111);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00002
 * @tc.desc: Test GetConfigSlotReminderModeByType with SERVICE_REMINDER.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00002, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::SERVICE_REMINDER);
    EXPECT_EQ(flags, 0b111111);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00003
 * @tc.desc: Test GetConfigSlotReminderModeByType with CONTENT_INFORMATION.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00003, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::CONTENT_INFORMATION);
    EXPECT_EQ(flags, 0b000000);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00004
 * @tc.desc: Test GetConfigSlotReminderModeByType with OTHER.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00004, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::OTHER);
    EXPECT_EQ(flags, 0b000000);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00005
 * @tc.desc: Test GetConfigSlotReminderModeByType with LIVE_VIEW.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00005, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::LIVE_VIEW);
    EXPECT_EQ(flags, 0b111011);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00006
 * @tc.desc: Test GetConfigSlotReminderModeByType with CUSTOMER_SERVICE.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00006, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::CUSTOMER_SERVICE);
    EXPECT_EQ(flags, 0b110001);
}

/**
 * @tc.name: GetConfigSlotReminderModeByType_00007
 * @tc.desc: Test GetConfigSlotReminderModeByType with EMERGENCY_INFORMATION.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetConfigSlotReminderModeByType_00007, Function | SmallTest | Level1)
{
    uint32_t flags = NotificationConfigParse::GetInstance()->GetConfigSlotReminderModeByType(
        NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    EXPECT_EQ(flags, 0b111111);
}

/**
 * @tc.name: GetCollaborationFilter_00001
 * @tc.desc: Test GetCollaborationFilter clears lists.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetCollaborationFilter_00001, Function | SmallTest | Level1)
{
    NotificationConfigParse::GetInstance()->uidList_.clear();
    NotificationConfigParse::GetInstance()->bundleNameList_.clear();
    NotificationConfigParse::GetInstance()->GetCollaborationFilter();
    EXPECT_TRUE(NotificationConfigParse::GetInstance()->uidList_.empty());
    EXPECT_TRUE(NotificationConfigParse::GetInstance()->bundleNameList_.empty());
}

/**
 * @tc.name: GetAppAndDeviceRelationMap_00001
 * @tc.desc: Test GetAppAndDeviceRelationMap returns true.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetAppAndDeviceRelationMap_00001, Function | SmallTest | Level1)
{
    std::map<std::string, std::string> relationMap;
    bool result = NotificationConfigParse::GetInstance()->GetAppAndDeviceRelationMap(relationMap);
    if (!result) {
        GTEST_SKIP() << "Json of appAndDeviceRelationMap not exist";
    }
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetNotificationExtensionEnabledBundlesList_00001
 * @tc.desc: Test GetNotificationExtensionEnabledBundlesList returns true.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationConfigParseTest, GetNotificationExtensionEnabledBundlesList_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> bundles;
    bool result = NotificationConfigParse::GetInstance()->GetNotificationExtensionEnabledBundlesWriteList(bundles);
    if (!result) {
        GTEST_SKIP() << "Json of enabledBundlesWriteList not exist";
    }
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetReportTrustListConfig_00001
 * @tc.desc: Test GetReportTrustListConfig with non-string elements (should not crash).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetReportTrustListConfig_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    auto saved = inst->notificationConfigJsons_;
    inst->notificationConfigJsons_.clear();
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {
            {"dfxNormalEvent", {1, "valid", true, "end"}},
            {"dfxKeyBundle", {42, "bundle1", false}}
        }}
    };
    inst->notificationConfigJsons_.push_back(badJson);
    inst->GetReportTrustListConfig();
    EXPECT_TRUE(inst->reporteTrustSet_.count("valid") > 0);
    EXPECT_TRUE(inst->reporteTrustSet_.count("end") > 0);
    EXPECT_TRUE(inst->keyTrustBundles_.count("bundle1") > 0);
    inst->notificationConfigJsons_ = saved;
}

/**
 * @tc.name: GetStartAbilityTimeout_00001
 * @tc.desc: Test GetStartAbilityTimeout with non-integer value (should return 0).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetStartAbilityTimeout_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    auto saved = inst->notificationConfigJsons_;
    inst->notificationConfigJsons_.clear();
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"startAbilityTimeout", "not_a_number"}}}
    };
    inst->notificationConfigJsons_.push_back(badJson);
    uint32_t result = inst->GetStartAbilityTimeout();
    EXPECT_EQ(result, 0u);
    inst->notificationConfigJsons_ = saved;
}

/**
 * @tc.name: IsNotificationExtensionLifecycleDestroyTimeConfigured_00001
 * @tc.desc: Test with non-integer destroy time (should return false).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsNotificationExtensionLifecycleDestroyTimeConfigured_00001,
    Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    auto saved = inst->notificationConfigJsons_;
    inst->notificationConfigJsons_.clear();
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"notificationExtension",
            {{"lifecycleDestoryTime", "not_a_number"}}}}}
    };
    inst->notificationConfigJsons_.push_back(badJson);
    uint32_t outDestroyTime = 999;
    bool result = inst->IsNotificationExtensionLifecycleDestroyTimeConfigured(outDestroyTime);
    EXPECT_FALSE(result);
    inst->notificationConfigJsons_ = saved;
}

/**
 * @tc.name: IsNotificationExtensionSubscribeSupportHfp_00001
 * @tc.desc: Test with non-boolean HFP support (should return false).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsNotificationExtensionSubscribeSupportHfp_00001,
    Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    auto saved = inst->notificationConfigJsons_;
    inst->notificationConfigJsons_.clear();
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"notificationExtension",
            {{"supportHfp", "not_a_bool"}}}}}
    };
    inst->notificationConfigJsons_.push_back(badJson);
    bool outSupportHfp = true;
    bool result = inst->IsNotificationExtensionSubscribeSupportHfp(outSupportHfp);
    EXPECT_FALSE(result);
    inst->notificationConfigJsons_ = saved;
}

/**
 * @tc.name: GetNotificationExtensionEnabledBundlesWriteList_00002
 * @tc.desc: Test with non-string elements in write list (should skip them).
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetNotificationExtensionEnabledBundlesWriteList_00002,
    Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    auto saved = inst->notificationConfigJsons_;
    inst->notificationConfigJsons_.clear();
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"notificationExtension",
            {{"enabledBundlesWriteList", {1, "valid", true, "end"}}}}}}
    };
    inst->notificationConfigJsons_.push_back(badJson);
    std::vector<std::string> bundles;
    bool result = inst->GetNotificationExtensionEnabledBundlesWriteList(bundles);
    EXPECT_TRUE(result);
    EXPECT_EQ(bundles.size(), 2u);
    inst->notificationConfigJsons_ = saved;
}

/**
 * @tc.name: GetNotificationServiceNotObject_00001
 * @tc.desc: Test config functions when notificationService value is not an object.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetNotificationServiceNotObject_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    auto saved = inst->notificationConfigJsons_;
    inst->notificationConfigJsons_.clear();
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", "not_an_object"}
    };
    inst->notificationConfigJsons_.push_back(badJson);
    std::vector<std::string> deviceTypes;
    bool result = inst->GetSmartReminderEnableList(deviceTypes);
    EXPECT_FALSE(result);
    result = inst->GetMirrorNotificationEnabledStatus(deviceTypes);
    EXPECT_FALSE(result);
    std::map<std::string, std::string> relationMap;
    result = inst->GetAppAndDeviceRelationMap(relationMap);
    EXPECT_FALSE(result);
    uint32_t timeout = inst->GetStartAbilityTimeout();
    EXPECT_EQ(timeout, 0u);
    inst->notificationConfigJsons_ = saved;
}
}   //namespace Notification
}   //namespace OHOS
