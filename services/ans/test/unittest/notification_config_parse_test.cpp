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

namespace {
void InjectConfig(const nlohmann::json &json)
{
    std::vector<nlohmann::json> docs {json};
    NotificationConfigParse::GetInstance()->ParseConfigs(docs);
}

void RestoreConfig()
{
    auto inst = NotificationConfigParse::GetInstance();
    std::vector<nlohmann::json> docs;
    inst->LoadConfigJsons(docs);
    inst->ParseConfigs(docs);
}
} // namespace

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
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {
            {"dfxNormalEvent", {1, "valid", true, "end"}},
            {"dfxKeyBundle", {42, "bundle1", false}}
        }}
    };
    InjectConfig(badJson);
    EXPECT_TRUE(inst->reporteTrustSet_.count("valid") > 0);
    EXPECT_TRUE(inst->reporteTrustSet_.count("end") > 0);
    EXPECT_TRUE(inst->keyTrustBundles_.count("bundle1") > 0);
    inst->GetReportTrustListConfig();
    RestoreConfig();
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
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"startAbilityTimeout", "not_a_number"}}}
    };
    InjectConfig(badJson);
    uint32_t result = inst->GetStartAbilityTimeout();
    EXPECT_EQ(result, 0u);
    RestoreConfig();
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
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"notificationExtension",
            {{"lifecycleDestoryTime", "not_a_number"}}}}}
    };
    InjectConfig(badJson);
    uint32_t outDestroyTime = 999;
    bool result = inst->IsNotificationExtensionLifecycleDestroyTimeConfigured(outDestroyTime);
    EXPECT_FALSE(result);
    RestoreConfig();
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
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", {{"notificationExtension",
            {{"enabledBundlesWriteList", {1, "valid", true, "end"}}}}}}
    };
    InjectConfig(badJson);
    std::vector<std::string> bundles;
    bool result = inst->GetNotificationExtensionEnabledBundlesWriteList(bundles);
    EXPECT_TRUE(result);
    EXPECT_EQ(bundles.size(), 2u);
    RestoreConfig();
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
    nlohmann::json badJson = nlohmann::json{
        {"notificationService", "not_an_object"}
    };
    InjectConfig(badJson);
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
    RestoreConfig();
}

/**
 * @tc.name: GetAppPrivileges_00001
 * @tc.desc: Test GetAppPrivileges when appPrivileges value is not an object, should return nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetAppPrivileges_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    nlohmann::json badJson = nlohmann::json{
        {"appPrivileges", "not_an_object"}
    };
    InjectConfig(badJson);
    EXPECT_EQ(inst->GetAppPrivileges("com.test.bundle"), nullptr);

    nlohmann::json numberJson = nlohmann::json{
        {"appPrivileges", 123}
    };
    InjectConfig(numberJson);
    EXPECT_EQ(inst->GetAppPrivileges("com.test.bundle"), nullptr);

    nlohmann::json arrayJson = nlohmann::json{
        {"appPrivileges", nlohmann::json::array({"bundle1", "bundle2"})}
    };
    InjectConfig(arrayJson);
    EXPECT_EQ(inst->GetAppPrivileges("bundle1"), nullptr);

    nlohmann::json nullJson = nlohmann::json{
        {"appPrivileges", nullptr}
    };
    InjectConfig(nullJson);
    EXPECT_EQ(inst->GetAppPrivileges("com.test.bundle"), nullptr);

    nlohmann::json emptyJson = nlohmann::json{
        {"appPrivileges", nlohmann::json::object()}
    };
    InjectConfig(emptyJson);
    EXPECT_EQ(inst->GetAppPrivileges("com.test.bundle"), nullptr);

    RestoreConfig();
}

/**
 * @tc.name: GetAppPrivileges_00002
 * @tc.desc: Test GetAppPrivileges with valid appPrivileges object.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetAppPrivileges_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    nlohmann::json goodJson = nlohmann::json{
        {"appPrivileges", {
            {"com.test.bundle", "11111"},
            {"com.other.bundle", "00000"}
        }}
    };
    InjectConfig(goodJson);
    auto privileges = inst->GetAppPrivileges("com.test.bundle");
    EXPECT_NE(privileges, nullptr);
    EXPECT_TRUE(privileges->IsLiveViewEnabled());
    EXPECT_TRUE(privileges->IsBannerEnabled());
    EXPECT_TRUE(privileges->IsReminderEnabled());
    EXPECT_TRUE(privileges->IsDistributedReplyEnabled());
    // bundle not in privileges
    EXPECT_EQ(inst->GetAppPrivileges("com.not.exist.bundle"), nullptr);
    RestoreConfig();
}

/**
 * @tc.name: ParseSlotTypeReminder_Branch_00001
 * @tc.desc: Test slotTypeReminder parsing keeps valid entries and skips invalid ones.
 */
HWTEST_F(NotificationConfigParseTest, ParseSlotTypeReminder_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    nlohmann::json doc = nlohmann::json{
        {"notificationService", {{"slotTypeReminder", {
            {{"name", "Social_communication"}, {"reminderFlags", "111111"}},
            {{"name", "INVALID_SLOT"}, {"reminderFlags", "111111"}},
            {{"name", "Live_view"}, {"reminderFlags", "bad"}},
            {{"name", 42}, {"reminderFlags", "111111"}},
            {{"name", "Other"}}
        }}}}
    };
    InjectConfig(doc);
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> reminders;
    EXPECT_TRUE(inst->GetCurrentSlotReminder(reminders));
    ASSERT_EQ(reminders.size(), 1u);
    EXPECT_EQ(reminders.count(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 1u);
    EXPECT_EQ(inst->GetConfigSlotReminderModeByType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 0b111111);
    // Slot absent from the config falls back to the built-in default reminder mode.
    EXPECT_EQ(inst->GetConfigSlotReminderModeByType(NotificationConstant::SlotType::CONTENT_INFORMATION), 0u);
    RestoreConfig();
}

/**
 * @tc.name: ParseSlotTypeReminder_Branch_00002
 * @tc.desc: Test GetCurrentSlotReminder returns false for invalid slotTypeReminder values.
 */
HWTEST_F(NotificationConfigParseTest, ParseSlotTypeReminder_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> reminders;
    InjectConfig(nlohmann::json{{"notificationService", {{"slotTypeReminder", "not_array"}}}});
    EXPECT_FALSE(inst->GetCurrentSlotReminder(reminders));
    InjectConfig(nlohmann::json{{"notificationService", {{"slotTypeReminder", nlohmann::json::array()}}}});
    EXPECT_FALSE(inst->GetCurrentSlotReminder(reminders));
    InjectConfig(nlohmann::json{{"otherKey", 1}});
    EXPECT_FALSE(inst->GetCurrentSlotReminder(reminders));
    RestoreConfig();
}

/**
 * @tc.name: ParseFlowCtrlConfig_Branch_00001
 * @tc.desc: Test flow control thresholds are applied when all keys are integers.
 */
HWTEST_F(NotificationConfigParseTest, ParseFlowCtrlConfig_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"MaxCreateNumPerSecond", 11},
            {"MaxUpdateNumPerSecond", 22},
            {"MaxCreateNumPerSecondPerApp", 33},
            {"MaxUpdateNumPerSecondPerApp", 44}
        }}
    });
    FlowControlThreshold threshold;
    inst->GetFlowCtrlConfigFromCCM(threshold);
    EXPECT_EQ(threshold.maxCreateNumPerSecond, 11u);
    EXPECT_EQ(threshold.maxUpdateNumPerSecond, 22u);
    EXPECT_EQ(threshold.maxCreateNumPerSecondPerApp, 33u);
    EXPECT_EQ(threshold.maxUpdateNumPerSecondPerApp, 44u);
    RestoreConfig();
}

/**
 * @tc.name: ParseFlowCtrlConfig_Branch_00002
 * @tc.desc: Test flow control thresholds stay untouched when keys are not integers.
 */
HWTEST_F(NotificationConfigParseTest, ParseFlowCtrlConfig_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"MaxCreateNumPerSecond", "bad"},
            {"MaxUpdateNumPerSecond", nlohmann::json::array()},
            {"MaxCreateNumPerSecondPerApp", nullptr},
            {"MaxUpdateNumPerSecondPerApp", true}
        }}
    });
    FlowControlThreshold threshold;
    const uint32_t createPerSecond = threshold.maxCreateNumPerSecond;
    inst->GetFlowCtrlConfigFromCCM(threshold);
    EXPECT_EQ(threshold.maxCreateNumPerSecond, createPerSecond);
    RestoreConfig();
}

/**
 * @tc.name: ParseSmartReminderAndMirror_Branch_00001
 * @tc.desc: Test smart reminder and mirror device type lists skip non-string elements.
 */
HWTEST_F(NotificationConfigParseTest, ParseSmartReminderAndMirror_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"smartReminderEnableList", {"phone", 42, "tablet"}},
            {"mirrorNotificationEnabledStatus", {"phone", 7}}
        }}
    });
    std::vector<std::string> smartReminders;
    EXPECT_TRUE(inst->GetSmartReminderEnableList(smartReminders));
    EXPECT_EQ(smartReminders.size(), 2u);
    std::vector<std::string> mirrors;
    EXPECT_TRUE(inst->GetMirrorNotificationEnabledStatus(mirrors));
    EXPECT_EQ(mirrors.size(), 1u);
    RestoreConfig();
}

/**
 * @tc.name: ParseSmartReminderAndMirror_Branch_00002
 * @tc.desc: Test invalid smart reminder and mirror lists return false.
 */
HWTEST_F(NotificationConfigParseTest, ParseSmartReminderAndMirror_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"smartReminderEnableList", "bad"},
            {"mirrorNotificationEnabledStatus", nlohmann::json::array()}
        }}
    });
    std::vector<std::string> deviceTypes;
    EXPECT_FALSE(inst->GetSmartReminderEnableList(deviceTypes));
    EXPECT_FALSE(inst->GetMirrorNotificationEnabledStatus(deviceTypes));
    RestoreConfig();
}

/**
 * @tc.name: ParseAppAndDeviceRelationMap_Branch_00001
 * @tc.desc: Test app and device relation map keeps string values only.
 */
HWTEST_F(NotificationConfigParseTest, ParseAppAndDeviceRelationMap_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {{"appAndDeviceRelationMap", {{"app", "phone"}, {"bad", 3}}}}}
    });
    std::map<std::string, std::string> relationMap;
    EXPECT_TRUE(inst->GetAppAndDeviceRelationMap(relationMap));
    ASSERT_EQ(relationMap.size(), 1u);
    EXPECT_EQ(relationMap["app"], "phone");
    RestoreConfig();
}

/**
 * @tc.name: ParseCollaborativeDelete_Branch_00001
 * @tc.desc: Test collaborative delete types and per-device filter parsing.
 */
HWTEST_F(NotificationConfigParseTest, ParseCollaborativeDelete_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"collaborativeDeleteTypes", {"LIVE_VIEW", 42, "SOCIAL_COMMUNICATION"}},
            {"collaborativeDeleteTypesDevices", {
                {{"localDeviceType", "phone"}, {"peerDeleteFilterDevice", {
                    {{"peerDeviceType", "tablet"}, {"deleteSlotTypes", {"LIVE_VIEW", 7}}},
                    {{"peerDeviceType", 5}},
                    {{}}
                }}},
                {{"peerDeleteFilterDevice", nlohmann::json::array()}},
                {{"localDeviceType", "watch"}}
            }}
        }}
    });
    auto types = inst->GetCollaborativeDeleteType();
    EXPECT_EQ(types.size(), 2u);
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> deviceMap;
    EXPECT_TRUE(inst->GetCollaborativeDeleteTypeByDevice(deviceMap));
    ASSERT_EQ(deviceMap.size(), 1u);
    ASSERT_EQ(deviceMap["phone"].size(), 1u);
    EXPECT_EQ(deviceMap["phone"]["tablet"].size(), 1u);
    RestoreConfig();
}

/**
 * @tc.name: ParseCollaborativeDelete_Branch_00002
 * @tc.desc: Test invalid collaborative delete config returns empty results.
 */
HWTEST_F(NotificationConfigParseTest, ParseCollaborativeDelete_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"collaborativeDeleteTypes", {{"not", 1}}},
            {"collaborativeDeleteTypesDevices", "bad"}
        }}
    });
    EXPECT_TRUE(inst->GetCollaborativeDeleteType().empty());
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> deviceMap;
    EXPECT_FALSE(inst->GetCollaborativeDeleteTypeByDevice(deviceMap));
    RestoreConfig();
}

/**
 * @tc.name: ParseCollaborationFilter_Branch_00001
 * @tc.desc: Test collaboration filter parses uid and bundle name arrays.
 */
HWTEST_F(NotificationConfigParseTest, ParseCollaborationFilter_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {{"collaborationFilter", {
            {"uid", {1001, "not_uid"}},
            {"bundleName", {"com.filter", 9}}
        }}}}
    });
    EXPECT_TRUE(inst->IsInCollaborationFilter("unknown.bundle", 1001));
    EXPECT_TRUE(inst->IsInCollaborationFilter("com.filter", 2002));
    EXPECT_FALSE(inst->IsInCollaborationFilter("unknown.bundle", 2002));
    RestoreConfig();
}

/**
 * @tc.name: ParseCollaborationFilter_Branch_00002
 * @tc.desc: Test invalid collaboration filter leaves the filter lists empty.
 */
HWTEST_F(NotificationConfigParseTest, ParseCollaborationFilter_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{{"notificationService", {{"collaborationFilter", 1}}}});
    EXPECT_FALSE(inst->IsInCollaborationFilter("com.filter", 1001));
    inst->GetCollaborationFilter();
    RestoreConfig();
}

/**
 * @tc.name: ParseSimpleScalars_Branch_00001
 * @tc.desc: Test startAbilityTimeout, cloneExpiredTime and datacloneBundleName parsing.
 */
HWTEST_F(NotificationConfigParseTest, ParseSimpleScalars_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"startAbilityTimeout", 3000},
            {"cloneExpiredTime", 7},
            {"datacloneBundleName", "com.clone"}
        }}
    });
    EXPECT_EQ(inst->GetStartAbilityTimeout(), 3000u);
    int32_t days = 0;
    EXPECT_TRUE(inst->GetCloneExpiredTime(days));
    EXPECT_EQ(days, 7);
    std::string bundleName;
    EXPECT_TRUE(inst->GetDataCloneBundleName(bundleName));
    EXPECT_EQ(bundleName, "com.clone");
    RestoreConfig();
}

/**
 * @tc.name: ParseSimpleScalars_Branch_00002
 * @tc.desc: Test invalid scalar values leave the defaults.
 */
HWTEST_F(NotificationConfigParseTest, ParseSimpleScalars_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"startAbilityTimeout", "bad"},
            {"cloneExpiredTime", "bad"},
            {"datacloneBundleName", ""}
        }}
    });
    EXPECT_EQ(inst->GetStartAbilityTimeout(), 0u);
    int32_t days = 0;
    EXPECT_FALSE(inst->GetCloneExpiredTime(days));
    std::string bundleName;
    EXPECT_FALSE(inst->GetDataCloneBundleName(bundleName));
    RestoreConfig();
}

/**
 * @tc.name: ParseAppLiveViewCcm_Branch_00001
 * @tc.desc: Test CheckAppLiveViewCcm reflects the presence of appLiveViewPermissions.
 */
HWTEST_F(NotificationConfigParseTest, ParseAppLiveViewCcm_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{{"appLiveViewPermissions", {{"com.live", "1"}}}});
    EXPECT_TRUE(inst->CheckAppLiveViewCcm());
    InjectConfig(nlohmann::json{{"otherKey", 1}});
    EXPECT_FALSE(inst->CheckAppLiveViewCcm());
    RestoreConfig();
}

/**
 * @tc.name: ParseReportTrustList_Branch_00001
 * @tc.desc: Test dfx trust lists keep string entries only.
 */
HWTEST_F(NotificationConfigParseTest, ParseReportTrustList_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {
            {"dfxNormalEvent", {"event1", 2, "event2"}},
            {"dfxKeyBundle", {"bundle1", 3}}
        }}
    });
    EXPECT_TRUE(inst->IsReportTrustList("event1"));
    EXPECT_TRUE(inst->IsReportTrustBundles("bundle1"));
    EXPECT_FALSE(inst->IsReportTrustList("missing"));
    RestoreConfig();
}

/**
 * @tc.name: ParseNotificationExtension_Branch_00001
 * @tc.desc: Test notificationExtension destroy time and write list parsing.
 */
HWTEST_F(NotificationConfigParseTest, ParseNotificationExtension_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {{"notificationExtension", {
            {"lifecycleDestoryTime", 5000},
            {"enabledBundlesWriteList", {"bundle1", 9, "bundle2"}}
        }}}}
    });
    uint32_t destroyTime = 0;
    EXPECT_TRUE(inst->IsNotificationExtensionLifecycleDestroyTimeConfigured(destroyTime));
    EXPECT_EQ(destroyTime, 5000u);
    std::vector<std::string> bundles;
    EXPECT_TRUE(inst->GetNotificationExtensionEnabledBundlesWriteList(bundles));
    EXPECT_EQ(bundles.size(), 2u);
    RestoreConfig();
}

/**
 * @tc.name: ParseNotificationExtension_Branch_00002
 * @tc.desc: Test invalid notificationExtension config returns false.
 */
HWTEST_F(NotificationConfigParseTest, ParseNotificationExtension_Branch_00002, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    InjectConfig(nlohmann::json{
        {"notificationService", {{"notificationExtension", {{"lifecycleDestoryTime", "bad"}}}}}
    });
    uint32_t destroyTime = 0;
    EXPECT_FALSE(inst->IsNotificationExtensionLifecycleDestroyTimeConfigured(destroyTime));
    std::vector<std::string> bundles;
    EXPECT_FALSE(inst->GetNotificationExtensionEnabledBundlesWriteList(bundles));
    RestoreConfig();
}

/**
 * @tc.name: GetConfigJson_Branch_00001
 * @tc.desc: Test GetConfigJson and GetFilterUidAndBundleName when no config file is available.
 */
HWTEST_F(NotificationConfigParseTest, GetConfigJson_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    nlohmann::json root;
    EXPECT_FALSE(inst->GetConfigJson("/appPrivileges", root));
    EXPECT_FALSE(inst->GetFilterUidAndBundleName(NotificationConfigParse::COLLABORATION_FILTER_KEY_UID));
    std::vector<nlohmann::json> docs;
    EXPECT_FALSE(inst->LoadConfigJsons(docs));
}

/**
 * @tc.name: ParseInvalidVariants_Branch_00001
 * @tc.desc: Test the remaining invalid config shapes leave the caches empty.
 */
HWTEST_F(NotificationConfigParseTest, ParseInvalidVariants_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    // notificationService is an empty object.
    InjectConfig(nlohmann::json{{"notificationService", nlohmann::json::object()}});
    FlowControlThreshold threshold;
    inst->GetFlowCtrlConfigFromCCM(threshold);
    EXPECT_EQ(inst->GetStartAbilityTimeout(), 0u);

    // collaborationFilter key is not an array.
    InjectConfig(nlohmann::json{{"notificationService", {{"collaborationFilter", {{"uid", "bad"}}}}}});
    EXPECT_FALSE(inst->IsInCollaborationFilter("bundle", 1));

    // enabledBundlesWriteList is not an array.
    InjectConfig(nlohmann::json{{"notificationService",
        {{"notificationExtension", {{"enabledBundlesWriteList", 1}}}}}});
    std::vector<std::string> bundles;
    EXPECT_FALSE(inst->GetNotificationExtensionEnabledBundlesWriteList(bundles));

    // dfx trust lists are invalid.
    InjectConfig(nlohmann::json{{"notificationService", {{"dfxNormalEvent", "bad"}}}});
    EXPECT_FALSE(inst->IsReportTrustList("event1"));

    // datacloneBundleName is not a string.
    InjectConfig(nlohmann::json{{"notificationService", {{"datacloneBundleName", 5}}}});
    std::string bundleName;
    EXPECT_FALSE(inst->GetDataCloneBundleName(bundleName));

    // Config without notificationService at all.
    InjectConfig(nlohmann::json{{"otherKey", 1}});
    int32_t days = 0;
    EXPECT_FALSE(inst->GetCloneExpiredTime(days));
    RestoreConfig();
}

/**
 * @tc.name: ParseNullValues_Branch_00001
 * @tc.desc: Test null config values and missing sibling keys do not crash and leave caches empty.
 */
HWTEST_F(NotificationConfigParseTest, ParseNullValues_Branch_00001, Function | SmallTest | Level1)
{
    auto inst = NotificationConfigParse::GetInstance();
    // appPrivileges contains a non-string privilege value.
    InjectConfig(nlohmann::json{{"appPrivileges", {{"bad.bundle", 1}}}});
    EXPECT_EQ(inst->GetAppPrivileges("bad.bundle"), nullptr);

    // Null slotTypeReminder / flow control / device relation values.
    InjectConfig(nlohmann::json{{"notificationService", {
        {"slotTypeReminder", nullptr},
        {"appAndDeviceRelationMap", nullptr},
        {"collaborativeDeleteTypesDevices", nullptr}
    }}});
    std::map<NotificationConstant::SlotType, std::shared_ptr<NotificationFlags>> reminders;
    EXPECT_FALSE(inst->GetCurrentSlotReminder(reminders));
    std::map<std::string, std::string> relationMap;
    EXPECT_FALSE(inst->GetAppAndDeviceRelationMap(relationMap));
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> deviceMap;
    EXPECT_FALSE(inst->GetCollaborativeDeleteTypeByDevice(deviceMap));

    // Null notificationService object.
    InjectConfig(nlohmann::json{{"notificationService", nullptr}});
    FlowControlThreshold threshold;
    inst->GetFlowCtrlConfigFromCCM(threshold);
    EXPECT_EQ(inst->GetStartAbilityTimeout(), 0u);

    // Empty collaborationFilter object.
    InjectConfig(nlohmann::json{{"notificationService", {{"collaborationFilter", nlohmann::json::object()}}}});
    EXPECT_FALSE(inst->IsInCollaborationFilter("bundle", 1));

    // dfxKeyBundle missing: only dfxNormalEvent is configured.
    InjectConfig(nlohmann::json{{"notificationService", {{"dfxNormalEvent", {"event1"}}}}});
    EXPECT_TRUE(inst->IsReportTrustList("event1"));
    EXPECT_FALSE(inst->IsReportTrustBundles("bundle1"));
    RestoreConfig();
}
}   //namespace Notification
}   //namespace OHOS
