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
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsLiveViewEnabled_00001
 * @tc.desc: Test IsLiveViewEnabled with empty bundleName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsLiveViewEnabled_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    bool result = NotificationConfigParse::GetInstance()->IsLiveViewEnabled(bundleName);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsReminderEnabled_00001
 * @tc.desc: Test IsReminderEnabled with empty bundleName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsReminderEnabled_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    bool result = NotificationConfigParse::GetInstance()->IsReminderEnabled(bundleName);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: IsDistributedReplyEnabled_00001
 * @tc.desc: Test IsDistributedReplyEnabled with empty bundleName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsDistributedReplyEnabled_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    bool result = NotificationConfigParse::GetInstance()->IsDistributedReplyEnabled(bundleName);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetSmartReminderEnableList_00001
 * @tc.desc: Test GetSmartReminderEnableList fail
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetSmartReminderEnableList_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> deviceTypes;
    bool result = NotificationConfigParse::GetInstance()->GetSmartReminderEnableList(deviceTypes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetMirrorNotificationEnabledStatus_00001
 * @tc.desc: Test GetMirrorNotificationEnabledStatus fail
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetMirrorNotificationEnabledStatus_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> deviceTypes;
    bool result = NotificationConfigParse::GetInstance()->GetMirrorNotificationEnabledStatus(deviceTypes);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetFilterUidAndBundleName_00001
 * @tc.desc: Test GetFilterUidAndBundleName with empty key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetFilterUidAndBundleName_00001, Function | SmallTest | Level1)
{
    std::string key = "";
    bool result = NotificationConfigParse::GetInstance()->GetFilterUidAndBundleName(key);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetCloneExpiredTime_00001
 * @tc.desc: Test GetCloneExpiredTime fail
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetCloneExpiredTime_00001, Function | SmallTest | Level1)
{
    int32_t days = 0;
    bool result = NotificationConfigParse::GetInstance()->GetCloneExpiredTime(days);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetDataCloneBundleName_00001
 * @tc.desc: Test GetDataCloneBundleName successfully
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetDataCloneBundleName_00001, Function | SmallTest | Level1)
{
    std::string bundleName;
    bool result = NotificationConfigParse::GetInstance()->GetDataCloneBundleName(bundleName);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetCollaborativeDeleteTypeByDevice_00001
 * @tc.desc: Test GetCollaborativeDeleteTypeByDevice successfully
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetCollaborativeDeleteTypeByDevice_00001, Function | SmallTest | Level1)
{
    std::map<std::string, std::map<std::string, std::unordered_set<std::string>>> deleteTypes;
    bool result = NotificationConfigParse::GetInstance()->GetCollaborativeDeleteTypeByDevice(deleteTypes);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsNotificationExtensionLifecycleDestroyTimeConfigured_00001
 * @tc.desc: Test IsNotificationExtensionLifecycleDestroyTimeConfigured successfully
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsNotificationExtensionLifecycleDestroyTimeConfigured_00001,
    Function | SmallTest | Level1)
{
    uint32_t destroyTime = 0;
    bool result = NotificationConfigParse::GetInstance()->IsNotificationExtensionLifecycleDestroyTimeConfigured(
        destroyTime);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: IsNotificationExtensionSubscribeSupportHfp_00001
 * @tc.desc: Test IsNotificationExtensionSubscribeSupportHfp successfully
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, IsNotificationExtensionSubscribeSupportHfp_00001, Function | SmallTest | Level1)
{
    bool supportHfp = false;
    bool result = NotificationConfigParse::GetInstance()->IsNotificationExtensionSubscribeSupportHfp(supportHfp);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetAppPrivileges_00001
 * @tc.desc: Test GetAppPrivileges with empty bundleName
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetAppPrivileges_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    auto result = NotificationConfigParse::GetInstance()->GetAppPrivileges(bundleName);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: GetConfigJson_00001
 * @tc.desc: Test GetConfigJson with empty key
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationConfigParseTest, GetConfigJson_00001, Function | SmallTest | Level1)
{
    std::string key = "";
    nlohmann::json configJson;
    bool result = NotificationConfigParse::GetInstance()->GetConfigJson(key, configJson);
    EXPECT_FALSE(result);
}
}   //namespace Notification
}   //namespace OHOS
