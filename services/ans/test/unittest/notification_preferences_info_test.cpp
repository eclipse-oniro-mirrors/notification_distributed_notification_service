/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ans_inner_errors.h"
#include "ans_ut_constant.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#define private public
#define protected public
#include "notification_preferences_info.h"
#include "advanced_notification_service.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GetSlotFlagsKeyFromType_00001
 * @tc.desc: Test GetSlotFlagsKeyFromType
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationPreferencesInfoTest, GetSlotFlagsKeyFromType_00001, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    const char *res= bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    std::string resStr(res);
    ASSERT_EQ(resStr, "Social_communication");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::SERVICE_REMINDER);
    resStr = res;
    ASSERT_EQ(resStr, "Service_reminder");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    resStr = res;
    ASSERT_EQ(resStr, "Content_information");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::OTHER);
    resStr = res;
    ASSERT_EQ(resStr, "Other");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CUSTOM);
    resStr = res;
    ASSERT_EQ(resStr, "Custom");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::LIVE_VIEW);
    resStr = res;
    ASSERT_EQ(resStr, "Live_view");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    resStr = res;
    ASSERT_EQ(resStr, "Custom_service");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    resStr = res;
    ASSERT_EQ(resStr, "Emergency_information");
}


/**
 * @tc.name: SetSlotFlagsForSlot_00001
 * @tc.desc: Test SetSlotFlagsForSlot
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationPreferencesInfoTest, SetSlotFlagsForSlot_00001, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetSlotFlags(1);
    bundleInfo.SetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    int res = bundleInfo.GetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    ASSERT_EQ(res, 0);
}

/**
 * @tc.name: SetSlotFlagsForSlot_00002
 * @tc.desc: Test SetSlotFlagsForSlot
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationPreferencesInfoTest, SetSlotFlagsForSlot_00002, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetSlotFlags(1);
    bundleInfo.slotFlagsMap_["Social_communication"] = 63;
    bundleInfo.SetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    auto size = bundleInfo.slotFlagsMap_.size();
    ASSERT_EQ(bundleInfo.GetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 63);
    
    bundleInfo.slotFlagsMap_["Social_communication"] = 1;
    bundleInfo.SetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    ASSERT_EQ(bundleInfo.GetSlotFlagsForSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION), 1);
}


/**
 * @tc.name: MakeDoNotDisturbProfileKey_0100
 * @tc.desc: test MakeDoNotDisturbProfileKey can convert key right.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, MakeDoNotDisturbProfileKey_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    int32_t userId = 1;
    int32_t profileId = 1;
    string profilekey = "1_1";
    auto res = preferencesInfo->MakeDoNotDisturbProfileKey(userId, profileId);
    ASSERT_EQ(res, profilekey);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0100
 * @tc.desc: test AddDoNotDisturbProfiles can add success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, AddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    int32_t profileId = 1;
    profile->SetProfileId(profileId);
    profiles.emplace_back(profile);
    profiles.emplace_back(nullptr);
    preferencesInfo->AddDoNotDisturbProfiles(userId, profiles);

    auto res = preferencesInfo->GetDoNotDisturbProfiles(profileId, userId, profile);
    ASSERT_EQ(res, true);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0100
 * @tc.desc: test RemoveDoNotDisturbProfiles can remove success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, RemoveDoNotDisturbProfiles_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    profiles.emplace_back(profile);
    profiles.emplace_back(nullptr);
    preferencesInfo->RemoveDoNotDisturbProfiles(userId, profiles);
    int32_t profileId = 1;
    auto res = preferencesInfo->GetDoNotDisturbProfiles(profileId, userId, profile);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: GetDoNotDisturbProfiles_0100
 * @tc.desc: test GetDoNotDisturbProfiles can get success.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDoNotDisturbProfiles_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    int32_t userId = 1;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    int32_t profileId = 1;
    profile->SetProfileId(profileId);
    profiles.emplace_back(profile);
    preferencesInfo->AddDoNotDisturbProfiles(userId, profiles);
    auto res = preferencesInfo->GetDoNotDisturbProfiles(profileId, userId, profile);
    ASSERT_EQ(res, true);
}

/**
 * @tc.name: RemoveBundleInfo_0100
 * @tc.desc: test RemoveBundleInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, RemoveBundleInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationBundleOption> bundleInfo = new NotificationBundleOption("test", 1);;
    auto res = preferencesInfo->RemoveBundleInfo(bundleInfo);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: GetDisableNotificationInfo_0100
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    NotificationDisable notificationDisable;
    EXPECT_FALSE(preferencesInfo->GetDisableNotificationInfo(notificationDisable));
}

/**
 * @tc.name: GetDisableNotificationInfo_0200
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({});
    preferencesInfo->SetDisableNotificationInfo(notificationDisable);

    NotificationDisable disable;
    bool ret = preferencesInfo->GetDisableNotificationInfo(disable);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetDisableNotificationInfo_0300
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(false);
    notificationDisable->SetBundleList({ "com.example.app" });
    preferencesInfo->SetDisableNotificationInfo(notificationDisable);

    NotificationDisable disable;
    EXPECT_TRUE(preferencesInfo->GetDisableNotificationInfo(disable));
}

/**
 * @tc.name: GetDisableNotificationInfo_0400
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0400, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    preferencesInfo->SetDisableNotificationInfo(notificationDisable);
    NotificationDisable disable;
    bool ret = preferencesInfo->GetDisableNotificationInfo(disable);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: RemoveSlot_0100
 * @tc.desc: test RemoveSlot.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, RemoveSlot_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    ASSERT_FALSE(bundleInfo.RemoveSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION));
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0100
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string validJson = R"([{"bundleName":"bundle1","uid":100},{"bundleName":"bundle2","uid":200}])";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(validJson);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0200
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0200, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string emptyJson = "";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(emptyJson);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0300
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0300, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string invalidJson = "invalid json";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(invalidJson);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0400
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0400, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string nullJson = "null";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(nullJson);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0500
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0500, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string emptyObjectJson = "{}";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(emptyObjectJson);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0600
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0600, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string discardedJson = R"([{"bundleName": "test", "uid": 100},])";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(discardedJson);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: SetExtensionSubscriptionBundlesFromJson_0700
 * @tc.desc: Test SetExtensionSubscriptionBundlesFromJson
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionBundlesFromJson_0700, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    std::string nonArrayJson = R"({"bundleName":"test","uid":100})";
    
    bool result = bundleInfo.SetExtensionSubscriptionBundlesFromJson(nonArrayJson);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: RemoveExtensionSubscriptionBundles_0100
 * @tc.desc: Test RemoveExtensionSubscriptionBundles
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, RemoveExtensionSubscriptionBundles_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("bundle1", 100);
    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("bundle2", 200);
    
    std::vector<sptr<NotificationBundleOption>> bundlesToAdd;
    bundlesToAdd.push_back(bundle1);
    bundlesToAdd.push_back(bundle2);
    bundleInfo.AddExtensionSubscriptionBundles(bundlesToAdd);

    std::vector<sptr<NotificationBundleOption>> bundlesToRemove;
    bundlesToRemove.push_back(bundle1);
    bundleInfo.RemoveExtensionSubscriptionBundles(bundlesToRemove);

    std::vector<sptr<NotificationBundleOption>> bundlesAfter;
    bundleInfo.GetExtensionSubscriptionBundles(bundlesAfter);
    ASSERT_EQ(bundlesAfter.size(), 1);
}

/**
 * @tc.name: RemoveExtensionSubscriptionBundles_0200
 * @tc.desc: Test RemoveExtensionSubscriptionBundles
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, RemoveExtensionSubscriptionBundles_0200, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("bundle1", 100);
    
    std::vector<sptr<NotificationBundleOption>> bundlesToAdd;
    bundlesToAdd.push_back(bundle1);
    bundleInfo.AddExtensionSubscriptionBundles(bundlesToAdd);

    sptr<NotificationBundleOption> nonExistingBundle = new NotificationBundleOption("nonexisting", 999);
    std::vector<sptr<NotificationBundleOption>> bundlesToRemove;
    bundlesToRemove.push_back(nonExistingBundle);
    bundleInfo.RemoveExtensionSubscriptionBundles(bundlesToRemove);

    std::vector<sptr<NotificationBundleOption>> bundlesAfter;
    bundleInfo.GetExtensionSubscriptionBundles(bundlesAfter);
    ASSERT_EQ(bundlesAfter.size(), 1);
}

/**
 * @tc.name: RemoveExtensionSubscriptionBundles_0300
 * @tc.desc: Test RemoveExtensionSubscriptionBundles
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, RemoveExtensionSubscriptionBundles_0300, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("bundle1", 100);
    
    std::vector<sptr<NotificationBundleOption>> bundlesToAdd;
    bundlesToAdd.push_back(bundle1);
    bundleInfo.AddExtensionSubscriptionBundles(bundlesToAdd);

    std::vector<sptr<NotificationBundleOption>> emptyBundlesToRemove;
    bundleInfo.RemoveExtensionSubscriptionBundles(emptyBundlesToRemove);

    std::vector<sptr<NotificationBundleOption>> bundlesAfter;
    bundleInfo.GetExtensionSubscriptionBundles(bundlesAfter);
    ASSERT_EQ(bundlesAfter.size(), 1);
}

/**
 * @tc.name: IsExsitBundleInfo_0100
 * @tc.desc: test IsExsitBundleInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, IsExsitBundleInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption());
    bundleOption->SetBundleName("test");
    bundleOption->SetUid(100);

    NotificationPreferencesInfo::BundleInfo bundleInfo;
    preferencesInfo->SetBundleInfoFromDb(bundleInfo, "test100");

    ASSERT_TRUE(preferencesInfo->IsExsitBundleInfo(bundleOption));

    bundleOption->SetBundleName("test111");
    ASSERT_FALSE(preferencesInfo->IsExsitBundleInfo(bundleOption));
}

/**
 * @tc.name: GetAllDoNotDisturbProfiles_0100
 * @tc.desc: test GetAllDoNotDisturbProfiles.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetAllDoNotDisturbProfiles_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;

    NotificationPreferencesInfo::BundleInfo bundleInfo;

    sptr<NotificationDoNotDisturbProfile> profile;
    preferencesInfo->doNotDisturbProfiles_["2_100_3"] = profile;

    preferencesInfo->GetAllDoNotDisturbProfiles(100, profiles);
    ASSERT_EQ(profiles.size(), 1);
}

/**
 * @tc.name: GetAllCLoneBundlesInfo_0100
 * @tc.desc: test GetAllCLoneBundlesInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetAllCLoneBundlesInfo_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    std::unordered_map<std::string, std::string> bunlesMap;
    std::vector<NotificationCloneBundleInfo> cloneBundles;
    bunlesMap["test"] = "test100";

    NotificationPreferencesInfo::BundleInfo bundleInfo;
    preferencesInfo->SetBundleInfoFromDb(bundleInfo, "test100");
    
    preferencesInfo->GetAllCLoneBundlesInfo(100, 100, bunlesMap, cloneBundles);
    ASSERT_EQ(cloneBundles.size(), 1);
}

/**
 * @tc.name: GetAllLiveViewEnabledBundles_0100
 * @tc.desc: test GetAllLiveViewEnabledBundles.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetAllLiveViewEnabledBundles_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    preferencesInfo->SetEnabledAllNotification(100, true);
    std::vector<NotificationBundleOption> bundleOption;
    auto res = preferencesInfo->GetAllLiveViewEnabledBundles(100, bundleOption);
    ASSERT_EQ(res, ERR_OK);
    ASSERT_EQ(bundleOption.size(), 0);
}

/**
 * @tc.name: GetAllLiveViewEnabledBundles_0200
 * @tc.desc: test GetAllLiveViewEnabledBundles.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetAllLiveViewEnabledBundles_0200, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    preferencesInfo->SetEnabledAllNotification(100, false);
    std::vector<NotificationBundleOption> bundleOption;
    auto res = preferencesInfo->GetAllLiveViewEnabledBundles(100, bundleOption);
    ASSERT_EQ(res, ERR_OK);
    ASSERT_EQ(bundleOption.size(), 0);
}

/**
 * @tc.name: GetAllLiveViewEnabledBundles_0300
 * @tc.desc: test GetAllLiveViewEnabledBundles.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetAllLiveViewEnabledBundles_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();

    NotificationPreferencesInfo::BundleInfo bundleInfo;
    sptr<NotificationSlot> slot(new NotificationSlot(
        NotificationConstant::SlotType::LIVE_VIEW));
    slot->SetEnable(true);
    bundleInfo.SetSlot(slot);
    preferencesInfo->SetBundleInfoFromDb(bundleInfo, "test100");

    preferencesInfo->isEnabledAllNotification_[100] = true;
    std::vector<NotificationBundleOption> bundleOption;
    auto res = preferencesInfo->GetAllLiveViewEnabledBundles(100, bundleOption);
    ASSERT_EQ(res, ERR_OK);
    ASSERT_EQ(bundleOption.size(), 1);
}

/**
 * @tc.name: SetkioskAppTrustList_0100
 * @tc.desc: test SetkioskAppTrustList.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetkioskAppTrustList_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    ASSERT_NE(preferencesInfo, nullptr);
    std::vector<std::string> kioskAppTrustList;
    kioskAppTrustList.push_back("testBundleName");
    preferencesInfo->SetkioskAppTrustList(kioskAppTrustList);
    ASSERT_EQ(preferencesInfo->kioskAppTrustList_.size(), 1);
}

/**
 * @tc.name: GetkioskAppTrustList_0100
 * @tc.desc: test GetkioskAppTrustList.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetkioskAppTrustList_0100, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    ASSERT_NE(preferencesInfo, nullptr);
    std::vector<std::string> resultList;
    auto ret = preferencesInfo->GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, false);

    std::vector<std::string> kioskAppTrustList;
    kioskAppTrustList.push_back("testBundleName");
    preferencesInfo->SetkioskAppTrustList(kioskAppTrustList);
    ASSERT_EQ(preferencesInfo->kioskAppTrustList_.size(), 1);

    ret = preferencesInfo->GetkioskAppTrustList(resultList);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: GetDisableNotificationInfo_0500
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0500, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(true);
    notificationDisable->SetBundleList({ "com.example.app" });
    notificationDisable->SetUserId(101);
    preferencesInfo->SetDisableNotificationInfo(notificationDisable);
    NotificationDisable disable;
    bool ret = preferencesInfo->GetUserDisableNotificationInfo(101, disable);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetDisableNotificationInfo_0600
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0600, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    sptr<NotificationDisable> notificationDisable = new (std::nothrow) NotificationDisable();
    notificationDisable->SetDisabled(false);
    notificationDisable->SetBundleList({ "com.example.app" });
    notificationDisable->SetUserId(101);
    preferencesInfo->SetDisableNotificationInfo(notificationDisable);
    NotificationDisable disable;
    bool ret = preferencesInfo->GetUserDisableNotificationInfo(101, disable);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: GetDisableNotificationInfo_0700
 * @tc.desc: test GetDisableNotificationInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetDisableNotificationInfo_0700, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesInfo> preferencesInfo = std::make_shared<NotificationPreferencesInfo>();
    NotificationPreferencesInfo::DisableNotificationInfo disableNotificationInfo;
    disableNotificationInfo.disabled = -1;
    preferencesInfo->userDisableNotificationInfo_.insert_or_assign(101, disableNotificationInfo);
    NotificationDisable disable;
    bool ret = preferencesInfo->GetUserDisableNotificationInfo(101, disable);
    EXPECT_FALSE(ret);
    disableNotificationInfo.disabled = 1;
    preferencesInfo->userDisableNotificationInfo_.insert_or_assign(101, disableNotificationInfo);
    ret = preferencesInfo->GetUserDisableNotificationInfo(101, disable);
    EXPECT_FALSE(ret);
    ret = preferencesInfo->GetUserDisableNotificationInfo(102, disable);
    EXPECT_FALSE(ret);
    preferencesInfo->userDisableNotificationInfo_.clear();
}

/**
 * @tc.name: GetRingtoneInfo_0100
 * @tc.desc: test GetRingtoneInfo.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, GetRingtoneInfo_0100, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    sptr<NotificationRingtoneInfo> savedRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    std::string fileName = "ringtone.file.name";
    std::string title = "ringtone.title";
    std::string uri = "ringtone.uri";
    savedRingtoneInfo->SetRingtoneFileName(fileName);
    savedRingtoneInfo->SetRingtoneTitle(title);
    savedRingtoneInfo->SetRingtoneUri(uri);
    bundleInfo.SetRingtoneInfo(savedRingtoneInfo);
    sptr<NotificationRingtoneInfo> ringtoneInfo = bundleInfo.GetRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    EXPECT_EQ(ringtoneInfo->GetRingtoneFileName(), fileName);
    EXPECT_EQ(ringtoneInfo->GetRingtoneTitle(), title);
    EXPECT_EQ(ringtoneInfo->GetRingtoneUri(), uri);
}

/**
 * @tc.name: SetExtensionSubscriptionInfos_0100
 * @tc.desc: test SetExtensionSubscriptionInfos.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionInfos_0100, TestSize.Level1)
{
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bundleInfo.SetExtensionSubscriptionInfos(infos);
    EXPECT_TRUE(bundleInfo.GetExtensionSubscriptionInfos().empty());
}

/**
 * @tc.name: SetExtensionSubscriptionInfosFromJson_0100
 * @tc.desc: test SetExtensionSubscriptionInfosFromJson with json empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionInfosFromJson_0100, TestSize.Level1)
{
    std::string json;
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bool ret = bundleInfo.SetExtensionSubscriptionInfosFromJson(json);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetExtensionSubscriptionInfosFromJson_0200
 * @tc.desc: test SetExtensionSubscriptionInfosFromJson with invalid json.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionInfosFromJson_0200, TestSize.Level1)
{
    std::string json = "test";
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bool ret = bundleInfo.SetExtensionSubscriptionInfosFromJson(json);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetExtensionSubscriptionInfosFromJson_0300
 * @tc.desc: test SetExtensionSubscriptionInfosFromJson with json overflow.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionInfosFromJson_0300, TestSize.Level1)
{
    std::string json = "{\"key\": 1e999}";
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bool ret = bundleInfo.SetExtensionSubscriptionInfosFromJson(json);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetExtensionSubscriptionInfosFromJson_0400
 * @tc.desc: test SetExtensionSubscriptionInfosFromJson with json not array.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionInfosFromJson_0400, TestSize.Level1)
{
    std::string json = "{\"key\": 999}";
    NotificationPreferencesInfo::BundleInfo bundleInfo;
    bool ret = bundleInfo.SetExtensionSubscriptionInfosFromJson(json);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: SetExtensionSubscriptionInfosFromJson_0500
 * @tc.desc: test SetExtensionSubscriptionInfosFromJson.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesInfoTest, SetExtensionSubscriptionInfosFromJson_0500, TestSize.Level1)
{
    NotificationPreferencesInfo::BundleInfo bundleInfo1;
    auto info1 = new (std::nothrow) NotificationExtensionSubscriptionInfo();
    info1->SetAddr("test address");
    info1->SetHfp(true);
    info1->SetType(NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos1 = { info1 };
    bundleInfo1.SetExtensionSubscriptionInfos(infos1);
    std::string json1 = bundleInfo1.GetExtensionSubscriptionInfosJson();
    EXPECT_FALSE(json1.empty());

    NotificationPreferencesInfo::BundleInfo bundleInfo2;
    bool ret = bundleInfo2.SetExtensionSubscriptionInfosFromJson(json1);
    EXPECT_TRUE(ret);
    auto infos2 = bundleInfo2.GetExtensionSubscriptionInfos();
    EXPECT_EQ(infos2.size(), 1);
    auto info2 = infos2[0];
    EXPECT_STREQ(info1->GetAddr().c_str(), info2->GetAddr().c_str());
    EXPECT_EQ(info1->IsHfp(), info2->IsHfp());
    EXPECT_EQ(info1->GetType(), info2->GetType());
}
}
}
