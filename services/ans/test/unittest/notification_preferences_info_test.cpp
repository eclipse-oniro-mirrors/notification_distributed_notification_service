/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
    EXPECT_EQ(resStr, "Social_communication");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::SERVICE_REMINDER);
    resStr = res;
    EXPECT_EQ(resStr, "Service_reminder");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CONTENT_INFORMATION);
    resStr = res;
    EXPECT_EQ(resStr, "Content_information");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::OTHER);
    resStr = res;
    EXPECT_EQ(resStr, "Other");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CUSTOM);
    resStr = res;
    EXPECT_EQ(resStr, "Custom");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::LIVE_VIEW);
    resStr = res;
    EXPECT_EQ(resStr, "Live_view");

    res = bundleInfo.GetSlotFlagsKeyFromType(NotificationConstant::SlotType::CUSTOMER_SERVICE);
    resStr = res;
    EXPECT_EQ(resStr, "Custom_service");
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
    EXPECT_EQ(res, 0);
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
    EXPECT_EQ(res, profilekey);
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
    preferencesInfo->AddDoNotDisturbProfiles(userId, profiles);

    auto res = preferencesInfo->GetDoNotDisturbProfiles(profileId, userId, profile);
    EXPECT_EQ(res, true);
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
    preferencesInfo->RemoveDoNotDisturbProfiles(userId, profiles);
    int32_t profileId = 1;
    auto res = preferencesInfo->GetDoNotDisturbProfiles(profileId, userId, profile);
    EXPECT_EQ(res, false);
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
    EXPECT_EQ(res, true);
}
}
}
