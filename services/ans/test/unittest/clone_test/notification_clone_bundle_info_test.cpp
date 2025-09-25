/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "notification_clone_bundle_info.h"
#include "ans_inner_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
constexpr const char *BUNDLE_INFO_NAME = "name";
constexpr const char *BUNDLE_INFO_APP_INDEX = "index";
constexpr const char *BUNDLE_INFO_SLOT_FLAGS = "slotFlags";
constexpr const char *BUNDLE_INFO_SHOW_BADGE = "badge";
constexpr const char *BUNDLE_INFO_ENABLE_NOTIFICATION = "enable";
constexpr const char *BUNDLE_INFO_SLOT_LIST = "slotList";
constexpr const char *BUNDLE_INFO_SLOT_TYPE = "slotType";
constexpr const char *BUNDLE_INFO_SLOT_ENABLE = "slotEnable";
constexpr const char *BUNDLE_INFO_SLOT_CONTROL = "slotControl";
class NotificationCloneBundleInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: SetBundleName_00001
 * @tc.desc: Test SetBundleName parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetBundleName_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetBundleName(bundleName);
    EXPECT_EQ(rrc->GetBundleName(), bundleName);
}

/**
 * @tc.name: SetAppIndex_00001
 * @tc.desc: Test SetAppIndex parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetAppIndex_00001, Function | SmallTest | Level1)
{
    int32_t appIndex = 1;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetAppIndex(appIndex);
    EXPECT_EQ(rrc->GetAppIndex(), appIndex);
}

/**
 * @tc.name: SetUid_00001
 * @tc.desc: Test SetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetUid_00001, Function | SmallTest | Level1)
{
    int32_t uid = 1;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetUid(uid);
    EXPECT_EQ(rrc->GetUid(), uid);
}

/**
 * @tc.name: SetSlotFlags_00001
 * @tc.desc: Test SetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetSlotFlags_00001, Function | SmallTest | Level1)
{
    int32_t slotFlags = 1;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetSlotFlags(slotFlags);
    EXPECT_EQ(rrc->GetSlotFlags(), slotFlags);
}

/**
 * @tc.name: SetIsShowBadge_00001
 * @tc.desc: Test SetIsShowBadge parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetIsShowBadge_00001, Function | SmallTest | Level1)
{
    bool isShowBadge = true;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetIsShowBadge(isShowBadge);
    EXPECT_EQ(rrc->GetIsShowBadge(), isShowBadge);
}

/**
 * @tc.name: SetEnableNotification_00001
 * @tc.desc: Test SetEnableNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetEnableNotification_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SWITCH_STATE enabledNotification = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetEnableNotification(enabledNotification);
    EXPECT_EQ(rrc->GetEnableNotification(), enabledNotification);
}

/**
 * @tc.name: AddSlotInfo_00001
 * @tc.desc: Test AddSlotInfo parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, AddSlotInfo_00001, Function | SmallTest | Level1)
{
    NotificationCloneBundleInfo::SlotInfo slotInfo;
    slotInfo.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    slotInfo.enable_ = true;
    slotInfo.isForceControl_ = true;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->AddSlotInfo(slotInfo);
    EXPECT_EQ(rrc->GetSlotInfo().size(), 1);
}

/**
 * @tc.name: SetExtensionSubscriptionInfos_00001
 * @tc.desc: Test SetExtensionSubscriptionInfos parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SetExtensionSubscriptionInfos_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    ASSERT_NE(rrc, nullptr);
    rrc->SetExtensionSubscriptionInfos(infos);
    EXPECT_EQ(rrc->GetExtensionSubscriptionInfos().size(), 1);
}

/**
 * @tc.name: SubscriptionInfosFromJson_00001
 * @tc.desc: Test SubscriptionInfosFromJson parameters with nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SubscriptionInfosFromJson_00001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    ASSERT_NE(rrc, nullptr);
    rrc->SubscriptionInfosFromJson(jsonObject);
    EXPECT_TRUE(rrc->GetExtensionSubscriptionInfos().empty());
}

/**
 * @tc.name: SubscriptionInfosFromJson_00002
 * @tc.desc: Test SubscriptionInfosFromJson parameters without array.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SubscriptionInfosFromJson_00002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        "extensionSubscriptionInfo", "test"
    };
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    ASSERT_NE(rrc, nullptr);
    rrc->SubscriptionInfosFromJson(jsonObject);
    EXPECT_TRUE(rrc->GetExtensionSubscriptionInfos().empty());
}

/**
 * @tc.name: SubscriptionInfosFromJson_00003
 * @tc.desc: Test SubscriptionInfosFromJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, SubscriptionInfosFromJson_00003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json{
        {"extensionSubscriptionInfo", {
            {
                {"addr", "addr1"},
                {"isHfp", true},
                {"type", 0}
            }
        }}
    };
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    ASSERT_NE(rrc, nullptr);
    rrc->SubscriptionInfosFromJson(jsonObject);
    EXPECT_EQ(rrc->GetExtensionSubscriptionInfos().size(), 1);
}

/**
 * @tc.name: ToJson_00001
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, ToJson_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t appIndex = 1;
    int32_t uid = 1;
    int32_t slotFlags = 1;
    bool isShowBadge = true;
    NotificationConstant::SWITCH_STATE enabledNotification = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    NotificationCloneBundleInfo::SlotInfo slotInfo;
    slotInfo.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    slotInfo.enable_ = true;
    slotInfo.isForceControl_ = true;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetBundleName(bundleName);
    rrc->SetAppIndex(appIndex);
    rrc->SetUid(uid);
    rrc->SetSlotFlags(slotFlags);
    rrc->SetIsShowBadge(isShowBadge);
    rrc->SetEnableNotification(enabledNotification);
    rrc->AddSlotInfo(slotInfo);
    nlohmann::json jsonObject;
    EXPECT_EQ(jsonObject.is_null(), true);
    EXPECT_EQ(jsonObject.is_object(), false);
    rrc->FromJson(jsonObject);
    rrc->ToJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_EQ(rrc->GetSlotInfo().size(), 1);
    rrc->FromJson(jsonObject);
    EXPECT_EQ(rrc->GetSlotInfo().size(), 2);
}

/**
 * @tc.name: ToJson_00002
 * @tc.desc: Test ToJson parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, ToJson_00002, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t appIndex = 1;
    int32_t uid = 1;
    int32_t slotFlags = 1;
    bool isShowBadge = true;
    NotificationConstant::SWITCH_STATE enabledNotification = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto type = NotificationConstant::SubscribeType::BLUETOOTH;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo("addr", type));
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetBundleName(bundleName);
    rrc->SetAppIndex(appIndex);
    rrc->SetUid(uid);
    rrc->SetSlotFlags(slotFlags);
    rrc->SetIsShowBadge(isShowBadge);
    rrc->SetEnableNotification(enabledNotification);
    rrc->SetExtensionSubscriptionInfos(infos);
    nlohmann::json jsonObject;
    EXPECT_EQ(jsonObject.is_null(), true);
    EXPECT_EQ(jsonObject.is_object(), false);
    rrc->FromJson(jsonObject);
    rrc->ToJson(jsonObject);
    EXPECT_EQ(jsonObject.is_object(), true);
    EXPECT_EQ(rrc->GetExtensionSubscriptionInfos().size(), 1);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationCloneBundleInfoTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t appIndex = 1;
    int32_t uid = 1;
    int32_t slotFlags = 1;
    bool isShowBadge = true;
    NotificationConstant::SWITCH_STATE enabledNotification = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    NotificationCloneBundleInfo::SlotInfo slotInfo;
    slotInfo.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    slotInfo.enable_ = true;
    slotInfo.isForceControl_ = true;
    auto rrc = std::make_shared<NotificationCloneBundleInfo>();
    rrc->SetBundleName(bundleName);
    rrc->SetAppIndex(appIndex);
    rrc->SetUid(uid);
    rrc->SetSlotFlags(slotFlags);
    rrc->SetIsShowBadge(isShowBadge);
    rrc->SetEnableNotification(enabledNotification);
    rrc->AddSlotInfo(slotInfo);
    std::string dumpInfo;
    EXPECT_EQ(dumpInfo.size(), 0);
    std::string slotDump = "{";
    for (auto& slot : rrc->GetSlotInfo()) {
        slotDump += slot.Dump();
        slotDump += ",";
    }
    slotDump += "}";
    dumpInfo += "CloneBundle{ name = " + bundleName +
            ", index = " + std::to_string(appIndex) +
            ", uid = " + std::to_string(uid) +
            ", slotFlags = " + std::to_string(slotFlags) +
            ", ShowBadge = " + std::to_string(isShowBadge) +
            ", isEnabled = " + std::to_string(static_cast<int32_t>(enabledNotification)) +
            ", slotsInfo = " + slotDump +
            ", silentReminderEnabled = 0" +
            " }";
    EXPECT_EQ(rrc->Dump(), dumpInfo);
}
}
}