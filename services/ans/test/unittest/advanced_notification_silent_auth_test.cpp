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

#define private public // NOLINT
#define protected public // NOLINT
#include "advanced_notification_service.h"
#include "notification_preferences.h"
#include "permission_filter.h"
#undef protected
#undef private

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_ut_constant.h"
#include "mock_accesstoken_kit.h"
#include "mock_bundle_manager_helper.h"
#include "mock_ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_clone_bundle_info.h"
#include "notification_constant.h"
#include "notification_disable.h"
#include "notification_record.h"
#include "notification_request.h"
#include "notification_silent_auth.h"
#include "parcel.h"

extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);
extern void MockIsOsAccountExists(bool mockRet);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase = 0);
extern void MockQueryAllCreatedOsAccounts(int32_t userId);
extern void MockQueryAllCreatedOsAccounts(const std::vector<int32_t> &userIdList);
extern void MockQueryAllCreatedOsAccountsFailed(bool mockRet);
extern void ResetAccountMock();

using namespace testing::ext;

namespace OHOS {
namespace Notification {
extern const char *OHOS_PERMISSION_NOTIFICATION_CONTROLLER;
extern const char *OHOS_PERMISSION_MANAGE_EDM_POLICY;

namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t ANCO_UID = 900; // user-0 domain uid for Anco tests
constexpr int32_t BUNDLE_UID = NON_SYSTEM_APP_UID;

sptr<NotificationSilentAuth> BuildSilentAuth(const std::vector<std::string> &bundleList, int32_t userId)
{
    sptr<NotificationSilentAuth> info = new (std::nothrow) NotificationSilentAuth();
    info->SetBundleList(bundleList);
    info->SetUserId(userId);
    return info;
}

sptr<NotificationDisable> BuildDisable(bool disabled, const std::vector<std::string> &bundleList, int32_t userId)
{
    sptr<NotificationDisable> info = new (std::nothrow) NotificationDisable();
    info->SetDisabled(disabled);
    info->SetBundleList(bundleList);
    info->SetUserId(userId);
    return info;
}

sptr<NotificationBundleOption> BuildOption(const std::string &bundleName, int32_t uid)
{
    return new (std::nothrow) NotificationBundleOption(bundleName, uid);
}

NotificationConstant::SWITCH_STATE GetSwitchState(const std::string &bundleName, int32_t uid)
{
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(BuildOption(bundleName, uid), state);
    return state;
}

void ResetSilentAuthMocks()
{
    ResetAccountMock();
    MockQueryAllCreatedOsAccounts(std::vector<int32_t> {ZERO_USERID, TEST_USER_ID});
    MockIsOsAccountExists(true);
    MockBundleManager::MockIsAncoApp(false);
    MockBundleManager::MockUidByBundleName(NON_SYSTEM_APP_UID, NON_SYSTEM_APP_UID);
    MockBundleManager::MockCheckApiCompatibility(true);
    MockIsVerfyPermisson(true);
    MockDeniedPermission("");
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    IPCSkeleton::SetCallingUid(SYSTEM_APP_UID);
}
} // namespace

class AdvancedNotificationSilentAuthTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        sptr<AdvancedNotificationService> instance = AdvancedNotificationService::GetInstance();
        if (instance != nullptr) {
            instance->SelfClean(false);
        }
    }
    void SetUp()
    {
        ResetSilentAuthMocks();
        service_ = new (std::nothrow) AdvancedNotificationService();
    }
    void TearDown()
    {
        ResetSilentAuthMocks();
        // Cancel all silent auth and disable entries to isolate tests.
        service_->SetSilentAuthNotificationInfo(BuildSilentAuth({}, 0));
        service_->SetSilentAuthNotificationInfo(BuildSilentAuth({}, TEST_USER_ID));
        // The legacy disable contract rejects empty bundle lists (db and info layers), so cleanup
        // writes an inert record (disabled=false with a non-empty list): it passes the layer guards,
        // CollectDisabledBundles skips it via the GetDisabled() gate, and later tests overwrite the
        // rows (INSERT OR REPLACE). Silent auth keeps the empty-list cancel semantics.
        service_->DisableNotificationFeature(BuildDisable(false, {"ans_ut_cleanup"}, TEST_USER_ID));
        service_->DisableNotificationFeature(BuildDisable(false, {"ans_ut_cleanup"}, 0));
        service_->SetNotificationsEnabledForAllBundles("", true);
        // Drop the cache so the next test starts from the db-refill view (same as a restart).
        NotificationPreferences::GetInstance()->preferencesInfo_ = NotificationPreferencesInfo();
        ResetSilentAuthMocks();
        service_ = nullptr;
    }

    sptr<AdvancedNotificationService> service_;
};

/**
 * @tc.name: SilentAuth_ParcelRoundTrip_001
 * @tc.desc: NotificationSilentAuth marshalling/unmarshalling roundtrip (bundleList + userId)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_ParcelRoundTrip_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth info;
    info.SetBundleList({"sa_bundle_a", "sa_bundle_b"});
    info.SetUserId(TEST_USER_ID);
    Parcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    NotificationSilentAuth *out = NotificationSilentAuth::Unmarshalling(parcel);
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->GetBundleList(), info.GetBundleList());
    EXPECT_EQ(out->GetUserId(), TEST_USER_ID);
    delete out;
}

/**
 * @tc.name: SilentAuth_JsonRoundTrip_001
 * @tc.desc: NotificationSilentAuth ToJson/FromJson roundtrip, empty list keeps default
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_JsonRoundTrip_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth info;
    info.SetBundleList({"sa_json_a"});
    info.SetUserId(TEST_USER_ID);
    NotificationSilentAuth out;
    out.FromJson(info.ToJson());
    EXPECT_EQ(out.GetBundleList(), info.GetBundleList());
    EXPECT_EQ(out.GetUserId(), TEST_USER_ID);

    NotificationSilentAuth empty;
    NotificationSilentAuth emptyOut;
    emptyOut.FromJson(empty.ToJson());
    EXPECT_TRUE(emptyOut.GetBundleList().empty());
    EXPECT_EQ(emptyOut.GetUserId(), -1);
}

/**
 * @tc.name: SilentAuth_FromJsonInvalid_001
 * @tc.desc: Invalid json keeps defaults (fault tolerance)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_FromJsonInvalid_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth out;
    out.FromJson("");
    out.FromJson("not-a-json");
    EXPECT_TRUE(out.GetBundleList().empty());
    EXPECT_EQ(out.GetUserId(), -1);
}

/**
 * @tc.name: Set_Nullptr_001
 * @tc.desc: Null config object returns 120001
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_Nullptr_001, Function | SmallTest | Level1)
{
    // The IPC entry rejects a null info before any permission or user resolution.
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(nullptr), ERR_ANS_INNER_INVALID_PARAM);
    // The preferences layer guards the same null contract.
    EXPECT_EQ(NotificationPreferences::GetInstance()->SetSilentAuthNotificationInfo(nullptr),
        ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: Set_NotSystemApp_001
 * @tc.desc: Non-system caller returns 110002
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_NotSystemApp_001, Function | SmallTest | Level1)
{
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_x"}, TEST_USER_ID)),
        ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.name: Set_PermissionDenied_001
 * @tc.desc: All permissions denied returns 110001
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_PermissionDenied_001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_x"}, TEST_USER_ID)),
        ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: Set_DualPermissionRequired_001
 * @tc.desc: Both MANAGE_EDM_POLICY and NOTIFICATION_CONTROLLER are required: denying either one returns 110001
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_DualPermissionRequired_001, Function | SmallTest | Level1)
{
    MockDeniedPermission(OHOS_PERMISSION_MANAGE_EDM_POLICY);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_x"}, TEST_USER_ID)),
        ERR_ANS_INNER_PERMISSION_DENIED);
    MockDeniedPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_x"}, TEST_USER_ID)),
        ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: Set_UserIdNotExist_001
 * @tc.desc: Explicit userId not in account list returns 120001
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_UserIdNotExist_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_x"}, TEST_USER_ID + 1)),
        ERR_ANS_INNER_INVALID_PARAM);
    // A rejected set must not leave the bundle locked or partially stored.
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_x", BUNDLE_UID)));
    EXPECT_EQ(GetSwitchState("sa_x", BUNDLE_UID), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
}

/**
 * @tc.name: Set_ActiveUserResolveFail_001
 * @tc.desc: userId -1 with active user resolve failure returns ERR_ANS_INNER_GET_ACTIVE_USER_FAILED
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_ActiveUserResolveFail_001, Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_x"}, SUBSCRIBE_USER_INIT)),
        ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.name: Set_ActiveUserDefault_001
 * @tc.desc: userId -1 resolves to the active user(100), stored on that user's entry
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_ActiveUserDefault_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_active"}, SUBSCRIBE_USER_INIT)), ERR_OK);
    EXPECT_TRUE(service_->IsBundleSilentAuthLocked(BuildOption("sa_active", BUNDLE_UID)));
    // The -1 form stores on the resolved active user entry, not the global (user-0) entry.
    std::vector<std::string> bundleList;
    EXPECT_EQ(service_->GetSilentAuthNotificationBundles(TEST_USER_ID, bundleList), ERR_OK);
    EXPECT_NE(std::find(bundleList.begin(), bundleList.end(), "sa_active"), bundleList.end());
}

/**
 * @tc.name: Set_BundleListForceOn_001
 * @tc.desc: Locked bundle is force-enabled to USER_MODIFIED_ON, idempotent on re-config
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_BundleListForceOn_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_force"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_force", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_force"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_force", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

/**
 * @tc.name: Set_EmptyListCancel_001
 * @tc.desc: Empty list cancels management: unlock, empty query map, switch value kept (BR-3)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_EmptyListCancel_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_cancel"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({}, TEST_USER_ID)), ERR_OK);
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_cancel", BUNDLE_UID)));
    EXPECT_EQ(GetSwitchState("sa_cancel", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_EQ(switchLimited.count("sa_cancel"), 0);
}

/**
 * @tc.name: Lock_EntryDimensions_001
 * @tc.desc: Lock check matches global entry for any user, user entry only for that user, null option is false
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Lock_EntryDimensions_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_global"}, 0)), ERR_OK);
    EXPECT_TRUE(service_->IsBundleSilentAuthLocked(BuildOption("sa_global", BUNDLE_UID)));
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_not_in_list", BUNDLE_UID)));
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(nullptr));
}

/**
 * @tc.name: Lock_AncoActiveUserEntry_001
 * @tc.desc: Anco app (uid->user-0) additionally matches the active user entry; non-Anco user-0 app does not
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Lock_AncoActiveUserEntry_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_anco_lock"}, TEST_USER_ID)), ERR_OK);
    MockGetOsAccountLocalIdFromUid(true, 3); // uid -> userId 0 (Anco user-0 domain)
    MockBundleManager::MockIsAncoApp(true);
    EXPECT_TRUE(service_->IsBundleSilentAuthLocked(BuildOption("sa_anco_lock", ANCO_UID)));
    MockBundleManager::MockIsAncoApp(false);
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_anco_lock", ANCO_UID)));
}

/**
 * @tc.name: Anco_ForceEnableFallback_001
 * @tc.desc: uid resolve falls back to the user-0 domain for Anco apps; non-Anco is rejected by IsAncoApp gate
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Anco_ForceEnableFallback_001, Function | SmallTest | Level1)
{
    MockBundleManager::MockUidByBundleName(-1, ANCO_UID);
    MockBundleManager::MockIsAncoApp(true);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_anco_force"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_anco_force", ANCO_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    MockBundleManager::MockIsAncoApp(false);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_non_anco"}, TEST_USER_ID)), ERR_OK);
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    EXPECT_NE(NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(
        BuildOption("sa_non_anco", ANCO_UID), state), ERR_OK);
}

/**
 * @tc.name: Disable_UserLevelRejected_001
 * @tc.desc: User-level disable of a locked bundle returns 110005 and keeps ON; enable(true) passes
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Disable_UserLevelRejected_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_reject"}, TEST_USER_ID)), ERR_OK);
    auto option = BuildOption("sa_reject", BUNDLE_UID);
    EXPECT_EQ(service_->SetNotificationsEnabledForSpecialBundle("", option, false, false),
        ERR_ANS_INNER_ENTERPRISE_POLICY_PROHIBITED);
    EXPECT_EQ(GetSwitchState("sa_reject", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(service_->SetNotificationsEnabledForSpecialBundle("", option, true, false), ERR_OK);
}

/**
 * @tc.name: Disable_SystemLevelAllowedThenSelfHeal_001
 * @tc.desc: v2.3: system-level disable is allowed (accepted window), then install/scan guard self-heals to ON
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Disable_SystemLevelAllowedThenSelfHeal_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_selfheal"}, TEST_USER_ID)), ERR_OK);
    auto option = BuildOption("sa_selfheal", BUNDLE_UID);
    EXPECT_EQ(service_->SetNotificationsSystemEnabledForSpecialBundle("", option, false, false), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_selfheal", BUNDLE_UID), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.allowEnableNotification = false;
    EXPECT_EQ(service_->UpdateNotificationSwitchState(option, bundleInfo), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_selfheal", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

/**
 * @tc.name: Disable_NotLockedUnaffected_001
 * @tc.desc: Unmanaged bundle keeps legacy disable behavior (I6 regression)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Disable_NotLockedUnaffected_001, Function | SmallTest | Level1)
{
    auto option = BuildOption("sa_unmanaged", BUNDLE_UID);
    EXPECT_EQ(service_->SetNotificationsEnabledForSpecialBundle("", option, false, false), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_unmanaged", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
}

/**
 * @tc.name: GetLimited_CheckFailed_001
 * @tc.desc: Permission denied 110001, non-system app 110002, userId not exist
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetLimited_CheckFailed_001, Function | SmallTest | Level1)
{
    std::map<std::string, bool> switchLimited;
    MockIsVerfyPermisson(false);
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited),
        ERR_ANS_INNER_PERMISSION_DENIED);
    IPCSkeleton::SetCallingTokenID(NON_NATIVE_TOKEN);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited),
        ERR_ANS_INNER_NON_SYSTEM_APP);
    ResetSilentAuthMocks();
    MockIsOsAccountExists(false);
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited),
        ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.name: GetLimited_MergeBlacklist_001
 * @tc.desc: List merged with fixed false when enabled; not merged when disabled; conflicts overridden to false
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetLimited_MergeBlacklist_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_qa", "sa_qb"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(service_->DisableNotificationFeature(BuildDisable(true, {"sa_qc"}, TEST_USER_ID)), ERR_OK);
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_TRUE(switchLimited["sa_qa"]);
    EXPECT_TRUE(switchLimited["sa_qb"]);
    EXPECT_FALSE(switchLimited["sa_qc"]);

    // Cancel within the legacy contract: disabled=false keeps the record inert (the empty-list
    // form is invalid input rejected by the db/info layers), so sa_qc is no longer merged.
    EXPECT_EQ(service_->DisableNotificationFeature(BuildDisable(false, {"sa_qc"}, TEST_USER_ID)), ERR_OK);
    // Drop the cache so the query below takes the db-refill path, mirroring the post-restart view.
    NotificationPreferences::GetInstance()->preferencesInfo_ = NotificationPreferencesInfo();
    switchLimited.clear();
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_EQ(switchLimited.count("sa_qc"), 0);

    EXPECT_EQ(service_->DisableNotificationFeature(BuildDisable(true, {"sa_qa"}, TEST_USER_ID)), ERR_OK);
    switchLimited.clear();
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_FALSE(switchLimited["sa_qa"]);
}

/**
 * @tc.name: GetLimited_NotInstalledValueTrue_001
 * @tc.desc: Not installed locked bundle reports true (locked-on semantics, no uid)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetLimited_NotInstalledValueTrue_001, Function | SmallTest | Level1)
{
    MockBundleManager::MockUidByBundleName(-1, -1);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_not_installed"}, TEST_USER_ID)), ERR_OK);
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_TRUE(switchLimited["sa_not_installed"]);
}

/**
 * @tc.name: GetSilentAuthBundles_PureNames_001
 * @tc.desc: MDM query returns deduped bundle names; check failures
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetSilentAuthBundles_PureNames_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_mb"}, 0)), ERR_OK);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(
        BuildSilentAuth({"sa_ma", "sa_mb"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(service_->DisableNotificationFeature(BuildDisable(true, {"sa_mc"}, TEST_USER_ID)), ERR_OK);
    std::vector<std::string> bundleList;
    EXPECT_EQ(service_->GetSilentAuthNotificationBundles(TEST_USER_ID, bundleList), ERR_OK);
    EXPECT_EQ(bundleList.size(), 2);
    EXPECT_NE(std::find(bundleList.begin(), bundleList.end(), "sa_ma"), bundleList.end());
    EXPECT_NE(std::find(bundleList.begin(), bundleList.end(), "sa_mb"), bundleList.end());
    EXPECT_EQ(std::find(bundleList.begin(), bundleList.end(), "sa_mc"), bundleList.end());

    MockIsVerfyPermisson(false);
    EXPECT_EQ(service_->GetSilentAuthNotificationBundles(TEST_USER_ID, bundleList), ERR_ANS_INNER_PERMISSION_DENIED);
    ResetSilentAuthMocks();
    MockIsOsAccountExists(false);
    EXPECT_EQ(service_->GetSilentAuthNotificationBundles(TEST_USER_ID, bundleList),
        ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
}

/**
 * @tc.name: UpdateSwitchState_LockedForceOn_001
 * @tc.desc: Install/scan guard keeps locked bundle ON instead of default-off initialization
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, UpdateSwitchState_LockedForceOn_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_install"}, TEST_USER_ID)), ERR_OK);
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.allowEnableNotification = false;
    EXPECT_EQ(service_->UpdateNotificationSwitchState(BuildOption("sa_install", BUNDLE_UID), bundleInfo), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_install", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

/**
 * @tc.name: UpdateSwitchState_NotLockedInit_001
 * @tc.desc: Unmanaged bundle initializes by allowEnableNotification declaration (legacy behavior, I6)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, UpdateSwitchState_NotLockedInit_001, Function | SmallTest | Level1)
{
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.allowEnableNotification = false;
    EXPECT_EQ(service_->UpdateNotificationSwitchState(BuildOption("sa_init_off", BUNDLE_UID), bundleInfo), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_init_off", BUNDLE_UID), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    bundleInfo.applicationInfo.allowEnableNotification = true;
    EXPECT_EQ(service_->UpdateNotificationSwitchState(BuildOption("sa_init_on", BUNDLE_UID), bundleInfo), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_init_on", BUNDLE_UID), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
}

/**
 * @tc.name: CloneRestore_LockedForceOn_001
 * @tc.desc: Clone restore writes USER_MODIFIED_ON for locked bundles (off-state not stored); on-state passes through
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, CloneRestore_LockedForceOn_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_clone"}, TEST_USER_ID)), ERR_OK);
    auto option = BuildOption("sa_clone", BUNDLE_UID);
    NotificationCloneBundleInfo cloneBundleInfo;
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    service_->UpdateCloneBundleInfoForEnable(cloneBundleInfo, option);
    EXPECT_EQ(GetSwitchState("sa_clone", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    cloneBundleInfo.SetEnableNotification(NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    service_->UpdateCloneBundleInfoForEnable(cloneBundleInfo, option);
    EXPECT_EQ(GetSwitchState("sa_clone", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
}

/**
 * @tc.name: IsAllowedNotify_ExemptAndLazyWrite_001
 * @tc.desc: Locked bundle is exempt from the global switch; missing record is lazily written to USER_MODIFIED_ON;
 *           unmanaged no-record bundle follows CheckApiCompatibility (mocked FA true)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, IsAllowedNotify_ExemptAndLazyWrite_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_exempt", "sa_lazy"}, TEST_USER_ID)), ERR_OK);
    // Global switch off: locked bundle is exempt and a missing record is lazily written.
    EXPECT_EQ(service_->SetNotificationsEnabledForAllBundles("", false), ERR_OK);
    bool allowed = false;
    EXPECT_EQ(service_->IsAllowedNotifySelf(BuildOption("sa_exempt", BUNDLE_UID), allowed), ERR_OK);
    EXPECT_TRUE(allowed);
    EXPECT_EQ(service_->IsAllowedNotifySelf(BuildOption("sa_lazy", BUNDLE_UID), allowed), ERR_OK);
    EXPECT_TRUE(allowed);
    EXPECT_EQ(GetSwitchState("sa_lazy", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    // Global switch on: unmanaged no-record bundle follows CheckApiCompatibility (mocked FA true).
    EXPECT_EQ(service_->SetNotificationsEnabledForAllBundles("", true), ERR_OK);
    EXPECT_EQ(service_->IsAllowedNotifySelf(BuildOption("sa_fa_compat", BUNDLE_UID), allowed), ERR_OK);
    EXPECT_TRUE(allowed);
    EXPECT_EQ(GetSwitchState("sa_fa_compat", BUNDLE_UID), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
}

/**
 * @tc.name: IsAllowedNotifyForBundle_Exempt_001
 * @tc.desc: IsAllowedNotifyForBundle (cancel path) exempts the locked bundle even with the global switch off
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, IsAllowedNotifyForBundle_Exempt_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_cancel_exempt"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(service_->SetNotificationsEnabledForAllBundles("", false), ERR_OK);
    bool allowed = true;
    EXPECT_EQ(service_->IsAllowedNotifyForBundle(BuildOption("sa_cancel_exempt", BUNDLE_UID), allowed), ERR_OK);
    EXPECT_TRUE(allowed);
    EXPECT_EQ(service_->SetNotificationsEnabledForAllBundles("", true), ERR_OK);
}

/**
 * @tc.name: PermissionFilter_LazyWrite_001
 * @tc.desc: Publish gate lazily writes USER_MODIFIED_ON for a locked bundle whose record is missing
 *           (bundle installed after the config); unmanaged no-record bundle follows CheckApiCompatibility
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, PermissionFilter_LazyWrite_001, Function | SmallTest | Level1)
{
    // The bundle is not installed when the config arrives, so no switch record is pre-written by the set.
    MockBundleManager::MockUidByBundleName(-1, -1);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_publish"}, TEST_USER_ID)), ERR_OK);
    // The bundle is installed afterwards: the uid resolves again, the switch record is still missing.
    MockBundleManager::MockUidByBundleName(NON_SYSTEM_APP_UID, -1);
    auto record = std::make_shared<NotificationRecord>();
    record->bundleOption = BuildOption("sa_publish", BUNDLE_UID);
    PermissionFilter filter;
    bool enable = false;
    // ResolveSilentAuthBundleNotExist: locked bundle is allowed and the switch is lazily written.
    filter.ResolveBundlePublishEnable(record, enable);
    EXPECT_TRUE(enable);
    EXPECT_EQ(GetSwitchState("sa_publish", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    record->bundleOption = BuildOption("sa_publish_fa", BUNDLE_UID);
    filter.ResolveBundlePublishEnable(record, enable);
    EXPECT_TRUE(enable);
}

/**
 * @tc.name: PublishChain_StageAppLockedForceOn_001
 * @tc.desc: Publish chain keeps a silent-auth locked stage app (compat default OFF) forced on:
 *           slot creation does not materialize an OFF record for locked bundles; unmanaged stays OFF
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, PublishChain_StageAppLockedForceOn_001, Function | SmallTest | Level1)
{
    // Stage app: an unmanaged bundle is materialized to SYSTEM_DEFAULT_OFF by slot creation.
    MockBundleManager::MockCheckApiCompatibility(false);
    // The bundle is not installed when the config arrives, so no switch record is pre-written.
    MockBundleManager::MockUidByBundleName(-1, -1);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_stage"}, TEST_USER_ID)), ERR_OK);
    // The bundle is installed afterwards: the uid resolves again, the switch record is still missing.
    MockBundleManager::MockUidByBundleName(BUNDLE_UID, -1);

    auto record = std::make_shared<NotificationRecord>();
    record->bundleOption = BuildOption("sa_stage", BUNDLE_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest(1);
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    record->request = request;
    AnsStatus slotStatus = service_->AssignValidNotificationSlot(record, record->bundleOption);
    EXPECT_TRUE(slotStatus.Ok());
    EXPECT_EQ(GetSwitchState("sa_stage", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    PermissionFilter filter;
    bool enable = false;
    filter.ResolveBundlePublishEnable(record, enable);
    EXPECT_TRUE(enable);

    // Control: an unmanaged stage app is materialized to SYSTEM_DEFAULT_OFF by slot creation.
    auto unmanaged = std::make_shared<NotificationRecord>();
    unmanaged->bundleOption = BuildOption("sa_stage_unmanaged", BUNDLE_UID);
    sptr<NotificationRequest> unmanagedRequest = new (std::nothrow) NotificationRequest(1);
    unmanagedRequest->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    unmanaged->request = unmanagedRequest;
    AnsStatus unmanagedSlotStatus = service_->AssignValidNotificationSlot(unmanaged, unmanaged->bundleOption);
    EXPECT_TRUE(unmanagedSlotStatus.Ok());
    EXPECT_EQ(GetSwitchState("sa_stage_unmanaged", BUNDLE_UID),
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    bool unmanagedEnable = true;
    filter.ResolveBundlePublishEnable(unmanaged, unmanagedEnable);
    EXPECT_FALSE(unmanagedEnable);
}

/**
 * @tc.name: SilentAuth_CacheRefillFromDb_001
 * @tc.desc: Cache-missing silent auth and disable queries are refilled from db and cached for later hits
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_CacheRefillFromDb_001, Function | SmallTest | Level1)
{
    auto prefs = NotificationPreferences::GetInstance();
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_rt"}, TEST_USER_ID)), ERR_OK);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_rt_g"}, 0)), ERR_OK);
    EXPECT_EQ(service_->DisableNotificationFeature(BuildDisable(true, {"sa_rt_d"}, TEST_USER_ID)), ERR_OK);
    sptr<NotificationDisable> seedGlobal = new (std::nothrow) NotificationDisable();
    ASSERT_NE(seedGlobal, nullptr);
    seedGlobal->SetUserId(0);
    seedGlobal->SetDisabled(true);
    seedGlobal->SetBundleList({"sa_rt_dg"});
    EXPECT_EQ(prefs->SetDisableNotificationInfo(seedGlobal), ERR_OK);

    // Drop the in-memory cache so the queries below take the db-refill path.
    prefs->preferencesInfo_ = NotificationPreferencesInfo();

    NotificationSilentAuth silentAuth;
    EXPECT_TRUE(prefs->GetUserSilentAuthNotificationInfo(TEST_USER_ID, silentAuth));
    EXPECT_EQ(silentAuth.GetBundleList(), std::vector<std::string>({"sa_rt"}));
    EXPECT_TRUE(prefs->GetSilentAuthNotificationInfo(silentAuth));
    EXPECT_EQ(silentAuth.GetBundleList(), std::vector<std::string>({"sa_rt_g"}));

    // Each scope query uses its own output object: NotificationDisable::FromJson appends to the
    // bundle list without resetting it (legacy behavior), so reusing one object across the
    // user-level and global queries would merge both lists.
    NotificationDisable userDisable;
    EXPECT_TRUE(prefs->GetUserDisableNotificationInfo(TEST_USER_ID, userDisable));
    EXPECT_TRUE(userDisable.GetDisabled());
    EXPECT_EQ(userDisable.GetBundleList(), std::vector<std::string>({"sa_rt_d"}));
    NotificationDisable globalDisable;
    EXPECT_TRUE(prefs->GetDisableNotificationInfo(globalDisable));
    EXPECT_TRUE(globalDisable.GetDisabled());
    EXPECT_EQ(globalDisable.GetBundleList(), std::vector<std::string>({"sa_rt_dg"}));
}

/**
 * @tc.name: SilentAuth_FailOpenContract_001
 * @tc.desc: Failed user silent auth queries degrade to unlocked and do not block the publish gate
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_FailOpenContract_001, Function | SmallTest | Level1)
{
    auto prefs = NotificationPreferences::GetInstance();
    NotificationSilentAuth silentAuth;
    EXPECT_FALSE(prefs->GetUserSilentAuthNotificationInfo(SUBSCRIBE_USER_INIT, silentAuth));
    EXPECT_FALSE(prefs->IsBundleSilentAuthLockedForUser("sa_fail_open", SUBSCRIBE_USER_INIT));
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_fail_open", BUNDLE_UID)));

    auto record = std::make_shared<NotificationRecord>();
    record->bundleOption = BuildOption("sa_fail_open", BUNDLE_UID);
    PermissionFilter filter;
    bool enable = false;
    filter.ResolveBundlePublishEnable(record, enable);
    EXPECT_TRUE(enable);
}

/**
 * @tc.name: Set_UserIdQueryFail_FailClosed_001
 * @tc.desc: Explicit userId with account query failure fails closed; negative userId is rejected directly
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_UserIdQueryFail_FailClosed_001, Function | SmallTest | Level1)
{
    MockQueryAllCreatedOsAccountsFailed(true);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_fail_closed"}, TEST_USER_ID)),
        ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_neg"}, -5)),
        ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: SilentAuth_UserCacheNotPollutedByGlobal_001
 * @tc.desc: The user-level cache is refilled from its own db entry only, the global list does not leak in
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_UserCacheNotPollutedByGlobal_001, Function | SmallTest | Level1)
{
    auto prefs = NotificationPreferences::GetInstance();
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_pollute_g"}, 0)), ERR_OK);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_pollute_u"}, TEST_USER_ID)), ERR_OK);

    // Drop the in-memory cache so the lock check below refills it from db.
    prefs->preferencesInfo_ = NotificationPreferencesInfo();

    EXPECT_TRUE(prefs->IsBundleSilentAuthLockedForUser("sa_pollute_u", TEST_USER_ID));
    NotificationSilentAuth userInfo;
    EXPECT_TRUE(prefs->GetUserSilentAuthNotificationInfo(TEST_USER_ID, userInfo));
    EXPECT_EQ(userInfo.GetBundleList(), std::vector<std::string>({"sa_pollute_u"}));

    // Cancel the global management: the global bundle must not stay locked via the user-level cache.
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({}, 0)), ERR_OK);
    EXPECT_FALSE(prefs->IsBundleSilentAuthLockedForUser("sa_pollute_g", TEST_USER_ID));
}

/**
 * @tc.name: SpecialBundleSwitch_LockedExempt_001
 * @tc.desc: Locked bundle is exempt from the global switch and lazily enabled on the special check path
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SpecialBundleSwitch_LockedExempt_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetNotificationsEnabledForAllBundles("", false), ERR_OK);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_special"}, TEST_USER_ID)), ERR_OK);

    sptr<NotificationBundleOption> bundleOption = BuildOption("sa_special", BUNDLE_UID);
    bool allowed = false;
    EXPECT_EQ(service_->CheckSpecialBundleSwitchAllowed(bundleOption, bundleOption, TEST_USER_ID, allowed), ERR_OK);
    EXPECT_TRUE(allowed);
    EXPECT_EQ(GetSwitchState("sa_special", BUNDLE_UID), NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);

    // Unmanaged bundle is not exempted, the global switch off result is kept.
    sptr<NotificationBundleOption> unmanaged = BuildOption("sa_unmanaged_special", BUNDLE_UID);
    bool unmanagedAllowed = true;
    EXPECT_EQ(service_->CheckSpecialBundleSwitchAllowed(unmanaged, unmanaged, TEST_USER_ID, unmanagedAllowed),
        ERR_OK);
    EXPECT_FALSE(unmanagedAllowed);
}

/**
 * @tc.name: Set_EmptyBundleNameSkipped_001
 * @tc.desc: Empty bundle names in the list are skipped by force-enable and both query paths
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Set_EmptyBundleNameSkipped_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"", "sa_skip"}, TEST_USER_ID)), ERR_OK);
    std::vector<std::string> bundleList;
    EXPECT_EQ(service_->GetSilentAuthNotificationBundles(TEST_USER_ID, bundleList), ERR_OK);
    EXPECT_EQ(bundleList.size(), 1);
    EXPECT_EQ(bundleList.front(), "sa_skip");
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_EQ(switchLimited.count(""), 0);
    EXPECT_TRUE(switchLimited["sa_skip"]);
}

/**
 * @tc.name: GetLimited_OverlapMergedOnce_001
 * @tc.desc: A bundle present in both the global and user lists is reported once with a single value
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetLimited_OverlapMergedOnce_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_ov"}, 0)), ERR_OK);
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_ov"}, TEST_USER_ID)), ERR_OK);
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_EQ(switchLimited.size(), 1);
    EXPECT_TRUE(switchLimited["sa_ov"]);
}

/**
 * @tc.name: GetLimited_LockedOffStateReportedFalse_001
 * @tc.desc: A locked bundle with a stored OFF record reports false instead of the locked-on default
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetLimited_LockedOffStateReportedFalse_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_off"}, TEST_USER_ID)), ERR_OK);
    auto option = BuildOption("sa_off", BUNDLE_UID);
    EXPECT_EQ(service_->SetNotificationsSystemEnabledForSpecialBundle("", option, false, false), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_off", BUNDLE_UID), NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_FALSE(switchLimited["sa_off"]);
}

/**
 * @tc.name: Lock_UidResolveFallbackToActiveUser_001
 * @tc.desc: When uid -> userId resolve fails, the lock check falls back to the active user entry
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Lock_UidResolveFallbackToActiveUser_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_fb"}, TEST_USER_ID)), ERR_OK);
    MockGetOsAccountLocalIdFromUid(false);
    // uid -> userId resolve fails, fallback to the active user entry still matches.
    EXPECT_TRUE(service_->IsBundleSilentAuthLocked(BuildOption("sa_fb", BUNDLE_UID)));
}

/**
 * @tc.name: Lock_FallbackChainExhaustedUnlocked_001
 * @tc.desc: When both uid resolve and active user resolve fail, the lock check reports unlocked
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Lock_FallbackChainExhaustedUnlocked_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_nouser"}, TEST_USER_ID)), ERR_OK);
    // Anco uid resolves to the user-0 domain, but the active user resolve fails: not locked.
    MockGetOsAccountLocalIdFromUid(true, 3);
    MockBundleManager::MockIsAncoApp(true);
    MockQueryForgroundOsAccountId(false);
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_nouser", ANCO_UID)));
    // uid resolve fails and the active user resolve fails: fallback chain exhausted.
    MockGetOsAccountLocalIdFromUid(false);
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_nouser", BUNDLE_UID)));
}

/**
 * @tc.name: Lock_ZeroUidUsesActiveUser_001
 * @tc.desc: A bundle option with uid <= 0 resolves the lock check against the active user entry
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Lock_ZeroUidUsesActiveUser_001, Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_zero_uid"}, TEST_USER_ID)), ERR_OK);
    // uid <= 0 falls back to the active user for the lock check.
    EXPECT_TRUE(service_->IsBundleSilentAuthLocked(BuildOption("sa_zero_uid", 0)));
    EXPECT_FALSE(service_->IsBundleSilentAuthLocked(BuildOption("sa_not_locked", 0)));
}

/**
 * @tc.name: Disable_SystemLevelEnableWritesDefaultOn_001
 * @tc.desc: System-level enable on a locked bundle writes SYSTEM_DEFAULT_ON
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, Disable_SystemLevelEnableWritesDefaultOn_001,
    Function | SmallTest | Level1)
{
    EXPECT_EQ(service_->SetSilentAuthNotificationInfo(BuildSilentAuth({"sa_sys_on"}, TEST_USER_ID)), ERR_OK);
    auto option = BuildOption("sa_sys_on", BUNDLE_UID);
    EXPECT_EQ(service_->SetNotificationsSystemEnabledForSpecialBundle("", option, true, false), ERR_OK);
    EXPECT_EQ(GetSwitchState("sa_sys_on", BUNDLE_UID),
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
}

/**
 * @tc.name: GetLimited_GlobalDisableMerged_001
 * @tc.desc: A global (user-0) disable list is merged into the query result as fixed false
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, GetLimited_GlobalDisableMerged_001, Function | SmallTest | Level1)
{
    sptr<NotificationDisable> seedGlobal = new (std::nothrow) NotificationDisable();
    ASSERT_NE(seedGlobal, nullptr);
    seedGlobal->SetUserId(0);
    seedGlobal->SetDisabled(true);
    seedGlobal->SetBundleList({"sa_gd"});
    EXPECT_EQ(NotificationPreferences::GetInstance()->SetDisableNotificationInfo(seedGlobal), ERR_OK);
    std::map<std::string, bool> switchLimited;
    EXPECT_EQ(service_->GetNotificationSwitchLimitedBundles(TEST_USER_ID, switchLimited), ERR_OK);
    EXPECT_FALSE(switchLimited["sa_gd"]);
}

/**
 * @tc.name: ForceEnable_InvalidBundleRejected_001
 * @tc.desc: Force enable with an unresolvable bundle (uid <= 0, not installed) is rejected
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, ForceEnable_InvalidBundleRejected_001, Function | SmallTest | Level1)
{
    // A null bundle option is rejected before any switch write.
    EXPECT_EQ(service_->ForceEnableSilentAuthBundle(nullptr), ERR_ANS_INNER_INVALID_BUNDLE);
    // "testBundleName" is the mocked unresolvable bundle: rejected before any switch write.
    EXPECT_EQ(service_->ForceEnableSilentAuthBundle(BuildOption("testBundleName", 0)),
        ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name: SilentAuth_MarshallingOverLimit_001
 * @tc.desc: Marshalling a bundle list larger than 1000 items fails
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_MarshallingOverLimit_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth info;
    std::vector<std::string> overLimit(1001, "sa_item");
    info.SetBundleList(overLimit);
    Parcel parcel;
    EXPECT_FALSE(info.Marshalling(parcel));
}

/**
 * @tc.name: SilentAuth_ParcelCorruptedSize_001
 * @tc.desc: Unmarshalling a parcel with a corrupted (negative) list size returns nullptr
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_ParcelCorruptedSize_001, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteInt32(-1));
    EXPECT_TRUE(parcel.WriteInt32(TEST_USER_ID));
    EXPECT_EQ(NotificationSilentAuth::Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: SilentAuth_FromJsonSizeBoundary_001
 * @tc.desc: FromJson accepts exactly 1000 items and rejects 1001 (list cleared before reject)
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_FromJsonSizeBoundary_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth info;
    std::vector<std::string> maxList(1000, "sa_item");
    info.SetBundleList(maxList);
    NotificationSilentAuth out;
    out.FromJson(info.ToJson());
    EXPECT_EQ(out.GetBundleList().size(), 1000);
    // 1001 items exceed the limit: the previously parsed list is cleared and nothing is stored.
    std::vector<std::string> overList(1001, "sa_item");
    info.SetBundleList(overList);
    out.FromJson(info.ToJson());
    EXPECT_TRUE(out.GetBundleList().empty());
}

/**
 * @tc.name: SilentAuth_FromJsonInvalidTypes_001
 * @tc.desc: A non-array bundleList or non-string elements are skipped, userId is still parsed
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_FromJsonInvalidTypes_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth out;
    out.FromJson(R"({"bundleList": "not-an-array", "userId": 100})");
    EXPECT_TRUE(out.GetBundleList().empty());
    out.FromJson(R"({"bundleList": [1, 2], "userId": 100})");
    EXPECT_TRUE(out.GetBundleList().empty());
    EXPECT_EQ(out.GetUserId(), 100);
}

/**
 * @tc.name: SilentAuth_FromJsonUserIdOutOfRange_001
 * @tc.desc: An int64 userId outside the int32 range is rejected and keeps the default value
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_FromJsonUserIdOutOfRange_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth out;
    out.FromJson(R"({"bundleList": [], "userId": 5000000000})");
    EXPECT_EQ(out.GetUserId(), -1);
    out.FromJson(R"({"bundleList": [], "userId": -5000000000})");
    EXPECT_EQ(out.GetUserId(), -1);
}

/**
 * @tc.name: SilentAuth_FromJsonNonObject_001
 * @tc.desc: A json array or null literal is rejected and keeps the defaults
 */
HWTEST_F(AdvancedNotificationSilentAuthTest, SilentAuth_FromJsonNonObject_001, Function | SmallTest | Level1)
{
    NotificationSilentAuth out;
    out.FromJson("[1, 2, 3]");
    EXPECT_TRUE(out.GetBundleList().empty());
    out.FromJson("null");
    EXPECT_TRUE(out.GetBundleList().empty());
    EXPECT_EQ(out.GetUserId(), -1);
}
} // namespace Notification
} // namespace OHOS
