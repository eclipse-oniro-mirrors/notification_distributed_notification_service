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

#include "ans_inner_errors.h"
#include "iservice_registry.h"
#include "notification_bundle_icon_info.h"
#include "notification_helper.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace {
// Legal business error codes of the new interfaces. NotificationHelper converts inner error codes
// to native error codes before returning (see SERVICE_ERROR_CONVERT_TABLE in ans_service_errors.cpp),
// so the legal set must be native codes.
bool IsLegalBusinessCode(ErrCode code)
{
    return code == ERR_OK ||
        code == ERR_ANS_PERMISSION_DENIED ||
        code == ERR_ANS_INVALID_PARAM ||
        code == ERR_ANS_INVALID_BUNDLE_OPTION ||
        code == ERR_ANS_DEVICE_NOT_SUPPORT ||
        code == ERR_ANS_SERVICE_NOT_CONNECTED;
}

// Codes a rejection-space operation (never-granted bundle / empty bundle name) may legitimately
// return to this non-companion XTS process. ERR_OK is deliberately excluded: a disable or icon
// query that unexpectedly succeeds on this process indicates an authorization defect.
bool IsExpectedRejection(ErrCode code)
{
    return code == ERR_ANS_PERMISSION_DENIED ||
        code == ERR_ANS_INVALID_PARAM ||
        code == ERR_ANS_INVALID_BUNDLE_OPTION ||
        code == ERR_ANS_DEVICE_NOT_SUPPORT ||
        code == ERR_ANS_SERVICE_NOT_CONNECTED;
}
}  // namespace

class AnsWearableCooperationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.number: AnsWearableCooperation_GetServiceObject_0000
 * @tc.name: Get ANS service object
 * @tc.desc: Precondition for all smoke cases: the ANS service is reachable.
 */
HWTEST_F(AnsWearableCooperationTest, AnsWearableCooperation_GetServiceObject_0000, Function | MediumTest | Level0)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_NE(systemAbilityManager, nullptr);

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    EXPECT_NE(remoteObject, nullptr);
}

/**
 * @tc.number: DisableGrantedBundle_E2E_00001
 * @tc.name: Disable granted bundle cooperation from wearable companion side
 * @tc.desc: Smoke coverage of the disable API chain from a NON-companion process. AC-2.1/AC-2.3
 *   delivery behaviour (onReceiveMessage stops for the disabled bundle) requires the real-device
 *   prerequisites below and is NOT asserted here:
 *   1. A wearable companion app (NotificationSubscriberExtensionAbility) is installed and subscribed.
 *   2. The user has granted notification cooperation for bundle A and B in settings.
 *   3. The companion app calls disableUserGrantedByBundle(A) and publishes a notification of A:
 *      onReceiveMessage must not receive A's notification while B still works.
 * Automated part (this process): both an empty bundle name and a never-granted bundle must be
 *   rejected (never succeed), and the granted-list query stays consistent on rejection (atomicity).
 */
HWTEST_F(AnsWearableCooperationTest, DisableGrantedBundle_E2E_00001, Function | MediumTest | Level0)
{
    std::vector<sptr<NotificationBundleOption>> before;
    ErrCode getResult = NotificationHelper::GetUserGrantedEnabledBundlesForSelf(before);
    EXPECT_TRUE(IsLegalBusinessCode(getResult));

    NotificationBundleOption emptyName("", -1);
    ErrCode emptyResult = NotificationHelper::DisableUserGrantedByBundle(emptyName);
    EXPECT_TRUE(IsExpectedRejection(emptyResult));

    // This process is not the companion app: a never-granted bundle must never be disabled
    // through it, so a success return here is an authorization defect, not a pass.
    NotificationBundleOption toDisable("com.ohos.wearable.notgranted", -1);
    ErrCode setResult = NotificationHelper::DisableUserGrantedByBundle(toDisable);
    EXPECT_TRUE(IsExpectedRejection(setResult));
    if (setResult == ERR_ANS_INVALID_BUNDLE_OPTION) {
        std::vector<sptr<NotificationBundleOption>> after;
        ErrCode afterResult = NotificationHelper::GetUserGrantedEnabledBundlesForSelf(after);
        EXPECT_TRUE(IsLegalBusinessCode(afterResult));
        EXPECT_EQ(after.size(), before.size());
    }
}

/**
 * @tc.number: HfpDisconnected_Notify_E2E_00001
 * @tc.name: Notification cooperation continues when HFP disconnects while BLE stays connected
 * @tc.desc: API smoke after HFP decoupling. AC-3.1 delivery behaviour (notification still received
 *   on HFP disconnect while BLE stays) requires the real-device prerequisites below and is NOT
 *   asserted here:
 *   1. Wearable device connected to phone via both BLE(GATT) and HFP links.
 *   2. Companion app subscribed and notifications are being cooperated (onReceiveMessage works).
 *   3. Disconnect ONLY the HFP link (keep BLE), publish a notification: onReceiveMessage must
 *      still receive it without re-subscribing.
 * Automated part (this process): the icon query chain is reachable after HFP decoupling and a
 *   never-granted bundle is rejected without ever yielding an icon.
 */
HWTEST_F(AnsWearableCooperationTest, HfpDisconnected_Notify_E2E_00001, Function | MediumTest | Level0)
{
    sptr<NotificationBundleIconInfo> bundleIcon = nullptr;
    ErrCode result = NotificationHelper::GetUserGrantedBundleIcon("com.ohos.wearable.notgranted", bundleIcon);
    EXPECT_TRUE(IsExpectedRejection(result));
    EXPECT_EQ(bundleIcon, nullptr);
}

/**
 * @tc.number: AllDisconnected_Notify_E2E_00001
 * @tc.name: Notification cooperation stops when all bluetooth links disconnect
 * @tc.desc: API smoke. AC-3.2 regression behaviour (onReceiveMessage stops when all links are
 *   disconnected) requires the real-device prerequisites below and is NOT asserted here:
 *   disconnect both BLE and HFP links, publish a notification: onReceiveMessage must NOT
 *   receive it (existing stop-on-disconnect behavior is preserved after HFP decoupling).
 * Automated part (this process): the query APIs keep returning legal codes when links are down
 *   and an empty bundle name is rejected without ever yielding an icon.
 */
HWTEST_F(AnsWearableCooperationTest, AllDisconnected_Notify_E2E_00001, Function | MediumTest | Level0)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode result = NotificationHelper::GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_TRUE(IsLegalBusinessCode(result));

    sptr<NotificationBundleIconInfo> bundleIcon = nullptr;
    ErrCode iconResult = NotificationHelper::GetUserGrantedBundleIcon("", bundleIcon);
    EXPECT_TRUE(IsExpectedRejection(iconResult));
    EXPECT_EQ(bundleIcon, nullptr);
}
}  // namespace Notification
}  // namespace OHOS
