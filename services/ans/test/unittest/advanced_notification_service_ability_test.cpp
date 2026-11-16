/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <functional>
#include <gtest/gtest.h>
#include "ans_ut_constant.h"
#include "mock_common_event_manager.h"
#include "mock_ipc_skeleton.h"

namespace OHOS {
namespace Notification {
extern void MockVerifyCallerPermission(bool isVerify);
}
}

#define private public
#define protected public
#include "advanced_notification_service_ability.h"
#include "notification_preferences.h"
#include "distributed_device_manager.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "nlohmann/json.hpp"
#include "os_account_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace AccountSA {
// The real QueryActiveOsAccountIds depends on the device os_account service, which
// is not healthy on the x86 emulator. Mock it locally so the default user recovery
// deterministically enumerates one active user.
ErrCode OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t> &ids)
{
    ids = {100};
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

namespace OHOS {
namespace Notification {
const int ANS_CLONE_ERROR = -1;

namespace {
constexpr int32_t RECOVER_TEST_USER_ID = 100;

// An expired live view row still counts as a processed recovery entry: the record is
// cleaned from DB and the batch is reported as success.
std::string BuildExpiredLiveViewRow()
{
    nlohmann::json row = {
        { "slotType", static_cast<int32_t>(NotificationConstant::SlotType::LIVE_VIEW) },
        { "notificationContentType", static_cast<int32_t>(NotificationContent::Type::LIVE_VIEW) },
        { "updateDeadLine", 1 },
        { "finishDeadLine", 1 },
        { "triggerDeadLine", 1 },
    };
    return row.dump();
}
}  // namespace

class AdvancedNotificationServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00100
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0100
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EXPECT_FALSE(test.isDatashaReready_);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00200
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0200
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00200, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
    EXPECT_FALSE(test.isDatashaReready_);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00300
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0300
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStop();
    test.OnStart();
    EXPECT_FALSE(test.isDatashaReready_);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00400
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0400
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00400, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string extension = "backup";
    MessageParcel data;
    MessageParcel reply;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    ErrCode ret = test.OnExtension(extension, data, reply);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00500
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0500
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00500, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string extension = "restore";
    MessageParcel data;
    MessageParcel reply;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnStart();
    ErrCode ret = test.OnExtension(extension, data, reply);
    EXPECT_EQ(ret, (int)ANS_CLONE_ERROR);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00600
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0600
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00600, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, deviceId);
    EXPECT_EQ(test.isDatashaReready_, true);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00700
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0700
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00700, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, deviceId);
    test.OnAddSystemAbility(COMMON_EVENT_SERVICE_ID, deviceId);
    test.OnRemoveSystemAbility(COMMON_EVENT_SERVICE_ID, deviceId);
    EXPECT_EQ(test.isDatashaReready_, true);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00800
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_0800
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00800, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    std::string oldKey = "enabledNotificationDistributed-test-88-aaa";
    NotificationPreferences::GetInstance()->SetKvToDb(oldKey, "1", 0);
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnAddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, deviceId);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::string version;
    NotificationPreferences::GetInstance()->GetKvFromDb("tableVersion", version, 0);
    ASSERT_EQ(version, "1");
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_00900
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_00900
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_00900, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    std::string extension = "other";
    MessageParcel data;
    MessageParcel reply;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    ErrCode ret = test.OnExtension(extension, data, reply);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_01000
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_01000
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_01000, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction("usual.event.DATA_SHARE_READY"));
    test.OnReceiveEvent(data);
    EXPECT_EQ(test.isDatashaReready_, true);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_01100
 * @tc.name      : AdvancedNotificationServiceAbilityTest_01100
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_01100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction("usual.event.TIME_CHANGED"));
    test.OnReceiveEvent(data);
    EXPECT_EQ(test.isDatashaReready_, false);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_01200
 * @tc.name      : AdvancedNotificationServiceAbilityTest_01200
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_01200, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction("usual.event.PACKAGE_REMOVED"));
    test.OnReceiveEvent(data);
    EXPECT_EQ(test.isDatashaReready_, false);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_01300
 * @tc.name      : AdvancedNotificationServiceAbilityTest_01300
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_01300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction("usual.event.USER_REMOVED"));
    test.OnReceiveEvent(data);
    EXPECT_EQ(test.isDatashaReready_, false);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_01400
 * @tc.name      : AdvancedNotificationServiceAbilityTest_01400
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_01400, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EventFwk::Want want;
    EventFwk::CommonEventData data;
    data.SetWant(want.SetAction("usual.event.TIMEZONE_CHANGED"));
    test.OnReceiveEvent(data);
    EXPECT_EQ(test.isDatashaReready_, false);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_01500
 * @tc.name      : AdvancedNotificationServiceAbilityTest_01500
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_01500, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.SubscribeCommonEvent();
    EXPECT_EQ(test.isDatashaReready_, false);
}

#ifdef ALL_SCENARIO_COLLABORATION
/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_02000
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_02000
 * @tc.desc      : Structure AdvancedNotificationServiceAbility with systemAbilityId and runOnCreate
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_02000, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    test.OnAddSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, deviceId);

    ASSERT_NE(DistributedDeviceManager::GetInstance().stateCallback_, nullptr);
}
#endif

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_02100
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_02100
 * @tc.desc      : SubscribeCommonEvent returns true without re-subscribing when subscriber_ already exists
 *                 (CES re-online idempotent guard, BR-9 / design ADR-2)
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_02100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.DATA_SHARE_READY");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    test.subscriber_ = std::make_shared<SystemEventSubscriber>(
        subscribeInfo, [](const EventFwk::CommonEventData &) {});
    auto subscriberBefore = test.subscriber_;
    ASSERT_NE(subscriberBefore, nullptr);
    // subscribe API mocked as failed: guard must short-circuit before calling it
    MockSubscribeCommonEventResult(false);
    EXPECT_TRUE(test.SubscribeCommonEvent());
    EXPECT_EQ(test.subscriber_, subscriberBefore);
    MockSubscribeCommonEventResult(true);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_02200
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_02200
 * @tc.desc      : SubscribeCommonEvent resets subscriber_ to nullptr on subscribe failure and retries on next call
 *                 (design ADR-2 failure-retry path, fixes ignored return value)
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_02200, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    MockSubscribeCommonEventResult(false);
    EXPECT_FALSE(test.SubscribeCommonEvent());
    EXPECT_EQ(test.subscriber_, nullptr);
    MockSubscribeCommonEventResult(true);
    EXPECT_TRUE(test.SubscribeCommonEvent());
    EXPECT_NE(test.subscriber_, nullptr);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_02300
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_02300
 * @tc.desc      : OnExtension restore callback without a valid backup fd returns clone error instead of
 *                 crashing (backup/restore pair guard, AC-5.1)
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_02300, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string extension = "restore";
    MessageParcel data;
    MessageParcel reply;
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    ErrCode ret = test.OnExtension(extension, data, reply);
    EXPECT_EQ(ret, ANS_CLONE_ERROR);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_02400
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_02400
 * @tc.desc      : OnAddSystemAbility(BMS) takes the early-return guard when datashare is not ready
 *                 (STATE-1 guard ordering; BMS online path completes without side effects)
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_02400, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 1;
    bool runOnCreate = true;
    std::string deviceId = "deviceId";
    AdvancedNotificationServiceAbility test(systemAbilityId, runOnCreate);
    EXPECT_FALSE(test.isDatashaReready_);
    test.OnAddSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID, deviceId);
    EXPECT_FALSE(test.isDatashaReready_);
}

/**
 * @tc.number    : AdvancedNotificationServiceAbilityTest_02500
 * @tc.name      : ANS_AdvancedNotificationServiceAbility_02500
 * @tc.desc      : OnStart recovers persisted live view records without waiting for USER_SWITCHED, so a
 *                 manually killed process restores third-party live views on restart (issue#4502)
 */
HWTEST_F(
    AdvancedNotificationServiceAbilityTest, AdvancedNotificationServiceAbilityTest_02500, Function | SmallTest | Level1)
{
    auto service = AdvancedNotificationService::GetInstance();
    ASSERT_NE(service, nullptr);
    service->notificationSvrQueue_.SyncSubmit(std::function<void()>([] {}));
    service->recoveredLiveViewUserIds_.clear();
    service->recoverReplayUserIds_.clear();

    const std::string plainKey = "ans_live_view_restart_recover_key";
    ASSERT_EQ(NotificationPreferences::GetInstance()->SetKvToDb(
        plainKey, BuildExpiredLiveViewRow(), RECOVER_TEST_USER_ID), ERR_OK);
    (void)NotificationPreferences::GetInstance()->DeleteKvFromDb("ans_recover_fail_count", RECOVER_TEST_USER_ID);

    AdvancedNotificationServiceAbility test(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID, true);
    test.service_ = service;
    test.RecoverLiveViewOnStart();
    service->notificationSvrQueue_.SyncSubmit(std::function<void()>([] {}));

    EXPECT_EQ(service->recoveredLiveViewUserIds_.count(RECOVER_TEST_USER_ID), 1U);
    std::string value;
    EXPECT_NE(NotificationPreferences::GetInstance()->GetKvFromDb(plainKey, value, RECOVER_TEST_USER_ID), ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
