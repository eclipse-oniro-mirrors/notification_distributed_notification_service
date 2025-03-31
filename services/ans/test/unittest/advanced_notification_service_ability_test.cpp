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
#define private public
#define protected public
#include "advanced_notification_service_ability.h"
#include "notification_preferences.h"
#include "distributed_device_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
const int ANS_CLONE_ERROR = -1;
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
    AdvancedNotificationServiceAbility(systemAbilityId, runOnCreate);
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
    EXPECT_EQ(ret, (int)ERR_OK);
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

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
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
}  // namespace Notification
}  // namespace OHOS
