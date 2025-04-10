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
#define protected public
#include "notification.h"
#undef private
#undef protected

#include "notification_request.h"
#include "parcel.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetBundleName_00001
 * @tc.desc: Test when request_ is nullptr get parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTest, GetBundleName_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    std::string ret = "";
    EXPECT_EQ(rrc->GetBundleName(), ret);
    EXPECT_EQ(rrc->GetCreateBundle(), ret);
    EXPECT_EQ(rrc->GetLabel(), ret);
    EXPECT_EQ(rrc->GetId(), -1);
    EXPECT_EQ(rrc->GetUid(), 0);
    EXPECT_EQ(rrc->GetPid(), 0);
    EXPECT_EQ(rrc->IsUnremovable(), false);
    EXPECT_EQ(rrc->IsGroup(), false);
    EXPECT_EQ(rrc->IsFloatingIcon(), false);
    EXPECT_EQ(rrc->GetUserId(), 0);
}

/**
 * @tc.name: GetLedLightColor_00001
 * @tc.desc: Test GetLedLightColor parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTest, GetLedLightColor_00001, Function | SmallTest | Level1)
{
    int32_t color = 10;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(deviceId, request);
    rrc->SetLedLightColor(color);
    EXPECT_EQ(rrc->GetLedLightColor(), color);
}

/**
 * @tc.name: GetLockscreenVisibleness_00001
 * @tc.desc: Test GetLockscreenVisibleness parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTest, GetLockscreenVisibleness_00001, Function | SmallTest | Level1)
{
    NotificationConstant::VisiblenessType visbleness = NotificationConstant::VisiblenessType::PUBLIC;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetLockScreenVisbleness(visbleness);
    EXPECT_EQ(rrc->GetLockscreenVisibleness(), visbleness);
}

/**
 * @tc.name: GetGroup_00001
 * @tc.desc: Test GetGroup parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetGroup_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    std::string ret = "";
    EXPECT_EQ(rrc->GetGroup(), ret);
}

/**
 * @tc.name: GetGroup_00002
 * @tc.desc: Test when request_ is not nullptr get parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetGroup_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    auto rrc = std::make_shared<Notification>(request);
    std::string ret = "";
    EXPECT_EQ(rrc->GetGroup(), ret);
    EXPECT_EQ(rrc->GetPid(), 0);
    EXPECT_EQ(rrc->IsUnremovable(), false);
    EXPECT_EQ(rrc->IsGroup(), false);
    EXPECT_EQ(rrc->IsFloatingIcon(), false);
}

/**
 * @tc.name: GetNotificationRequestPoint_00001
 * @tc.desc: Test GetNotificationRequestPoint parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetNotificationRequestPoint_00001, Function | SmallTest | Level1)
{
    int32_t notificationId = 10;
    sptr<NotificationRequest> request = new(std::nothrow) NotificationRequest(notificationId);
    auto rrc = std::make_shared<Notification>(request);
    EXPECT_EQ(rrc->GetNotificationRequestPoint()->GetNotificationId(), notificationId);
}

/**
 * @tc.name: GetPostTime_00001
 * @tc.desc: Test GetPostTime parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetPostTime_00001, Function | SmallTest | Level1)
{
    int64_t time = 10;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetPostTime(time);
    EXPECT_EQ(rrc->GetPostTime(), time);
}

/**
 * @tc.name: GetSound_00001
 * @tc.desc: Test GetSound parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetSound_00001, Function | SmallTest | Level1)
{
    Uri sound = Uri("sound");
    bool enable = true;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetSound(sound);
    rrc->SetEnableSound(enable);
    EXPECT_EQ(rrc->GetSound(), sound);
}

/**
 * @tc.name: GetVibrationStyle_00001
 * @tc.desc: Test GetVibrationStyle parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetVibrationStyle_00001, Function | SmallTest | Level1)
{
    std::vector<int64_t> style;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetVibrationStyle(style);
    EXPECT_EQ(rrc->GetVibrationStyle(), style);
}

/**
 * @tc.name: GetRemindType_00001
 * @tc.desc: Test GetRemindType parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetRemindType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::RemindType reminType = NotificationConstant::RemindType::NONE;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetRemindType(reminType);
    EXPECT_EQ(rrc->GetRemindType(), reminType);
}

/**
 * @tc.name: GenerateNotificationKey_00001
 * @tc.desc: Test GenerateNotificationKey parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GenerateNotificationKey_00001, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    int32_t uid = 20;
    std::string label = "Lable";
    int32_t id = 30;
    sptr<NotificationRequest> request = sptr<NotificationRequest>::MakeSptr();
    request->SetCreatorUid(uid);
    request->SetCreatorUserId(userId);
    request->SetLabel(label);
    request->SetNotificationId(id);
    request->SetCreatorBundleName("come.test");
    auto rrc = std::make_shared<Notification>(request);
    std::string result = "__10_20_come.test_Lable_30";
    EXPECT_EQ(rrc->GetKey(), result);
}

/**
 * @tc.name: GenerateNotificationKey_00002
 * @tc.desc: Test GenerateNotificationKey parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GenerateNotificationKey_00002, Function | SmallTest | Level1)
{
    std::string deviceId = "DeviceId";
    int32_t userId = 10;
    int32_t uid = 20;
    std::string label = "Lable";
    int32_t id = 30;
    sptr<NotificationRequest> request = sptr<NotificationRequest>::MakeSptr();
    request->SetIsAgentNotification(true);
    request->SetOwnerUid(uid);
    request->SetOwnerUserId(userId);
    request->SetLabel(label);
    request->SetNotificationId(id);
    request->SetCreatorBundleName("come.push");
    request->SetOwnerBundleName("come.test");
    auto rrc = std::make_shared<Notification>(deviceId, request);
    std::string result = "_DeviceId_10_20_come.test_Lable_30";
    EXPECT_EQ(rrc->GetKey(), result);
}

/**
 * @tc.name: IsRemoveAllowed_00001
 * @tc.desc: Test IsRemoveAllowed parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, IsRemoveAllowed_00001, Function | SmallTest | Level1)
{
    bool removeAllowed = true;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetRemoveAllowed(removeAllowed);
    EXPECT_EQ(rrc->IsRemoveAllowed(), removeAllowed);
}

/**
 * @tc.name: GetSourceType_00001
 * @tc.desc: Test GetSourceType parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetSourceType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SourceType sourceType = NotificationConstant::SourceType::TYPE_NORMAL;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetSourceType(sourceType);
    EXPECT_EQ(rrc->GetSourceType(), sourceType);
}

/**
 * @tc.name: GetDeviceId_00001
 * @tc.desc: Test GetDeviceId parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetDeviceId_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);
    EXPECT_EQ(rrc->GetDeviceId(), deviceId);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);
    std::string ret =  "Notification{ key = _DeviceId_-1_0___0, ledLightColor = 0, "
    "lockscreenVisbleness = 0, remindType = -1, isRemoveAllowed = true, sourceType = 0, "
    "deviceId = DeviceId, request = NotificationRequest{ notificationId = 0, slotType = 3, "
    "createTime = 0, deliveryTime = 0, autoDeletedTime = -1, settingsText = , "
    "creatorBundleName = , creatorPid = 0, creatorUid = 0, ownerBundleName = , "
    "ownerUid = 0, groupName = , statusBarText = , label = , shortcutId = , "
    "sortingKey = , groupAlertType = 0, color = 0, badgeNumber = 0, visiblenessType = 0, "
    "progressValue = 0, progressMax = 0, badgeStyle = 0, classification = , "
    "notificationContentType = 0, notificationControlFlags = 0, showDeliveryTime = false, "
    "tapDismissed = true, colorEnabled = false, alertOneTime = false, showStopwatch = false, "
    "isCountdown = false, inProgress = false, groupOverview = false, isRemoveAllowed = true, "
    "progressIndeterminate = false, unremovable = false, floatingIcon = false, onlyLocal = false, "
    "permitted = true, isAgent = false, updateOnly = false, isForceDistributed = false, "
    "isNotDistributed = false, removalWantAgent = null, maxScreenWantAgent = null, "
    "additionalParams = null, littleIcon = null, bigIcon = null, overlayIcon = null, "
    "notificationContent = null, notificationTemplate = null, actionButtons = empty, "
    "messageUsers = empty, userInputHistory = empty, distributedOptions = "
    "NotificationDistributedOptions{ isDistributed = true, devicesSupportDisplay = [], "
    "devicesSupportOperate = [] }, notificationFlags = null, notificationFlagsOfDevices = null, "
    "notificationBundleOption = null, agentBundle = null, creatorUserId = -1, ownerUserId = -1, "
    "receiverUserId = -1, updateDeadLine = 0, finishDeadLine = 0, sound = , distributed = 0: "
    "flag: 0, unifiedGroupInfo_ = null }, postTime = 0, "
    "sound = nullptr, vibrationStyle = [], updateTimer = 0, finishTimer = 0, archiveTimer = 0 }";
    EXPECT_EQ(rrc->Dump(), ret);
}

/**
 * @tc.name: MarshallingBool_00001
 * @tc.desc: Test MarshallingBool parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, MarshallingBool_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);
    EXPECT_EQ(rrc->MarshallingBool(parcel), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    std::shared_ptr<Notification> result =
    std::make_shared<Notification>(deviceId, request);
    result->Marshalling(parcel);

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);
    rrc->Marshalling(parcel);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), false);
}

/**
 * @tc.name: GetSound_00002
 * @tc.desc: Test GetSound parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetSound_00002, Function | SmallTest | Level1)
{
    Uri sound = Uri("sound");
    bool enable = false;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetSound(sound);
    rrc->SetEnableSound(enable);
    EXPECT_EQ(rrc->GetSound(), Uri(""));
}

/**
 * @tc.name: GetSound_00003
 * @tc.desc: Test GetSound parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetSound_00003, Function | SmallTest | Level1)
{
    Uri sound = Uri("");
    bool enable = true;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetSound(sound);
    rrc->SetEnableSound(enable);
    EXPECT_EQ(rrc->GetSound(), Uri(""));
}

/**
 * @tc.name: EnableLight_00001
 * @tc.desc: Test EnableLight parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, EnableLight_00001, Function | SmallTest | Level1)
{
    bool enable = true;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetEnableLight(enable);
    EXPECT_EQ(rrc->EnableLight(), enable);
}

/**
 * @tc.name: EnableSound_00001
 * @tc.desc: Test EnableSound parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, EnableSound_00001, Function | SmallTest | Level1)
{
    bool enable = true;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetEnableSound(enable);
    EXPECT_EQ(rrc->EnableSound(), enable);
    Parcel parcel;
    rrc->ReadFromParcelString(parcel);
}

/**
 * @tc.name: EnableVibrate_00001
 * @tc.desc: Test EnableVibrate parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, EnableVibrate_00001, Function | SmallTest | Level1)
{
    bool enable = true;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetEnableVibration(enable);
    EXPECT_EQ(rrc->EnableVibrate(), enable);
}

/**
 * @tc.name: GetBundleName_00002
 * @tc.desc: Test when request_ is nullptr get parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationTest, GetBundleName_00002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    auto rrc = std::make_shared<Notification>(request);
    std::string ret = "";
    EXPECT_EQ(rrc->GetBundleName(), ret);
    EXPECT_EQ(rrc->GetCreateBundle(), ret);
}

/**
 * @tc.name: GetSound_00004
 * @tc.desc: Test GetSound parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetSound_00004, Function | SmallTest | Level1)
{
    Uri sound = Uri("sound");
    bool enable = false;
    sptr<NotificationRequest> request = new NotificationRequest(1);
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetSound(sound);
    rrc->SetEnableSound(enable);
    EXPECT_EQ(rrc->GetSound(), Uri(""));
}

/**
 * @tc.name: GetSound_00005
 * @tc.desc: Test GetSound parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetSound_00005, Function | SmallTest | Level1)
{
    Uri sound = Uri("sound");
    bool enable = true;
    sptr<NotificationRequest> request = new NotificationRequest(1);
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetSound(sound);
    rrc->SetEnableSound(enable);
    EXPECT_EQ(rrc->GetSound(), Uri("sound"));
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationTest, Marshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);

    bool enable = true;
    auto sound = std::make_shared<Uri>("sound");
    rrc->SetSound(*sound);
    rrc->SetEnableSound(enable);

    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Marshalling_00003
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBHI
 */
HWTEST_F(NotificationTest, Marshalling_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    std::string deviceId = "DeviceId";
    sptr<NotificationRequest> request = new NotificationRequest();
    auto rrc = std::make_shared<Notification>(deviceId, request);

    bool enable = false;
    auto sound = std::make_shared<Uri>("sound");
    rrc->SetSound(*sound);
    rrc->SetEnableSound(enable);

    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: GetUpdateTimer_00001
 * @tc.desc: Test get update timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetUpdateTimer_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetUpdateTimer(1);
    EXPECT_EQ(rrc->GetUpdateTimer(), 1);
}

/**
 * @tc.name: GetFinishTimer_00001
 * @tc.desc: Test get finish timer.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationTest, GetFinishTimer_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    auto rrc = std::make_shared<Notification>(request);
    rrc->SetFinishTimer(1);
    EXPECT_EQ(rrc->GetFinishTimer(), 1);
}
} // namespace Notification
} // namespace OHOS
