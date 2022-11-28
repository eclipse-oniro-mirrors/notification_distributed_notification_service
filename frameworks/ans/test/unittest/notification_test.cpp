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
    std::string deviceId = "DeviceId";
    int32_t userId = 10;
    int32_t uid = 20;
    std::string label = "Lable";
    int32_t id = 30;
    sptr<NotificationRequest> request = nullptr;
    auto rrc = std::make_shared<Notification>(deviceId, request);
    std::string result = "DeviceId_10_20_Lable_30";
    EXPECT_EQ(rrc->GenerateNotificationKey(deviceId, userId, uid, label, id), result);
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
    std::string ret = "Notification{ key = DeviceId_-1_0__0, ledLightColor = 0, "
    "lockscreenVisbleness = 0, remindType = -1, isRemoveAllowed = true, sourceType = 0, "
    "deviceId = DeviceId, request = NotificationRequest{ notificationId = 0, "
    "slotType = 3, createTime = 0, deliveryTime = 0, autoDeletedTime = 0, settingsText = , "
    "creatorBundleName = , creatorPid = 0, creatorUid = 0, ownerBundleName = , "
    "ownerUid = 0, groupName = , statusBarText = , label = , shortcutId = , "
    "sortingKey = , groupAlertType = 0, color = 0, badgeNumber = 0, visiblenessType = 0, "
    "progressValue = 0, progressMax = 0, badgeStyle = 0, classification = , "
    "notificationContentType = 0, showDeliveryTime = false, tapDismissed = true, "
    "colorEnabled = false, alertOneTime = false, showStopwatch = false, isCountdown = false, "
    "inProgress = false, groupOverview = false, progressIndeterminate = false, "
    "unremovable = false, floatingIcon = false, onlyLocal = false, permitted = true, "
    "isAgent = false, removalWantAgent = null, maxScreenWantAgent = null, additionalParams = null, "
    "littleIcon = null, bigIcon = null, notificationContent = null, "
    "notificationTemplate = null, actionButtons = empty, messageUsers = empty, "
    "userInputHistory = empty, distributedOptions = NotificationDistributedOptions"
    "{ isDistributed = true, devicesSupportDisplay = [], devicesSupportOperate = [] }, "
    "notificationFlags = null, creatorUserId = -1, ownerUserId = -1, receiverUserId = -1 }, "
    "postTime = 0, sound = nullptr, vibrationStyle = [] }";
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

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
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
    EXPECT_EQ(rrc->ReadFromParcel(parcel), true);
}
}
}