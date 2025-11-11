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

#include "reminder_request.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderRequestBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// const uint8_t ReminderRequestBranchTest::REMINDER_STATUS_SHOWING = 4;

/**
 * @tc.name: ShouldShowImmediately_00100
 * @tc.desc: ShouldShowImmediately.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, ShouldShowImmediately_00100, Function | SmallTest | Level1)
{
    ReminderRequest reminderRequest;
    bool ret = reminderRequest.ShouldShowImmediately();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ShouldShowImmediately_00200
 * @tc.desc: ShouldShowImmediately.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, ShouldShowImmediately_00200, Function | SmallTest | Level1)
{
    ReminderRequest reminderRequest;
    uint64_t triggerTimeInMilli = reminderRequest.GetNowInstantMilli() + 5 * 60 * 1000;
    reminderRequest.SetTriggerTimeInMilli(triggerTimeInMilli);
    bool ret = reminderRequest.ShouldShowImmediately();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CanShow_00100
 * @tc.desc: CanShow.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, CanShow_00100, Function | SmallTest | Level1)
{
    ReminderRequest reminderRequest;
    bool ret = reminderRequest.CanShow();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: HandleSysTimeChange_00100
 * @tc.desc: 1.Test HandleSysTimeChange function
 *           2.OriTriggerTime == 0 and optTriggerTime < now
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, HandleSysTimeChange_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    reminderRequest->isExpired_ = false;
    uint64_t oriTriggerTime = 0;
    uint64_t optTriggerTime = 1675876470000;
    EXPECT_EQ(reminderRequest->HandleSysTimeChange(oriTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: HandleSysTimeChange_00200
 * @tc.desc: 1.Test HandleSysTimeChange function
 *           2.OriTriggerTime == 0 and optTriggerTime > now
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, HandleSysTimeChange_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    reminderRequest->isExpired_ = false;
    uint64_t oriTriggerTime = 0;
    uint64_t optTriggerTime = 1675876480001;
    EXPECT_EQ(reminderRequest->HandleSysTimeChange(oriTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: HandleSysTimeChange_00300
 * @tc.desc: 1.Test HandleSysTimeChange function
 *           2.OriTriggerTime == optTriggerTime and optTriggerTime != 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, HandleSysTimeChange_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    reminderRequest->isExpired_ = false;
    uint64_t oriTriggerTime = 1675876480001;
    uint64_t optTriggerTime = 1675876480001;
    EXPECT_EQ(reminderRequest->HandleSysTimeChange(oriTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: HandleSysTimeChange_00400
 * @tc.desc: 1.Test HandleSysTimeChange function
 *           2.OriTriggerTime != 0 and optTriggerTime == 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, HandleSysTimeChange_00400, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    reminderRequest->isExpired_ = false;
    uint64_t oriTriggerTime = 1675876470000;
    uint64_t optTriggerTime = 0;
    EXPECT_EQ(reminderRequest->HandleSysTimeChange(oriTriggerTime, optTriggerTime), true);
}

/**
 * @tc.name: HandleSysTimeChange_00500
 * @tc.desc: 1.Test HandleSysTimeChange function
 *           2.OriTriggerTime > now and optTriggerTime == 0
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, HandleSysTimeChange_00500, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    reminderRequest->isExpired_ = false;
    uint64_t oriTriggerTime = reminderRequest->GetNowInstantMilli() + 5 * 60 * 1000;
    uint64_t optTriggerTime = 0;
    EXPECT_EQ(reminderRequest->HandleSysTimeChange(oriTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: UpdateNotificationRequest_00100
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.Type is UpdateNotificationType::COMMON
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze);
}

/**
 * @tc.name: UpdateNotificationRequest_00200
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.Type is UpdateNotificationType::REMOVAL_WANT_AGENT
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = false;
    reminderRequest->UpdateNotificationRequest(notificationRequest, false);
}

/**
 * @tc.name: UpdateNotificationRequest_00300
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.Type is UpdateNotificationType::WANT_AGENT
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->wantAgentInfo_ = std::make_shared<ReminderRequest::WantAgentInfo>();
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze);
}

/**
 * @tc.name: UpdateNotificationRequest_00400
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.Type is UpdateNotificationType::MAX_SCREEN_WANT_AGENT
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00400, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    reminderRequest->maxScreenWantAgentInfo_ = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze);
}

/**
 * @tc.name: UpdateNotificationRequest_00500
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.Type is UpdateNotificationType::BUNDLE_INFO
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00500, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze);
}

/**
 * @tc.name: UpdateNotificationRequest_00600
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.Type is UpdateNotificationType::CONTENT
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00600, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze);
}

/**
 * @tc.name: GetButtonInfo_00100
 * @tc.desc: 1.Test GetButtonInfo function
 *           2.IsFirst is true and buttonInfo.wantAgent is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, GetButtonInfo_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CLOSE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    EXPECT_NE(reminderRequest->SerializeButtonInfo(), "");
}

/**
 * @tc.name: GetButtonInfo_00200
 * @tc.desc: 1.Test GetButtonInfo function
 *           2.IsFirst is true and buttonInfo.wantAgent is not nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, GetButtonInfo_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    std::string title = "aa";
    std::string pkgName = "bb";
    std::string abilityName = "cc";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CLOSE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
    info.wantAgent->pkgName = pkgName;
    info.wantAgent->abilityName = abilityName;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    EXPECT_NE(reminderRequest->SerializeButtonInfo(), "");
}

/**
 * @tc.name: AddActionButtons_00100
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::CLOSE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string stringData = "aa";
    ReminderRequest::ActionButtonType buttonType = ReminderRequest::ActionButtonType::CLOSE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = stringData;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(buttonType, info));
    bool includeSnooze = true;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
}

/**
 * @tc.name: AddActionButtons_00200
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::SNOOZE and includeSnooze is true
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::SNOOZE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = true;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
}

/**
 * @tc.name: AddActionButtons_00300
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::SNOOZE and includeSnooze is false
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationIds = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "title";
    ReminderRequest::ActionButtonType actionButtonType_ = ReminderRequest::ActionButtonType::SNOOZE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType_, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
}

/**
 * @tc.name: AddActionButtons_00400
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::CUSTOM and button.second.wantAgent is nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00400, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CUSTOM;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
}

/**
 * @tc.name: AddActionButtons_00500
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::CUSTOM and button.second.wantAgent is not nullptr
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00500, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    std::string pkgName = "bb";
    std::string abilityName = "cc";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CUSTOM;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
    info.wantAgent->pkgName = pkgName;
    info.wantAgent->abilityName = abilityName;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
}

/**
 * @tc.name: AddActionButtons_00600
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::INVALID
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00600, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::INVALID;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
}

/**
 * @tc.name: UpdateNotificationCommon_00100
 * @tc.desc: 1.Test UpdateNotificationCommon function
 *           2.reminderType_ is ReminderRequest::ReminderType::TIMER
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationCommon_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::TIMER;
    reminderRequest->UpdateNotificationCommon(notificationRequest, false);
}

/**
 * @tc.name: UpdateNotificationCommon_00200
 * @tc.desc: 1.Test UpdateNotificationCommon function
 *           2.reminderType_ is ReminderRequest::ReminderType::ALARM
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationCommon_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::ALARM;
    reminderRequest->UpdateNotificationCommon(notificationRequest, false);
}

/**
 * @tc.name: UpdateNotificationCommon_00300
 * @tc.desc: 1.Test UpdateNotificationCommon function
 *           2.reminderType_ is ReminderRequest::ReminderType::INVALID
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationCommon_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::INVALID;
    reminderRequest->UpdateNotificationCommon(notificationRequest, false);
}

/**
 * @tc.name: UpdateNotificationBundleInfo_00100
 * @tc.desc: 1.Test UpdateNotificationBundleInfo function
 *           2.OwnerBundleName is empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationBundleInfo_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string ownerName = "";
    notificationRequest.SetOwnerBundleName(ownerName);
    reminderRequest->UpdateNotificationBundleInfo(notificationRequest);
}

/**
 * @tc.name: UpdateNotificationBundleInfo_00200
 * @tc.desc: 1.Test UpdateNotificationBundleInfo function
 *           2.OwnerBundleName is not empty
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationBundleInfo_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    EXPECT_NE(reminderRequest, nullptr);
    int32_t notificationId_ = 0;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string ownerName = "aa";
    notificationRequest.SetOwnerBundleName(ownerName);
    reminderRequest->UpdateNotificationBundleInfo(notificationRequest);
}
}
}
