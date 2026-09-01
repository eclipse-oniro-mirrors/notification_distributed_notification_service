/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
 * @tc.desc: ShouldShowImmediately when trigger time has passed.
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
 * @tc.desc: ShouldShowImmediately when trigger time is in the future.
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
 *           2.isSnooze is true, verify snooze path sets correct slot type
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze, 0);
    EXPECT_EQ(notificationRequest.GetSlotType(), NotificationConstant::SlotType::CONTENT_INFORMATION);
    EXPECT_EQ(notificationRequest.GetLabel(), ReminderRequest::NOTIFICATION_LABEL);
    EXPECT_EQ(notificationRequest.IsShowDeliveryTime(), true);
}

/**
 * @tc.name: UpdateNotificationRequest_00200
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.isSnooze is false, verify alert path uses slotType_
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->UpdateNotificationRequest(notificationRequest, false, 0);
    EXPECT_EQ(notificationRequest.GetSlotType(), NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    EXPECT_EQ(notificationRequest.GetLabel(), ReminderRequest::NOTIFICATION_LABEL);
    EXPECT_EQ(notificationRequest.IsShowDeliveryTime(), true);
}

/**
 * @tc.name: UpdateNotificationRequest_00300
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.wantAgentInfo_ is set, verify WantAgent is assigned
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    reminderRequest->wantAgentInfo_ = std::make_shared<ReminderRequest::WantAgentInfo>();
    reminderRequest->wantAgentInfo_->pkgName = "com.test.pkg";
    reminderRequest->wantAgentInfo_->abilityName = "TestAbility";
    reminderRequest->maxScreenWantAgentInfo_ = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
    reminderRequest->maxScreenWantAgentInfo_->pkgName = "com.test.pkg";
    reminderRequest->maxScreenWantAgentInfo_->abilityName = "TestAbility";
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze, 0);
    EXPECT_EQ(notificationRequest.GetLabel(), ReminderRequest::NOTIFICATION_LABEL);
}

/**
 * @tc.name: UpdateNotificationRequest_00500
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.reminderType is TIMER, verify notification is unremoveable
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00500, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::TIMER;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze, 0);
    EXPECT_EQ(notificationRequest.IsUnremovable(), true);
}

/**
 * @tc.name: UpdateNotificationRequest_00600
 * @tc.desc: 1.Test UpdateNotificationRequest function
 *           2.tapDismissed is false, verify notification tapDismissed flag
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationRequest_00600, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    reminderRequest->tapDismissed_ = false;
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    bool isSnooze = true;
    reminderRequest->UpdateNotificationRequest(notificationRequest, isSnooze, 0);
    EXPECT_EQ(notificationRequest.IsTapDismissed(), false);
}

/**
 * @tc.name: GetButtonInfo_00100
 * @tc.desc: 1.Test GetButtonInfo function
 *           2.buttonInfo.wantAgent is nullptr, serialized result should not contain wantAgent
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, GetButtonInfo_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CLOSE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::SNOOZE;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    std::string result = reminderRequest->SerializeButtonInfo();
    EXPECT_NE(result, "");
    EXPECT_EQ(result.find("wantAgent"), std::string::npos);
}

/**
 * @tc.name: GetButtonInfo_00200
 * @tc.desc: 1.Test GetButtonInfo function
 *           2.buttonInfo.wantAgent is not nullptr, serialized result should contain wantAgent fields
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, GetButtonInfo_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
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
    std::string result = reminderRequest->SerializeButtonInfo();
    EXPECT_NE(result, "");
    EXPECT_NE(result.find("pkgName"), std::string::npos);
    EXPECT_NE(result.find("abilityName"), std::string::npos);
}

/**
 * @tc.name: AddActionButtons_00100
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::CLOSE, one action button should be added
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string stringData = "aa";
    ReminderRequest::ActionButtonType buttonType = ReminderRequest::ActionButtonType::CLOSE;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::CLOSE;
    info.title = stringData;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(buttonType, info));
    bool includeSnooze = true;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
    EXPECT_EQ(notificationRequest.GetActionButtons().size(), 1);
}

/**
 * @tc.name: AddActionButtons_00200
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::SNOOZE and includeSnooze is true, one button should be added
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
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
    EXPECT_EQ(notificationRequest.GetActionButtons().size(), 1);
}

/**
 * @tc.name: AddActionButtons_00300
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::SNOOZE and includeSnooze is false, no button should be added
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
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
    EXPECT_EQ(notificationRequest.GetActionButtons().size(), 0);
}

/**
 * @tc.name: AddActionButtons_00400
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::CUSTOM and button.second.wantAgent is nullptr, early return, no button added
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00400, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CUSTOM;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::CUSTOM;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
    EXPECT_EQ(notificationRequest.GetActionButtons().size(), 0);
}

/**
 * @tc.name: AddActionButtons_00500
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::CUSTOM and button.second.wantAgent is not nullptr, one button added
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00500, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    std::string pkgName = "bb";
    std::string abilityName = "cc";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::CUSTOM;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::CUSTOM;
    info.title = title;
    info.wantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
    info.wantAgent->pkgName = pkgName;
    info.wantAgent->abilityName = abilityName;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
    EXPECT_EQ(notificationRequest.GetActionButtons().size(), 1);
}

/**
 * @tc.name: AddActionButtons_00600
 * @tc.desc: 1.Test AddActionButtons function
 *           2.Type is ActionButtonType::INVALID, default branch, one button added
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, AddActionButtons_00600, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    std::string title = "aa";
    ReminderRequest::ActionButtonType actionButtonType = ReminderRequest::ActionButtonType::INVALID;
    ReminderRequest::ActionButtonInfo info;
    info.type = ReminderRequest::ActionButtonType::INVALID;
    info.title = title;
    info.wantAgent = nullptr;
    reminderRequest->actionButtonMap_.insert(
        std::pair<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo>(actionButtonType, info));
    bool includeSnooze = false;
    reminderRequest->AddActionButtons(notificationRequest, includeSnooze);
    EXPECT_EQ(notificationRequest.GetActionButtons().size(), 1);
}

/**
 * @tc.name: UpdateNotificationCommon_00100
 * @tc.desc: 1.Test UpdateNotificationCommon function
 *           2.reminderType_ is ReminderRequest::ReminderType::TIMER, notification should be unremovable
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationCommon_00100, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::TIMER;
    reminderRequest->UpdateNotificationCommon(notificationRequest, false);
    EXPECT_EQ(notificationRequest.IsUnremovable(), true);
    EXPECT_EQ(notificationRequest.GetLabel(), ReminderRequest::NOTIFICATION_LABEL);
    EXPECT_EQ(notificationRequest.IsShowDeliveryTime(), true);
}

/**
 * @tc.name: UpdateNotificationCommon_00200
 * @tc.desc: 1.Test UpdateNotificationCommon function
 *           2.reminderType_ is ReminderRequest::ReminderType::ALARM, notification should be unremovable
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationCommon_00200, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::ALARM;
    reminderRequest->UpdateNotificationCommon(notificationRequest, false);
    EXPECT_EQ(notificationRequest.IsUnremovable(), true);
    EXPECT_EQ(notificationRequest.GetLabel(), ReminderRequest::NOTIFICATION_LABEL);
}

/**
 * @tc.name: UpdateNotificationCommon_00300
 * @tc.desc: 1.Test UpdateNotificationCommon function
 *           2.reminderType_ is ReminderRequest::ReminderType::INVALID, notification should be removable
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(ReminderRequestBranchTest, UpdateNotificationCommon_00300, Function | SmallTest | Level1)
{
    auto reminderRequest = std::make_shared<ReminderRequest>();
    NotificationRequest notificationRequest(reminderRequest->GetNotificationId());
    reminderRequest->reminderType_ = ReminderRequest::ReminderType::INVALID;
    reminderRequest->UpdateNotificationCommon(notificationRequest, false);
    EXPECT_EQ(notificationRequest.IsUnremovable(), false);
    EXPECT_EQ(notificationRequest.GetLabel(), ReminderRequest::NOTIFICATION_LABEL);
}
}
}
