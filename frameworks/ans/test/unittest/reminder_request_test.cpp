/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "reminder_request.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ReminderRequestChild : public ReminderRequest {
public:
    ReminderRequestChild() : ReminderRequest() {};
};

class ReminderRequestTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}

    static const uint8_t REMINDER_STATUS_SHOWING;
};

const uint8_t ReminderRequestTest::REMINDER_STATUS_SHOWING = 4;

/**
 * @tc.name: CanRemove_00100
 * @tc.desc: When reminder init, CanRemove should return true.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, CanRemove_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_TRUE(rrc->CanRemove()) << "When init, canRemove should be false";
}

/**
 * @tc.name: CanRemove_00200
 * @tc.desc: When reminder is shown, CanRemove should return false.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, CanRemove_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, false, true);
    EXPECT_FALSE(rrc->CanRemove()) << "When shown, canRemove should be false";
}

/**
 * @tc.name: CanRemove_00300
 * @tc.desc: When reminder close, CanRemove should return true.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, CanRemove_00300, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, false, true);
    rrc->OnClose(false);
    EXPECT_TRUE(rrc->CanRemove()) << "When reminder is expired and closed, can remove should be false";
}

/**
 * @tc.name: CanRemove_00400
 * @tc.desc: When reminder is covered as same notification id, CanRemove should return true.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF AR000GH8E6
 */
HWTEST_F(ReminderRequestTest, CanRemove_00400, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, false, true);
    rrc->OnSameNotificationIdCovered();
    EXPECT_TRUE(rrc->CanRemove()) << "When reminder is expired and covered by \
        sameNotification id, can remove should be true";
}

/**
 * @tc.name: StateCheck_00100
 * @tc.desc: When reminder init, state should be 0.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetState(), 0) << "When init, state should be 0";
}

/**
 * @tc.name: StateCheck_00200
 * @tc.desc: When reminder close with param true, state REMINDER_STATUS_SHOWING should be unset.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnClose(true);
    EXPECT_TRUE((rrc->GetState() & ReminderRequestTest::REMINDER_STATUS_SHOWING) == 0);
}

/**
 * @tc.name: StateCheck_00300
 * @tc.desc: When reminder close with param false, state REMINDER_STATUS_SHOWING should be unset.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00300, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnClose(false);
    EXPECT_TRUE((rrc->GetState() & ReminderRequestTest::REMINDER_STATUS_SHOWING) == 0);
}

/**
 * @tc.name: StateCheck_00400
 * @tc.desc: When reminder is covered as same notification id, state REMINDER_STATUS_SHOWING should be unset.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF AR000GH8E6
 */
HWTEST_F(ReminderRequestTest, StateCheck_00400, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnSameNotificationIdCovered();
    EXPECT_TRUE((rrc->GetState() & ReminderRequestTest::REMINDER_STATUS_SHOWING) == 0);
}

/**
 * @tc.name: StateCheck_00500
 * @tc.desc: When reminder is shown with param true,true, state REMINDER_STATUS_SHOWING should be set.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00500, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, true, true);
    EXPECT_TRUE((rrc->GetState() & ReminderRequestTest::REMINDER_STATUS_SHOWING) != 0);
}

/**
 * @tc.name: StateCheck_00600
 * @tc.desc: When reminder is shown with param false,true, state REMINDER_STATUS_SHOWING should be set.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00600, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, false, true);
    EXPECT_TRUE((rrc->GetState() & ReminderRequestTest::REMINDER_STATUS_SHOWING) != 0);
}

/**
 * @tc.name: StateCheck_00700
 * @tc.desc: When reminder is shown with param true,false, state REMINDER_STATUS_SHOWING should not change.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00700, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    uint8_t stateBefore = rrc->GetState();
    rrc->OnShow(false, true, false);
    EXPECT_EQ(rrc->GetState(), stateBefore);
}

/**
 * @tc.name: StateCheck_00800
 * @tc.desc: When reminder is shown with param false,false, state REMINDER_STATUS_SHOWING should be unset.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, StateCheck_00800, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    uint8_t stateBefore = rrc->GetState();
    rrc->OnShow(false, false, false);
    EXPECT_EQ(rrc->GetState(), stateBefore);
}

/**
 * @tc.name: initReminderId_00100
 * @tc.desc: When reminder create successfully, system should assign unique id to reminder.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF AR000GH8E6
 */
HWTEST_F(ReminderRequestTest, initReminderId_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->InitReminderId();
    int32_t reminderIdBefore = rrc->GetReminderId();
    rrc->InitReminderId();
    int32_t reminderIdAfter = rrc->GetReminderId();
    EXPECT_EQ((reminderIdAfter - reminderIdBefore), 1);
}

/**
 * @tc.name: setContent_00100
 * @tc.desc: Test SetContent with normal parameters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, setContent_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string content = "this is normal content";
    rrc->SetContent(content);
    EXPECT_EQ(rrc->GetContent(), content);
}

/**
 * @tc.name: setContent_00200
 * @tc.desc: Test SetContent parameters with special characters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, setContent_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string content = "this is content with special characters: ~!@#$%^&*()-+";
    rrc->SetContent(content);
    EXPECT_EQ(rrc->GetContent(), content);
}

/**
 * @tc.name: setExpiredContent_00100
 * @tc.desc: Test SetExpiredContent with normal parameters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF AR000GNF1U AR000GNF1U
 */
HWTEST_F(ReminderRequestTest, setExpiredContent_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string content = "this is normal content";
    rrc->SetExpiredContent(content);
    EXPECT_EQ(rrc->GetExpiredContent(), content);
}

/**
 * @tc.name: setExpiredContent_00200
 * @tc.desc: Test SetExpiredContent with special characters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF AR000GNF1U AR000GNF1U
 */
HWTEST_F(ReminderRequestTest, setExpiredContent_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string content = "this is content with special characters: ~!@#$%^&*()-+";
    rrc->SetExpiredContent(content);
    EXPECT_EQ(rrc->GetExpiredContent(), content);
}

/**
 * @tc.name: setTitle_00100
 * @tc.desc: Test SetTitle with normal parameters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, setTitle_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string content = "this is normal content";
    rrc->SetTitle(content);
    EXPECT_EQ(rrc->GetTitle(), content);
}

/**
 * @tc.name: setTitle_00200
 * @tc.desc: Test SetTitle with special characters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, setTitle_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string content = "this is content with special characters: ~!@#$%^&*()-+";
    rrc->SetTitle(content);
    EXPECT_EQ(rrc->GetTitle(), content);
}

/**
 * @tc.name: setNotificationId_00100
 * @tc.desc: Test SetNotificationId parameters.
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderRequestTest, setNotificationId_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    int32_t notificationId = 0;
    rrc->SetNotificationId(notificationId);
    EXPECT_EQ(rrc->GetNotificationId(), notificationId);
}

/**
 * @tc.name: setSnoozeTimes_00100
 * @tc.desc: Test SetSnoozeTimes parameters.
 * @tc.type: FUNC
 * @tc.require: AR000GNF1T AR000GH8E7
 */
HWTEST_F(ReminderRequestTest, setSnoozeTimes_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1) << "Get snoozeTimes not 1";
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1) << "Get snoozeTimesDynamic not 1";
}

/**
 * @tc.name: setTimeInterval_00100
 * @tc.desc: Test SetTimeInterval parameters.
 * @tc.type: FUNC
 * @tc.require: AR000GNF1T
 */
HWTEST_F(ReminderRequestTest, setTimeInterval_00100, Function | SmallTest | Level1)
{
    uint32_t minTimeIntervalInSecond = 5 * 60;
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetTimeInterval(-1);
    EXPECT_EQ(rrc->GetTimeInterval(), 0) << "timeInterval should be 0 when set with value less than 0";
    rrc->SetTimeInterval(0);
    EXPECT_EQ(rrc->GetTimeInterval(), 0) << "timeInterval should be 0 when set with value 0";
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond)
        << "0 < timeInterval < minTimeInterval should be set to minTimeInterval";
    uint32_t timeInterval = minTimeIntervalInSecond;
    rrc->SetTimeInterval(timeInterval);
    EXPECT_EQ(rrc->GetTimeInterval(), timeInterval) << "timeInterval set error";
    timeInterval = minTimeIntervalInSecond + 1;
    rrc->SetTimeInterval(timeInterval);
    EXPECT_EQ(rrc->GetTimeInterval(), timeInterval) << "timeInterval set error.";
}

/**
 * @tc.name: IsExpired_00100
 * @tc.desc: Test IsExpired parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, IsExpired_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->IsExpired(), false);
}

/**
 * @tc.name: IsShowing_00100
 * @tc.desc: Test IsShowing parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, IsShowing_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->IsShowing(), false);
}

/**
 * @tc.name: OnDateTimeChange_00100
 * @tc.desc: Test OnDateTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnDateTimeChange_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->OnDateTimeChange(), true);
}

/**
 * @tc.name: OnSnooze_00100
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->OnSnooze(), true);
}

/**
 * @tc.name: OnTerminate_00100
 * @tc.desc: Test OnTerminate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnTerminate_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->OnTerminate(), false);
}

/**
 * @tc.name: ShouldShowImmediately_00100
 * @tc.desc: Test ShouldShowImmediately parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, ShouldShowImmediately_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->ShouldShowImmediately(), true);
}

/**
 * @tc.name: GetSlotType_00100
 * @tc.desc: Test GetSlotType parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, GetSlotType_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    NotificationConstant::SlotType mySlotType = NotificationConstant::OTHER;
    rrc->SetSlotType(mySlotType);
    EXPECT_EQ(rrc->GetSlotType(), mySlotType);
}

/**
 * @tc.name: GetTriggerTimeInMilli_00100
 * @tc.desc: Test GetTriggerTimeInMilli parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, GetTriggerTimeInMilli_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    uint64_t triggerTimeInMilliTest = 1;
    rrc->SetTriggerTimeInMilli(triggerTimeInMilliTest);
    EXPECT_EQ(rrc->GetTriggerTimeInMilli(), triggerTimeInMilliTest);
}

/**
 * @tc.name: GetUserId_00100
 * @tc.desc: Test GetUserId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, GetUserId_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetUserId(), -1);
}

/**
 * @tc.name: GetUid_00100
 * @tc.desc: Test GetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, GetUid_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetUid(), -1);
}

/**
 * @tc.name: GetReminderType_00100
 * @tc.desc: Test GetReminderType parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, GetReminderType_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetReminderType(), ReminderRequest::ReminderType::INVALID);
}

/**
 * @tc.name: GetRingDuration_00100
 * @tc.desc: Test GetRingDuration parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, GetRingDuration_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetRingDuration(), 1);
}

/**
 * @tc.name: SetNextTriggerTime_00100
 * @tc.desc: Test SetNextTriggerTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, SetNextTriggerTime_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->SetNextTriggerTime(), false);
}

/**
 * @tc.name: Marshalling_00100
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, Marshalling_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    Parcel p;
    EXPECT_EQ(rrc->Marshalling(p), true);
}

/**
 * @tc.name: CanShow_00001
 * @tc.desc: Test CanShow parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, CanShow_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->CanShow(), true);
}

/**
 * @tc.name: CanShow_00002
 * @tc.desc: Test CanShow parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, CanShow_00002, Function | SmallTest | Level1)
{
    uint64_t reminderTimeInMilli = 5 * 60 * 1000;
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetReminderTimeInMilli(reminderTimeInMilli);
    EXPECT_EQ(rrc->CanShow(), true);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, Dump_00001, Function | SmallTest | Level1)
{
    std::string ret = "Reminder[reminderId=-1, type=3, state='Inactive, nextTriggerTime=1970-01-01 ";
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string res = rrc->Dump();
    EXPECT_EQ(res.substr(0, res.size()-9), ret);
}

/**
 * @tc.name: SetExpired_00001
 * @tc.desc: Test SetExpired parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, SetExpired_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool isExpired = rrc->IsExpired();
    rrc->SetExpired(isExpired);
    EXPECT_EQ(isExpired, false);
}

/**
 * @tc.name: HandleTimeZoneChange_00001
 * @tc.desc: Test HandleTimeZoneChange parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, HandleTimeZoneChange_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetExpired(false);
    uint64_t oldZoneTriggerTime = 1998;
    uint64_t newZoneTriggerTime = 1999;
    uint64_t optTriggerTime = 0;
    EXPECT_EQ(rrc->HandleTimeZoneChange(oldZoneTriggerTime, newZoneTriggerTime, optTriggerTime), true);
}

/**
 * @tc.name: HandleTimeZoneChange_00002
 * @tc.desc: Test HandleTimeZoneChange parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, HandleTimeZoneChange_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetExpired(true);
    uint64_t oldZoneTriggerTime = 1998;
    uint64_t newZoneTriggerTime = 1998;
    uint64_t optTriggerTime = 0;
    EXPECT_EQ(rrc->HandleTimeZoneChange(oldZoneTriggerTime, newZoneTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: HandleTimeZoneChange_00003
 * @tc.desc: Test HandleTimeZoneChange parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, HandleTimeZoneChange_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetExpired(true);
    uint64_t oldZoneTriggerTime = 1998;
    uint64_t newZoneTriggerTime = 1999;
    uint64_t optTriggerTime = 10;
    EXPECT_EQ(rrc->HandleTimeZoneChange(oldZoneTriggerTime, newZoneTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: HandleTimeZoneChange_00001
 * @tc.desc: Test HandleSysTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, HandleSysTimeChange_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetExpired(true);
    uint64_t oriTriggerTime = 10;
    uint64_t optTriggerTime = 10;
    EXPECT_EQ(rrc->HandleSysTimeChange(oriTriggerTime, optTriggerTime), false);
}

/**
 * @tc.name: OnSnooze_00001
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, false, true);
    EXPECT_EQ(rrc->OnSnooze(), true);
}

/**
 * @tc.name: OnSnooze_00002
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->UpdateNextReminder(false);
    EXPECT_EQ(rrc->OnSnooze(), true);
}

/**
 * @tc.name: OnSnooze_00003
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetTimeInterval(100);
    EXPECT_EQ(rrc->OnSnooze(), true);
}

/**
 * @tc.name: OnTerminate_00001
 * @tc.desc: Test OnTerminate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnTerminate_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->OnShow(false, false, true);
    EXPECT_EQ(rrc->OnTerminate(), false);
}

/**
 * @tc.name: OnTimeZoneChange_00001
 * @tc.desc: Test OnTerOnTimeZoneChangeminate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnTimeZoneChange_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->OnTimeZoneChange(), false);
}

/**
 * @tc.name: RecoverInt64FromDb_00001
 * @tc.desc: Test RecoverInt64FromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, RecoverInt64FromDb_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    std::string columnName = "columnName";
    ReminderRequest::DbRecoveryType columnType = ReminderRequest::DbRecoveryType::INT;
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->RecoverInt64FromDb(resultSet, columnName, columnType), 0);
}

/**
 * @tc.name: StringSplit_00001
 * @tc.desc: Test StringSplit parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, StringSplit_00001, Function | SmallTest | Level1)
{
    std::string source = "";
    std::string split = "split";
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::vector<std::string> ret = rrc->StringSplit(source, split);
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: StringSplit_00002
 * @tc.desc: Test StringSplit parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, StringSplit_00002, Function | SmallTest | Level1)
{
    std::string source = "source";
    std::string split = "split";
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::vector<std::string> ret = rrc->StringSplit(source, split);
    EXPECT_EQ(ret.size(), 1);
}

/**
 * @tc.name: SetMaxScreenWantAgentInfo_00001
 * @tc.desc: Test SetMaxScreenWantAgentInfo parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, SetMaxScreenWantAgentInfo_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequest::MaxScreenAgentInfo> maxScreenWantAgentInfo =
    std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetMaxScreenWantAgentInfo(maxScreenWantAgentInfo);
    EXPECT_EQ(rrc->GetMaxScreenWantAgentInfo(), maxScreenWantAgentInfo);
}

/**
 * @tc.name: SetSnoozeContent_00001
 * @tc.desc: Test SetSnoozeContent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, SetSnoozeContent_00001, Function | SmallTest | Level1)
{
    std::string snoozeContent = "snoozeContent";
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetSnoozeContent(snoozeContent);
    EXPECT_EQ(rrc->GetSnoozeContent(), snoozeContent);
}

/**
 * @tc.name: SetWantAgentInfo_00001
 * @tc.desc: Test SetWantAgentInfo parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, SetWantAgentInfo_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequest::WantAgentInfo> wantAgentInfo = std::make_shared<ReminderRequest::WantAgentInfo>();
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetWantAgentInfo(wantAgentInfo);
    EXPECT_EQ(rrc->GetWantAgentInfo(), wantAgentInfo);
}

/**
 * @tc.name: SetReminderTimeInMilli_00001
 * @tc.desc: Test SetReminderTimeInMilli parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, SetReminderTimeInMilli_00001, Function | SmallTest | Level1)
{
    uint64_t reminderTimeInMilli = 10;
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetReminderTimeInMilli(reminderTimeInMilli);
    EXPECT_EQ(rrc->GetReminderTimeInMilli(), reminderTimeInMilli);
}

/**
 * @tc.name: SetRingDuration_00001
 * @tc.desc: Test SetRingDuration parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, SetRingDuration_00001, Function | SmallTest | Level1)
{
    uint64_t ringDurationInSeconds = 0;
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetRingDuration(ringDurationInSeconds);
    EXPECT_EQ(rrc->GetRingDuration(), 1);
}

/**
 * @tc.name: SetRingDuration_00002
 * @tc.desc: Test SetRingDuration parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, SetRingDuration_00002, Function | SmallTest | Level1)
{
    uint64_t ringDurationInSeconds = 10;
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetRingDuration(ringDurationInSeconds);
    EXPECT_EQ(rrc->GetRingDuration(), ringDurationInSeconds);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    bool result = false;
    Parcel parcel;
    auto rrc = std::make_shared<ReminderRequestChild>();
    if (nullptr == rrc->Unmarshalling(parcel)) {
        result = true;
    }
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: InitNotificationRequest_00001
 * @tc.desc: Test InitNotificationRequest parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, InitNotificationRequest_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
}

/**
 * @tc.name: InitNotificationRequest_00002
 * @tc.desc: Test InitNotificationRequest parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, InitNotificationRequest_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetNotificationId(100);
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
}

/**
 * @tc.name: IsAlerting_00001
 * @tc.desc: Test IsAlerting parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, IsAlerting_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->IsAlerting(), false);
}

/**
 * @tc.name: GetButtonInfo_00001
 * @tc.desc: Test GetButtonInfo parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, GetButtonInfo_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetButtonInfo(), "");
}

/**
 * @tc.name: GetShowTime_00001
 * @tc.desc: Test GetShowTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, GetShowTime_00001, Function | SmallTest | Level1)
{
    uint64_t showTime = 8 * 60 * 1000;
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string ret = ":08";
    std::string res = rrc->GetShowTime(showTime);
    EXPECT_EQ(res.substr(2, res.size()), ret);
}

/**
 * @tc.name: GetShowTime_00002
 * @tc.desc: Test GetShowTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, GetShowTime_00002, Function | SmallTest | Level1)
{
    uint64_t showTime = 8 * 60 * 1000;
    ReminderRequest reminder = ReminderRequest(ReminderRequest::ReminderType::TIMER);
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string ret = ":08";
    std::string res = rrc->GetShowTime(showTime);
    EXPECT_EQ(res.substr(2, res.size()), ret);
}

/**
 * @tc.name: CreateWantAgent_00001
 * @tc.desc: Test CreateWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, CreateWantAgent_00001, Function | SmallTest | Level1)
{
    AppExecFwk::ElementName element;
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_NE(rrc->CreateWantAgent(element), nullptr);
}

/**
 * @tc.name: GetUid_00001
 * @tc.desc: Test GetUid parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, GetUid_00001, Function | SmallTest | Level1)
{
    int32_t userId = 1;
    std::string bundleName = "bundleName";
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetUid(userId, bundleName), -1);
}

/**
 * @tc.name: GetUserId_00001
 * @tc.desc: Test GetUserId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, GetUserId_00001, Function | SmallTest | Level1)
{
    int32_t uid = 1;
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->GetUserId(uid), 0);
}
}
}
