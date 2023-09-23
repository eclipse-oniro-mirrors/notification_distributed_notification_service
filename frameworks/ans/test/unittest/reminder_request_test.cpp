/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

extern void MockNowInstantMilli(bool mockRet);

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
 * @tc.name: IsShowing_00200
 * @tc.desc: Test IsShowing parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, IsShowing_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 4;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 4);
    bool result = rrc->IsShowing();
    EXPECT_EQ(result, true);
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
    rrc->SetExpired(true);
    EXPECT_EQ(rrc->OnDateTimeChange(), false);
}

/**
 * @tc.name: OnSnooze_00100
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00100, Function | SmallTest | Level1)
{
    MockNowInstantMilli(true);
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
    MockNowInstantMilli(true);
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
    MockNowInstantMilli(true);
    auto rrc = std::make_shared<ReminderRequestChild>();
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
    std::string ret = "Reminder[reminderId=-1, type=3, state='Inactive', nextTriggerTime=";
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string res = rrc->Dump();
    EXPECT_EQ(res.substr(0, res.size()-20), ret);
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
 * @tc.name: HandleTimeZoneChange_00002
 * @tc.desc: Test HandleSysTimeChange parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, HandleSysTimeChange_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetExpired(false);
    uint64_t oriTriggerTime = 10;
    uint64_t optTriggerTime = 20;
    MockNowInstantMilli(false);
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
    MockNowInstantMilli(true);
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
    MockNowInstantMilli(true);
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
    MockNowInstantMilli(true);
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetTimeInterval(100);
    EXPECT_EQ(rrc->OnSnooze(), true);
}

/**
 * @tc.name: OnSnooze_00004
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00004, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 8;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 8);
    EXPECT_EQ(rrc->OnSnooze(), false);
}

/**
 * @tc.name: OnSnooze_00005
 * @tc.desc: Test OnSnooze parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, OnSnooze_00005, Function | SmallTest | Level1)
{
    MockNowInstantMilli(true);
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 1;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 1);
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
    uint64_t ret = rrc->GetTriggerTimeInMilli();
    struct tm oriTime;
    time_t newZoneTriggerTime = mktime(&oriTime);
    uint64_t ret2 = rrc->GetDurationSinceEpochInMilli(newZoneTriggerTime);
    if (ret == ret2) {
        EXPECT_EQ(rrc->OnTimeZoneChange(), false);
    } else {
        EXPECT_EQ(rrc->OnTimeZoneChange(), true);
    }
}

/**
 * @tc.name: RecoverInt64FromDb_00001
 * @tc.desc: Test RecoverInt64FromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5UYHP
 */
HWTEST_F(ReminderRequestTest, RecoverInt64FromDb_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
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
    std::string ret = "8";
    std::string res = rrc->GetShowTime(showTime);
    EXPECT_EQ(res.substr(4, res.size()), ret);
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
    std::string ret = "8";
    std::string res = rrc->GetShowTime(showTime);
    EXPECT_EQ(res.substr(4, res.size()), ret);
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

/**
 * @tc.name: SetActionButton_00001
 * @tc.desc: Test SetActionButton parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, SetActionButton_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::string title = "this is title";
    Notification::ReminderRequest::ActionButtonType type =
            Notification::ReminderRequest::ActionButtonType::INVALID;
    reminderRequestChild->SetActionButton(title, type);
}

/**
 * @tc.name: SetActionButton_00002
 * @tc.desc: Test SetActionButton parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, SetActionButton_00002, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::string title = "this is title";
    Notification::ReminderRequest::ActionButtonType type2 =
            Notification::ReminderRequest::ActionButtonType::CLOSE;
    reminderRequestChild->SetActionButton(title, type2);
}

/**
 * @tc.name: SetActionButton_00003
 * @tc.desc: Test SetActionButton parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, SetActionButton_00003, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::string title = "this is title";
    Notification::ReminderRequest::ActionButtonType type3 =
            Notification::ReminderRequest::ActionButtonType::SNOOZE;
    reminderRequestChild->SetActionButton(title, type3);
}

/**
 * @tc.name: AddActionButtons_00001
 * @tc.desc: Test AddActionButtons parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, AddActionButtons_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    reminderRequestChild->AddActionButtons(true);
    reminderRequestChild->AddActionButtons(false);
}

/**
 * @tc.name: InitUserId_00001
 * @tc.desc: Test InitUserId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, InitUserId_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    bool deSet = true;
    uint8_t newState = 2;
    std::string function = "this is function";
    int32_t userId = 1;
    int32_t uid = 2;
    reminderRequestChild->InitUserId(userId);
    reminderRequestChild->InitUid(uid);
    reminderRequestChild->SetState(deSet, newState, function);
    uint8_t result1 = reminderRequestChild->GetState();
    EXPECT_EQ(result1, 2);
    bool result = reminderRequestChild->IsShowing();
    EXPECT_EQ(result, false);
    reminderRequestChild->OnShow(true, true, true);
    reminderRequestChild->OnShowFail();
}

/**
 * @tc.name: OnStart_00001
 * @tc.desc: Test OnStart parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, OnStart_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    reminderRequestChild->OnStart();
    reminderRequestChild->OnStop();
    bool deSet = true;
    uint8_t newState = 2;
    std::string function = "this is function";
    int32_t userId = 1;
    int32_t uid = 2;
    reminderRequestChild->InitUserId(userId);
    reminderRequestChild->InitUid(uid);
    reminderRequestChild->SetState(deSet, newState, function);
    reminderRequestChild->OnStart();
    reminderRequestChild->OnStop();
}

/**
 * @tc.name: RecoverInt64FromDb_00002
 * @tc.desc: Test RecoverInt64FromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, RecoverInt64FromDb_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::shared_ptr<NativeRdb::ResultSet> resultSet =
        std::make_shared<NativeRdb::AbsSharedResultSet>();
    std::string columnName = "this is columnName";
    ReminderRequest::DbRecoveryType columnType = ReminderRequest::DbRecoveryType::INT;
    int64_t result = rrc->RecoverInt64FromDb(resultSet, columnName, columnType);
    EXPECT_EQ(result, 0);

    ReminderRequest::DbRecoveryType columnType2 = ReminderRequest::DbRecoveryType::LONG;
    int64_t result2 = rrc->RecoverInt64FromDb(resultSet, columnName, columnType2);
    EXPECT_EQ(result2, 0);
    rrc->RecoverFromDb(resultSet);
    rrc->RecoverActionButton(resultSet);
    rrc->RecoverActionButton(nullptr);
}

/**
 * @tc.name: RecoverInt64FromDb_00003
 * @tc.desc: Test RecoverInt64FromDb parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, RecoverInt64FromDb_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::shared_ptr<NativeRdb::ResultSet> resultSet =
        std::make_shared<NativeRdb::AbsSharedResultSet>();
    std::string columnName = "this is columnName";

    ReminderRequest::DbRecoveryType columnType = ReminderRequest::DbRecoveryType(3);
    int64_t result2 = rrc->RecoverInt64FromDb(resultSet, columnName, columnType);
    EXPECT_EQ(result2, 0);
}

/**
 * @tc.name: RecoverWantAgent_00002
 * @tc.desc: Test RecoverWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgent_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string source = "source";
    std::string split = "split";
    std::vector<std::string> ret = rrc->StringSplit(source, split);
    EXPECT_EQ(ret.size(), 1);

    std::string wantAgentInfo = "this is wantAgentInfo";
    uint8_t type = 0;
    rrc->RecoverWantAgent(wantAgentInfo, type);
}

/**
 * @tc.name: GetActionButtons_00002
 * @tc.desc: Test GetActionButtons parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, GetActionButtons_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::map<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo> ret =
        rrc->GetActionButtons();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: UpdateNotificationContent_00002
 * @tc.desc: Test UpdateNotificationContent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationContent_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetNotificationId(100);
    EXPECT_EQ(rrc->InitNotificationRequest(), true);

    rrc->UpdateNotificationContent(true);
    rrc->UpdateNotificationContent(false);

    Notification::ReminderRequest::TimeTransferType type = Notification::ReminderRequest::TimeTransferType::WEEK;
    int32_t actualTime = 1;
    int32_t result = rrc->GetCTime(type, actualTime);
    EXPECT_EQ(result, 1);
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
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> WantAgent =
        reminderRequestChild->CreateWantAgent(element);
}

/**
 * @tc.name: AddColumn_00002
 * @tc.desc: Test AddColumn parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, AddColumn_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->InitDbColumns();
    std::string name = "this is name";
    std::string type = "this is type";
    rrc->AddColumn(name, type, true);
    rrc->AddColumn(name, type, false);
    int32_t result = rrc->GetReminderId();
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: OnClose_00100
 * @tc.desc: Test OnClose parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnClose_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 4;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 4);
    rrc->OnClose(true);
}

/**
 * @tc.name: OnClose_00200
 * @tc.desc: Test OnClose parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnClose_00200, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 2;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 2);
    rrc->OnClose(true);
}

/**
 * @tc.name: OnShow_00100
 * @tc.desc: Test OnShow parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5QVYA
 */
HWTEST_F(ReminderRequestTest, OnShow_00100, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 9;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 9);
    rrc->OnShow(true, true, true);
}

/**
 * @tc.name: OnStart_00002
 * @tc.desc: Test OnStart parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, OnStart_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 1;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 1);
    rrc->OnStart();
}

/**
 * @tc.name: OnStart_00003
 * @tc.desc: Test OnStart parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, OnStart_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    bool deSet = true;
    uint8_t newState = 2;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 2);
    rrc->SetExpired(true);
    rrc->OnStart();
}

/**
 * @tc.name: StringSplit_00003
 * @tc.desc: Test StringSplit parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, StringSplit_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string source1 = "source1";
    std::string split = "c";
    std::vector<std::string> ret1 = rrc->StringSplit(source1, split);
    EXPECT_EQ(ret1.size(), 2);
}

/**
 * @tc.name: RecoverWantAgent_00003
 * @tc.desc: Test RecoverWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgent_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string wantAgentInfo = "sour<SEP#/>123";
    uint8_t type = 0;
    std::vector<std::string> ret1 = rrc->StringSplit(wantAgentInfo, "<SEP#/>");
    EXPECT_EQ(ret1.size(), 2);
    rrc->RecoverWantAgent(wantAgentInfo, type);
}

/**
 * @tc.name: RecoverWantAgent_00004
 * @tc.desc: Test RecoverWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgent_00004, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string wantAgentInfo = "sour<SEP#/>123";
    uint8_t type = 1;
    std::vector<std::string> ret1 = rrc->StringSplit(wantAgentInfo, "<SEP#/>");
    EXPECT_EQ(ret1.size(), 2);
    rrc->RecoverWantAgent(wantAgentInfo, type);
}

/**
 * @tc.name: RecoverWantAgent_00005
 * @tc.desc: Test RecoverWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgent_00005, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string wantAgentInfo = "sour<SEP#/>123";
    uint8_t type = 2;
    std::vector<std::string> ret1 = rrc->StringSplit(wantAgentInfo, "<SEP#/>");
    EXPECT_EQ(ret1.size(), 2);
    rrc->RecoverWantAgent(wantAgentInfo, type);
}

/**
 * @tc.name: UpdateActionButtons_00001
 * @tc.desc: Test UpdateActionButtons parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, UpdateActionButtons_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    bool setSnooze = true;
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1);
    rrc->SetSnoozeTimesDynamic(1);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1);
    rrc->UpdateActionButtons(setSnooze);
}

/**
 * @tc.name: UpdateActionButtons_00002
 * @tc.desc: Test UpdateActionButtons parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, UpdateActionButtons_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    bool setSnooze = true;
    rrc->SetSnoozeTimes(0);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 0);
    rrc->SetSnoozeTimesDynamic(1);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1);
    rrc->UpdateActionButtons(setSnooze);
}

/**
 * @tc.name: UpdateActionButtons_00003
 * @tc.desc: Test UpdateActionButtons parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, UpdateActionButtons_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    bool setSnooze = false;
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1);
    rrc->SetSnoozeTimesDynamic(1);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1);
    rrc->UpdateActionButtons(setSnooze);
}

/**
 * @tc.name: UpdateActionButtons_00004
 * @tc.desc: Test UpdateActionButtons parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, UpdateActionButtons_00004, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    bool setSnooze = true;
    rrc->SetSnoozeTimes(1);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 1);
    rrc->SetSnoozeTimesDynamic(0);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 0);
    rrc->UpdateActionButtons(setSnooze);
}

/**
 * @tc.name: UpdateNotificationContent_00300
 * @tc.desc: Test UpdateNotificationContent parameters.
 * @tc.type: FUNC
 * @tc.require: AR000GNF1T
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationContent_00300, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    uint32_t minTimeIntervalInSecond = 5 * 60;
    rrc->SetTimeInterval(1);
    EXPECT_EQ(rrc->GetTimeInterval(), minTimeIntervalInSecond);

    bool setSnooze = true;
    rrc->UpdateNotificationContent(setSnooze);
}


/**
 * @tc.name: UpdateNotificationContent_00400
 * @tc.desc: Test UpdateNotificationContent parameters.
 * @tc.type: FUNC
 * @tc.require: AR000GNF1T
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationContent_00400, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();

    bool deSet = true;
    uint8_t newState = 2;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 2);
    EXPECT_EQ(rrc->IsAlerting(), true);
    bool setSnooze = false;
    rrc->UpdateNotificationContent(setSnooze);
}

/**
 * @tc.name: UpdateNotificationContent_00500
 * @tc.desc: Test UpdateNotificationContent parameters.
 * @tc.type: FUNC
 * @tc.require: AR000GNF1T
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationContent_00500, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();

    bool deSet = false;
    uint8_t newState = 0;
    std::string function = "this is function";
    rrc->SetState(deSet, newState, function);
    uint8_t result1 = rrc->GetState();
    EXPECT_EQ(result1, 0);
    EXPECT_EQ(rrc->IsAlerting(), false);

    rrc->SetSnoozeTimes(0);
    EXPECT_EQ(rrc->GetSnoozeTimes(), 0);
    rrc->SetSnoozeTimesDynamic(1);
    EXPECT_EQ(rrc->GetSnoozeTimesDynamic(), 1);

    bool setSnooze = false;
    rrc->UpdateNotificationContent(setSnooze);
}

/**
 * @tc.name: GetCTime_00001
 * @tc.desc: Test GetCTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, GetCTime_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    Notification::ReminderRequest::TimeTransferType type = Notification::ReminderRequest::TimeTransferType(3);
    int32_t actualTime = 1;
    int32_t result = rrc->GetCTime(type, actualTime);
    int32_t ret = -1;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: GetActualTime_00001
 * @tc.desc: Test GetActualTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, GetActualTime_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    Notification::ReminderRequest::TimeTransferType type = Notification::ReminderRequest::TimeTransferType(3);
    int32_t actualTime = 1;
    int32_t result = rrc->GetActualTime(type, actualTime);
    int32_t ret = -1;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: SetSystemApp_00001
 * @tc.desc: Test SetSystemApp parameters.
 * @tc.type: FUNC
 * @tc.require: issueI6NQPJ
 */
HWTEST_F(ReminderRequestTest, SetSystemApp_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetSystemApp(true);
    bool result = rrc->IsSystemApp();
    bool ret = true;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: SetTapDismissed_00001
 * @tc.desc: Test SetTapDismissed parameters.
 * @tc.type: FUNC
 * @tc.require: issueI6NQPJ
 */
HWTEST_F(ReminderRequestTest, SetTapDismissed_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetTapDismissed(true);
    bool result = rrc->IsTapDismissed();
    bool ret = true;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: SetAutoDeletedTime_00001
 * @tc.desc: Test SetAutoDeletedTime parameters.
 * @tc.type: FUNC
 * @tc.require: issueI6NQPJ
 */
HWTEST_F(ReminderRequestTest, SetAutoDeletedTime_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetAutoDeletedTime(1);
    int32_t result = rrc->GetAutoDeletedTime();
    int32_t ret = 1;
    EXPECT_EQ(result, ret);
}

/**
 * @tc.name: SetCustomButtonUri_00001
 * @tc.desc: Test SetCustomButtonUri parameters.
 * @tc.type: FUNC
 * @tc.require: issueI6NQPJ
 */
HWTEST_F(ReminderRequestTest, SetCustomButtonUri_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetCustomButtonUri("test");
    std::string result = rrc->GetCustomButtonUri();
    std::string ret = "test";
    EXPECT_EQ(result, ret);
}
}
}
