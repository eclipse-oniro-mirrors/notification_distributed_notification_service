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
#include "reminder_table_old.h"
#include "reminder_table.h"
#include "string_wrapper.h"
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
    EXPECT_EQ(rrc->HandleSysTimeChange(oriTriggerTime, optTriggerTime), true);
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
    EXPECT_EQ(rrc->GetRingDuration(), 0);
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
 * @tc.name: SetRingDuration_00003
 * @tc.desc: Test SetRingDuration parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderRequestTest, SetRingDuration_00003, Function | SmallTest | Level1)
{
    uint64_t ringDurationInSeconds = 45 * 60;
    auto rrc = std::make_shared<ReminderRequestChild>();
    rrc->SetRingDuration(ringDurationInSeconds);
    EXPECT_EQ(rrc->GetRingDuration(), ReminderRequest::MAX_RING_DURATION / ReminderRequest::MILLI_SECONDS);
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
    std::string resource = "invalid";
    Notification::ReminderRequest::ActionButtonType type =
            Notification::ReminderRequest::ActionButtonType::INVALID;
    reminderRequestChild->SetActionButton(title, type, resource);
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
    std::string resource = "close";
    Notification::ReminderRequest::ActionButtonType type2 =
            Notification::ReminderRequest::ActionButtonType::CLOSE;
    reminderRequestChild->SetActionButton(title, type2, resource);
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
    std::string resource = "snooze";
    Notification::ReminderRequest::ActionButtonType type3 =
            Notification::ReminderRequest::ActionButtonType::SNOOZE;
    reminderRequestChild->SetActionButton(title, type3, resource);
}

/**
 * @tc.name: SetActionButton_00004
 * @tc.desc: Test SetActionButton parameters.
 * @tc.type: FUNC
 * @tc.require: issueI89IQR
 */
HWTEST_F(ReminderRequestTest, SetActionButton_00004, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::string title = "this is title";
    std::string resource = "CLOSE";
    Notification::ReminderRequest::ActionButtonType type2 =
            Notification::ReminderRequest::ActionButtonType::CLOSE;
    std::shared_ptr<ReminderRequest::ButtonWantAgent> buttonWantAgent =
        std::make_shared<ReminderRequest::ButtonWantAgent>();
    std::shared_ptr<ReminderRequest::ButtonDataShareUpdate> buttonDataShareUpdate =
        std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    reminderRequestChild->SetActionButton(title, type2, resource, buttonWantAgent, buttonDataShareUpdate);
}

/**
 * @tc.name: SetActionButton_00005
 * @tc.desc: Test SetActionButton parameters.
 * @tc.type: FUNC
 * @tc.require: issueI89IQR
 */
HWTEST_F(ReminderRequestTest, SetActionButton_00005, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::string title = "this is title";
    std::string resource = "SNOOZE";
    Notification::ReminderRequest::ActionButtonType type3 =
            Notification::ReminderRequest::ActionButtonType::SNOOZE;
    std::shared_ptr<ReminderRequest::ButtonWantAgent> buttonWantAgent =
        std::make_shared<ReminderRequest::ButtonWantAgent>();
    std::shared_ptr<ReminderRequest::ButtonDataShareUpdate> buttonDataShareUpdate =
        std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    reminderRequestChild->SetActionButton(title, type3, resource, buttonWantAgent, buttonDataShareUpdate);
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
    AppExecFwk::ElementName element("", "com.example.myapplication", "EntryAbility");
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> WantAgent =
        reminderRequestChild->CreateMaxWantAgent(element);
    EXPECT_EQ(WantAgent, nullptr);
}

/**
 * @tc.name: CreateWantAgent_00002
 * @tc.desc: Test CreateWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI86QW2
 */
HWTEST_F(ReminderRequestTest, CreateWantAgent_00002, Function | SmallTest | Level1)
{
    AppExecFwk::ElementName element("", "com.example.myapplication", "EntryAbility");
    std::shared_ptr<ReminderRequestChild> reminderRequestChild = std::make_shared<ReminderRequestChild>();
    ASSERT_NE(nullptr, reminderRequestChild);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> WantAgent =
        reminderRequestChild->CreateWantAgent(element);
    EXPECT_EQ(WantAgent, nullptr);
}

/**
 * @tc.name: AddColumn_00002
 * @tc.desc: Test AddColumn parameters.
 * @tc.type: FUNC
 * @tc.require: issueI65R21
 */
HWTEST_F(ReminderRequestTest, AddColumn_00002, Function | SmallTest | Level1)
{
    std::string name = "this is name";
    std::string type = "this is type";
    ReminderTable::AddColumn(name, type, true);
    ReminderTable::AddColumn(name, type, false);
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
 * @tc.name: RecoverWantAgent_00006
 * @tc.desc: Test RecoverWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI86QW2
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgent_00006, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string wantAgentInfo = "sour<SEP#/>123<SEP#/>uri";
    uint8_t type = 0;
    std::vector<std::string> ret1 = rrc->StringSplit(wantAgentInfo, "<SEP#/>");
    EXPECT_EQ(ret1.size(), 3);
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
 * @tc.name: UpdateNotificationContent_00600
 * @tc.desc: Test UpdateNotificationContent extend content when snooze.
 * @tc.type: FUNC
 * @tc.require: issueI87A02
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationContent_00600, Function | SmallTest | Level1)
{
    // given
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    rrc->snoozeContent_ = "snooze";
    rrc->content_ = "content";
    rrc->expiredContent_ = "expiredContent";
    rrc->timeIntervalInMilli_ = 1;

    // when
    bool setSnooze = true;
    rrc->UpdateNotificationContent(setSnooze);

    // then
    EXPECT_EQ(rrc->displayContent_, "snooze");
}

/**
 * @tc.name: UpdateNotificationContent_00800
 * @tc.desc: Test UpdateNotificationContent extend content when expiredContent.
 * @tc.type: FUNC
 * @tc.require: issueI87A02
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationContent_00800, Function | SmallTest | Level1)
{
    // given
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    rrc->snoozeContent_ = "snooze";
    rrc->content_ = "content";
    rrc->expiredContent_ = "expiredContent";
    rrc->timeIntervalInMilli_ = 0;

    // when
    bool setSnooze = true;
    rrc->UpdateNotificationContent(setSnooze);

    // then
    EXPECT_EQ(rrc->displayContent_, "expiredContent");
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

/**
 * @tc.name: SetGroupId_00001
 * @tc.desc: Test SetGroupId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI8CDH3
 */
HWTEST_F(ReminderRequestTest, SetGroupId_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string groupId = "123";
    rrc->SetGroupId(groupId);
    EXPECT_EQ(rrc->GetGroupId(), groupId);
}

/**
 * @tc.name: InitBundleName_00001
 * @tc.desc: Test InitBundleName with normal parameters.
 * @tc.type: FUNC
 * @tc.require: issueI89858
 */
HWTEST_F(ReminderRequestTest, InitBundleName_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string bundleName = "com.example.myapplication";
    rrc->InitBundleName(bundleName);
    EXPECT_EQ(rrc->GetBundleName(), bundleName);
}

/**
 * @tc.name: InitBundleName_00002
 * @tc.desc: Test InitBundleName with special parameters.
 * @tc.type: FUNC
 * @tc.require: issueI89858
 */
HWTEST_F(ReminderRequestTest, InitBundleName_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string bundleName = "com.example.myapplication.~!@#$%^&*()";
    rrc->InitBundleName(bundleName);
    EXPECT_EQ(rrc->GetBundleName(), bundleName);
}

/**
 * @tc.name: UpdateNotificationCommon_00100
 * @tc.desc: Test UpdateNotificationCommon when snooze is true.
 * @tc.type: FUNC
 * @tc.require: issueII8F9EZ
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationCommon_00100, Function | SmallTest | Level1)
{
    // given
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    rrc->snoozeSlotType_ = NotificationConstant::SlotType::OTHER;
    bool isSnooze = true;

    // when
    rrc->UpdateNotificationCommon(isSnooze);

    // then
    EXPECT_EQ(ret->GetSlotType(), NotificationConstant::SlotType::CONTENT_INFORMATION);
}

/**
 * @tc.name: UpdateNotificationCommon_00200
 * @tc.desc: Test UpdateNotificationCommon when snooze is true.
 * @tc.type: FUNC
 * @tc.require: issueII8F9EZ
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationCommon_00200, Function | SmallTest | Level1)
{
    // given
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    rrc->snoozeSlotType_ = NotificationConstant::SlotType::SERVICE_REMINDER;
    bool isSnooze = true;

    // when
    rrc->UpdateNotificationCommon(isSnooze);

    // then
    EXPECT_EQ(ret->GetSlotType(), NotificationConstant::SlotType::SERVICE_REMINDER);
}

/**
 * @tc.name: UpdateNotificationCommon_00300
 * @tc.desc: Test UpdateNotificationCommon when snooze is false.
 * @tc.type: FUNC
 * @tc.require: issueII8F9EZ
 */
HWTEST_F(ReminderRequestTest, UpdateNotificationCommon_00300, Function | SmallTest | Level1)
{
    // given
    auto rrc = std::make_shared<ReminderRequestChild>();
    EXPECT_EQ(rrc->InitNotificationRequest(), true);
    sptr<NotificationRequest> ret = rrc->GetNotificationRequest();
    rrc->snoozeSlotType_ = NotificationConstant::SlotType::SERVICE_REMINDER;
    rrc->slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    bool isSnooze = false;

    // when
    rrc->UpdateNotificationCommon(isSnooze);

    // then
    EXPECT_EQ(ret->GetSlotType(), NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
}

/**
 * @tc.name: InitCreatorBundleName_00001
 * @tc.desc: Test InitCreatorBundleName with normal parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I8R55M
 */
HWTEST_F(ReminderRequestTest, InitCreatorBundleName_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string bundleName = "com.example.myapplication";
    rrc->InitCreatorBundleName(bundleName);
    EXPECT_EQ(rrc->GetCreatorBundleName(), bundleName);
}

/**
 * @tc.name: InitCreatorBundleName_00002
 * @tc.desc: Test InitCreatorBundleName with special parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I8R55M
 */
HWTEST_F(ReminderRequestTest, InitCreatorBundleName_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string bundleName = "com.example.myapplication.~!@#$%^&*()";
    rrc->InitCreatorBundleName(bundleName);
    EXPECT_EQ(rrc->GetCreatorBundleName(), bundleName);
}

/**
 * @tc.name: RecoverWantAgentByJson_00001
 * @tc.desc: Test invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgentByJson_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string jsonValue = "";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = "{}";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");
    
    jsonValue = R"({"pkgName":1})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication"})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":1})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility"})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":1})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":""})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":"","parameters":1})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":"","parameters":""})";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "MainAbility");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":"","parameters":""})";
    rrc->RecoverWantAgentByJson(jsonValue, 1);
    EXPECT_EQ(rrc->GetMaxScreenWantAgentInfo()->abilityName, "MainAbility");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":"","parameters":""})";
    rrc->RecoverWantAgentByJson(jsonValue, 2);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "MainAbility");

    jsonValue = "awefasdfawefasdfaswe";
    rrc->RecoverWantAgentByJson(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "MainAbility");
}

/**
 * @tc.name: RecoverWantAgent_00007
 * @tc.desc: Test RecoverWantAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, RecoverWantAgent_00007, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string jsonValue = "";
    rrc->RecoverWantAgent(jsonValue, 0);
    EXPECT_EQ(rrc->GetWantAgentInfo()->abilityName, "");

    jsonValue = R"({"pkgName":"com.example.myapplication","abilityName":"MainAbility","uri":"","parameters":""})";
    rrc->RecoverWantAgent(jsonValue, 1);
    EXPECT_EQ(rrc->GetMaxScreenWantAgentInfo()->abilityName, "MainAbility");

    jsonValue = R"(})";
    rrc->RecoverWantAgent(jsonValue, 1);
    EXPECT_EQ(rrc->GetMaxScreenWantAgentInfo()->abilityName, "MainAbility");

    jsonValue = R"({})";
    rrc->RecoverWantAgent(jsonValue, 1);
    EXPECT_EQ(rrc->GetMaxScreenWantAgentInfo()->abilityName, "MainAbility");

    jsonValue = "fawexcdvasdfwessdf";
    rrc->RecoverWantAgent(jsonValue, 1);
    EXPECT_EQ(rrc->GetMaxScreenWantAgentInfo()->abilityName, "MainAbility");
}

/**
 * @tc.name: MarshallingWantParameters_00001
 * @tc.desc: Test MarshallingWantParameters parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, MarshallingWantParameters_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    AAFwk::WantParams params1;
    Parcel p1;
    bool ret = rrc->MarshallingWantParameters(p1, params1);
    EXPECT_EQ(ret, true);

    std::string key = "key";
    std::string value = "value";
    params1.SetParam(key, AAFwk::String::Box(value));
    Parcel p2;
    ret = rrc->MarshallingWantParameters(p2, params1);
    EXPECT_EQ(ret, true);

    AAFwk::WantParams params2;
    ret = rrc->ReadWantParametersFromParcel(p1, params2);
    EXPECT_EQ(ret, true);

    ret = rrc->ReadWantParametersFromParcel(p2, params2);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(params2.GetStringParam(key), value);
}

/**
 * @tc.name: AppendWantAgentValuesBucket_00001
 * @tc.desc: Test AppendWantAgentValuesBucket parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, AppendWantAgentValuesBucket_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequestChild> rrc = new ReminderRequestChild;
    NativeRdb::ValuesBucket values;
    ReminderRequest::AppendWantAgentValuesBucket(rrc, values);

    NativeRdb::ValueObject object;
    values.GetObject(ReminderBaseTable::WANT_AGENT, object);
    std::string result;
    object.GetString(result);
    EXPECT_NE(result.find("pkgName"), -1);

    values.GetObject(ReminderBaseTable::MAX_SCREEN_WANT_AGENT, object);
    object.GetString(result);
    EXPECT_NE(result.find("pkgName"), -1);
}

/**
 * @tc.name: AppendWantAgentValuesBucket_00002
 * @tc.desc: Test AppendWantAgentValuesBucket parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, AppendWantAgentValuesBucket_00002, Function | SmallTest | Level1)
{
    auto wantInfo = std::make_shared<ReminderRequest::WantAgentInfo>();
    wantInfo->pkgName = "test";
    auto maxWantInfo = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
    maxWantInfo->pkgName = "maxTest";

    sptr<ReminderRequestChild> rrc = new ReminderRequestChild;
    rrc->SetWantAgentInfo(wantInfo);
    rrc->SetMaxScreenWantAgentInfo(maxWantInfo);
    NativeRdb::ValuesBucket values;
    ReminderRequest::AppendWantAgentValuesBucket(rrc, values);

    NativeRdb::ValueObject object;
    values.GetObject(ReminderBaseTable::WANT_AGENT, object);
    std::string result;
    object.GetString(result);
    EXPECT_NE(result.find("test"), -1);

    values.GetObject(ReminderBaseTable::MAX_SCREEN_WANT_AGENT, object);
    object.GetString(result);
    EXPECT_NE(result.find("maxTest"), -1);
}

/**
 * @tc.name: WantAgentStr_00001
 * @tc.desc: Test want agent str parameters.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, WantAgentStr_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequestChild> rrc = new ReminderRequestChild;
    rrc->wantAgentStr_ = "test";
    rrc->maxWantAgentStr_ = "test_max";
    EXPECT_EQ(rrc->GetWantAgentStr(), "test");
    EXPECT_EQ(rrc->GetMaxWantAgentStr(), "test_max");
}

/**
 * @tc.name: RecoverActionButtonJsonMode_00001
 * @tc.desc: Test action button json string.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, RecoverActionButtonJsonMode_00001, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    std::string jsonValue = "";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_.size(), 0);

    // test type
    jsonValue = R"({})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_.size(), 0);

    jsonValue = R"({"type":1})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_.size(), 0);

    jsonValue = R"({"type":"a"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_.size(), 0);

    jsonValue = R"({"type":"asdfwe"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_.size(), 0);

    // test title
    jsonValue = R"({"type":"1"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].title, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":1})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].title, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].title, "test");

    // test resource
    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].resource, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":1})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].resource, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].resource, "resource");
}

/**
 * @tc.name: RecoverActionButtonJsonMode_00002
 * @tc.desc: Test action button json string wantAgent.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, RecoverActionButtonJsonMode_00002, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    // test wantAgent.pkgName
    std::string jsonValue = R"({"type":"1","title":"test","resource":"resource"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].wantAgent->pkgName, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","wantAgent":{"pkgName":1}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].wantAgent->pkgName, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","wantAgent":{"pkgName":"pkgName"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].wantAgent->pkgName, "pkgName");

    // test wantAgent.abilityName
    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","wantAgent":{"pkgName":"pkgName"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].wantAgent->abilityName, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"res","wantAgent":{"pkgName":"pkgName","abilityName":1}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].wantAgent->abilityName, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","wantAgent":{"abilityName":"abilityName"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[ReminderRequest::ActionButtonType::SNOOZE].wantAgent->abilityName, "abilityName");
}

/**
 * @tc.name: RecoverActionButtonJsonMode_00003
 * @tc.desc: Test action button json string dataShareUpdate.
 * @tc.type: FUNC
 * @tc.require: issue#I94VJT
 */
HWTEST_F(ReminderRequestTest, RecoverActionButtonJsonMode_00003, Function | SmallTest | Level1)
{
    auto rrc = std::make_shared<ReminderRequestChild>();
    constexpr auto type = ReminderRequest::ActionButtonType::SNOOZE;
    // test dataShareUpdate.uri
    std::string jsonValue = R"({"type":"1","title":"test","resource":"resource"})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->uri, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"uri":1}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->uri, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"uri":"uri"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->uri, "uri");

    // test dataShareUpdate.equalTo
    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"uri":"uri"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->equalTo, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"equalTo":1}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->equalTo, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"equalTo":"equalTo"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->equalTo, "equalTo");

    // test dataShareUpdate.valuesBucket
    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"uri":"uri"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->valuesBucket, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"resource","dataShareUpdate":{"valuesBucket":1}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->valuesBucket, "");

    rrc->actionButtonMap_.clear();
    jsonValue = R"({"type":"1","title":"test","resource":"res","dataShareUpdate":{"valuesBucket":"valuesBucket"}})";
    rrc->RecoverActionButtonJsonMode(jsonValue);
    EXPECT_EQ(rrc->actionButtonMap_[type].dataShareUpdate->valuesBucket, "valuesBucket");
}
}
}
