/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "notification_slot.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t TYPE_NOTIFICATION =
    static_cast<int32_t>(NotificationConstant::SlotFlagsNotificationType::NOTIFICATION);
constexpr int32_t TYPE_PRIORITY_NOTIFICATION =
    static_cast<int32_t>(NotificationConstant::SlotFlagsNotificationType::PRIORITY_NOTIFICATION);
}

class NotificationSlotTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetSlotTypeByString_00001
 * @tc.desc: Test GetSlotTypeByString method is ok.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, GetSlotTypeByString_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType type;
    EXPECT_EQ(NotificationSlot::GetSlotTypeByString(NotificationSlot::CONTENT_INFORMATION, type), true);
    EXPECT_EQ(type, NotificationConstant::SlotType::CONTENT_INFORMATION);
}

/**
 * @tc.name: GetSlotTypeByString_00002
 * @tc.desc: Test GetSlotTypeByString method is false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, GetSlotTypeByString_00002, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType type;
    const std::string inputStr = "others";
    EXPECT_EQ(NotificationSlot::GetSlotTypeByString(inputStr, type), false);
}

/**
 * @tc.name: GetSlotFlags_00001
 * @tc.desc: Test GetSlotTypeByString method is false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, GetSlotFlags_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot;
    notificationSlot.SetType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    ASSERT_EQ(notificationSlot.GetId(), "EMERGENCY_INFORMATION");

    notificationSlot.SetSlotFlags(1);
    ASSERT_EQ(notificationSlot.GetSlotFlags(), 1);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test GetSlotTypeByString method is false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot;
    notificationSlot.SetType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    Parcel parcel;
    auto res = notificationSlot.Marshalling(parcel);
    ASSERT_TRUE(res);
    Uri uri("123");
    notificationSlot.SetSound(uri);

    sptr<NotificationSlot> notificationSlotSptr = notificationSlot.Unmarshalling(parcel);
    ASSERT_NE(notificationSlotSptr, nullptr);
    ASSERT_NE(notificationSlotSptr->GetSound().ToString(), "123");
}

/**
 * @tc.name: MergeVectorToString_00001
 * @tc.desc: Test GetSlotTypeByString method is false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, MergeVectorToString_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot;
    notificationSlot.SetType(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    std::vector<int64_t> mergeVector;
    mergeVector.push_back(100);

    auto res = notificationSlot.MergeVectorToString(mergeVector);
    auto it = res.find("100");
    ASSERT_NE(it, std::string::npos);
}

/**
 * @tc.name: ReminderModeByType_00001
 * @tc.desc: Test Set/GetReminderModeByType dispatch for each notification type.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, ReminderModeByType_00001, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    uint32_t normalMode = 0b000011;
    uint32_t priorityMode = 0b110000;
    notificationSlot.SetReminderModeByType(normalMode, TYPE_NOTIFICATION);
    notificationSlot.SetReminderModeByType(priorityMode, TYPE_PRIORITY_NOTIFICATION);
    ASSERT_EQ(notificationSlot.GetReminderMode(), normalMode);
    ASSERT_EQ(notificationSlot.GetPriorityReminderMode(), priorityMode);
    ASSERT_EQ(notificationSlot.GetReminderModeByType(TYPE_NOTIFICATION), normalMode);
    ASSERT_EQ(notificationSlot.GetReminderModeByType(TYPE_PRIORITY_NOTIFICATION), priorityMode);
}

/**
 * @tc.name: ReminderModeByType_00002
 * @tc.desc: Test GetReminderModeByType falls back to slot default when mode is invalid.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, ReminderModeByType_00002, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot(NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    uint32_t defaultMode = notificationSlot.GetDefaultReminderMode();
    ASSERT_NE(defaultMode, INVALID_REMINDER_MODE);
    ASSERT_EQ(notificationSlot.GetReminderModeByType(TYPE_NOTIFICATION), defaultMode);
    ASSERT_EQ(notificationSlot.GetReminderModeByType(TYPE_PRIORITY_NOTIFICATION), defaultMode);
    notificationSlot.SetReminderModeByType(INVALID_REMINDER_MODE, TYPE_PRIORITY_NOTIFICATION);
    ASSERT_EQ(notificationSlot.GetPriorityReminderMode(), defaultMode);
}

/**
 * @tc.name: ReminderModeByType_00003
 * @tc.desc: Test legacy reminder mode interfaces keep consistent with ByType dispatch.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSlotTest, ReminderModeByType_00003, Function | SmallTest | Level1)
{
    NotificationSlot notificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    notificationSlot.SetReminderMode(0b101010);
    ASSERT_EQ(notificationSlot.GetReminderModeByType(TYPE_NOTIFICATION), 0b101010);
    notificationSlot.SetPriorityReminderMode(0b010101);
    ASSERT_EQ(notificationSlot.GetReminderModeByType(TYPE_PRIORITY_NOTIFICATION), 0b010101);
    ASSERT_EQ(notificationSlot.GetReminderMode(), 0b101010);
    ASSERT_EQ(notificationSlot.GetPriorityReminderMode(), 0b010101);
}
}
}