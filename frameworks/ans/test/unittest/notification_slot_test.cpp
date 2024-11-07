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

#include "notification_slot.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
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
}
}