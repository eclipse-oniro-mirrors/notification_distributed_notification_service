/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "reminder_state.h"

using namespace testing::ext;
namespace OHOS::Notification {
class ReminderStateTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ReminderStateTest_001
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderStateTest, ReminderStateTest_001, Function | SmallTest | Level1)
{
    ReminderState state;
    state.reminderId_ = 100;
    ReminderState state2(state);
    EXPECT_EQ(state2.reminderId_, 100);
}

/**
 * @tc.name: ReminderStateTest_002
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderStateTest, ReminderStateTest_002, Function | SmallTest | Level1)
{
    ReminderState state;
    state.reminderId_ = 100;
    ReminderState state2;
    state2 = state;
    EXPECT_EQ(state2.reminderId_, 100);
}

/**
 * @tc.name: ReminderStateTest_003
 * @tc.type: FUNC
 * @tc.require: SR000GGTRD AR000GH8EF
 */
HWTEST_F(ReminderStateTest, ReminderStateTest_003, Function | SmallTest | Level1)
{
    Parcel p;
    ReminderState state;
    EXPECT_EQ(state.Marshalling(p), true);
}

/**
 * @tc.name: ReminderStateTest_004
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStateTest, ReminderStateTest_004, Function | SmallTest | Level1)
{
    bool result = false;
    Parcel parcel;
    ReminderState state;
    if (nullptr == state.Unmarshalling(parcel)) {
        result = true;
    }
    EXPECT_EQ(true, result);
}
}
