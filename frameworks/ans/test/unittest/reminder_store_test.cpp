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
#include "reminder_store.h"
#undef private
#undef protected
#include "reminder_helper.h"
#include "notification_preferences.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
    constexpr int32_t NON_SYSTEM_APP_UID = 1000;
    const std::string TEST_DEFUALT_BUNDLE = "bundleName";
    const int32_t STATE_FAIL = -1;
}
class ReminderStoreTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ReminderHelper::CancelAllReminders();
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown()
    {
        ReminderHelper::CancelAllReminders();
    }
    static sptr<NotificationBundleOption> bundleOption_;
};

sptr<NotificationBundleOption> ReminderStoreTest::bundleOption_ =
    new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);

/**
 * @tc.name: Init_00001
 * @tc.desc: Test Init parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Init_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Init();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: InitData_00001
 * @tc.desc: Test InitData parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, InitData_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.InitData();
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Delete_00001
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00001, Function | SmallTest | Level1)
{
    int32_t reminderId = 1;
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete(reminderId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Delete_00002
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00002, Function | SmallTest | Level1)
{
    std::string pkg = "pkg";
    int32_t userId = 1;
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete(pkg, userId);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Delete_00003
 * @tc.desc: Test Delete parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Delete_00003, Function | SmallTest | Level1)
{
    std::string deleteCondition = "deleteCondition";
    ReminderStore reminderStore;
    int32_t ret = reminderStore.Delete(deleteCondition);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Insert_00001
 * @tc.desc: Test Insert parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Insert_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderStore reminderStore;
    int64_t ret = reminderStore.Insert(reminder, bundleOption_);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Update_00001
 * @tc.desc: Test Update parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Update_00001, Function | SmallTest | Level1)
{
    sptr<ReminderRequest> reminder = nullptr;
    ReminderStore reminderStore;
    int64_t ret = reminderStore.Update(reminder, bundleOption_);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Query_00001
 * @tc.desc: Test Query parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, Query_00001, Function | SmallTest | Level1)
{
    std::string queryCondition = "queryCondition";
    std::string name = "it";
    ReminderStore reminderStore;
    reminderStore.GetColumnIndex(name);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> ret = reminderStore.Query(queryCondition);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: GetMaxId_00001
 * @tc.desc: Test GetMaxId parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetMaxId_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    int32_t ret = reminderStore.GetMaxId();
    EXPECT_EQ(ret, STATE_FAIL);
}

/**
 * @tc.name: GetAllValidReminders_00001
 * @tc.desc: Test GetAllValidReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetAllValidReminders_00001, Function | SmallTest | Level1)
{
    ReminderStore reminderStore;
    std::vector<sptr<ReminderRequest>> ret = reminderStore.GetAllValidReminders();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.name: GetReminders_00001
 * @tc.desc: Test GetReminders parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5VB6V
 */
HWTEST_F(ReminderStoreTest, GetReminders_00001, Function | SmallTest | Level1)
{
    std::string queryCondition = "queryCondition";
    ReminderStore reminderStore;
    std::vector<sptr<ReminderRequest>> ret = reminderStore.GetReminders(queryCondition);
    EXPECT_EQ(ret.size(), 0);
}
}
}