/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "notification_rdb_hook_mgr.h"
#include "gtest/gtest.h"
#include <string>

using namespace testing::ext;

namespace OHOS::Notification::Infra {
class NtfRdbHookMgrTest : public ::testing::Test {
public:
    void SetUp() override {
    }

    void TearDown() override {}
};

bool DummyUpgradeMigrate(const std::string &oldValue, std::string &newValue)
{
    newValue = oldValue + "_migrated";
    return true;
}

void DummyOperationFailReport(int32_t sceneId, int32_t branchId, int32_t errCode, const std::string &errMsg)
{
    // do nothing
}

void DummySendUserDataSizeHisysevent()
{
    // do nothing
}

/**
 * @tc.name: OnRdbUpgradeLiveviewMigrate_100
 * @tc.desc: Verify OnRdbUpgradeLiveviewMigrate executes the registered upgrade migration callback when initialized,
 *           transforming old value to new value correctly.
 * @tc.type: FUNC
 */
HWTEST_F(NtfRdbHookMgrTest, OnRdbUpgradeLiveviewMigrate_100, Function | SmallTest | Level1)
{
    NtfRdbHook hooks = {
        .OnRdbUpgradeLiveviewMigrate = DummyUpgradeMigrate,
    };

    NtfRdbHookMgr hookMgr(hooks);
    std::string oldValue = "old";
    std::string newValue;
    EXPECT_TRUE(hookMgr.OnRdbUpgradeLiveviewMigrate(oldValue, newValue));
    EXPECT_EQ(newValue, "old_migrated");
}

/**
 * @tc.name: OnRdbUpgradeLiveviewMigrate_200
 * @tc.desc: Verify OnRdbUpgradeLiveviewMigrate returns false when upgrade migration callback is nullptr, even after
 *           initialization.
 * @tc.type: FUNC
 */
HWTEST_F(NtfRdbHookMgrTest, OnRdbUpgradeLiveviewMigrate_200, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    NtfRdbHookMgr hookMgr(hooks);
    std::string oldValue = "old";
    std::string newValue;
    EXPECT_FALSE(hookMgr.OnRdbUpgradeLiveviewMigrate(oldValue, newValue));
}

/**
 * @tc.name: OnRdbOperationFailReport_100
 * @tc.desc: Verify OnRdbOperationFailReport executes the registered fail report callback with correct parameters
 *           when initialized.
 * @tc.type: FUNC
 */
HWTEST_F(NtfRdbHookMgrTest, OnRdbOperationFailReport_100, Function | SmallTest | Level1)
{
    NtfRdbHook hooks = {
        .OnRdbOperationFailReport = DummyOperationFailReport,
    };
    NtfRdbHookMgr hookMgr(hooks);
    EXPECT_TRUE(hookMgr.OnRdbOperationFailReport(1, 2, 3, "error"));
}

/**
 * @tc.name: OnRdbOperationFailReport_200
 * @tc.desc: Verify OnRdbOperationFailReport returns false when operation failure report callback is nullptr,
 *           preventing callback invocation.
 * @tc.type: FUNC
 */
HWTEST_F(NtfRdbHookMgrTest, OnRdbOperationFailReport_200, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    NtfRdbHookMgr hookMgr(hooks);
    EXPECT_FALSE(hookMgr.OnRdbOperationFailReport(1, 2, 3, "error"));
}

/**
 * @tc.name: OnSendUserDataSizeHisysevent_100
 * @tc.desc: Verify OnSendUserDataSizeHisysevent executes the registered user data size event report callback
 *           successfully when initialized.
 * @tc.type: FUNC
 */
HWTEST_F(NtfRdbHookMgrTest, OnSendUserDataSizeHisysevent_100, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    hooks.OnSendUserDataSizeHisysevent = DummySendUserDataSizeHisysevent;
    NtfRdbHookMgr hookMgr(hooks);
    EXPECT_TRUE(hookMgr.OnSendUserDataSizeHisysevent());
}

/**
 * @tc.name: OnSendUserDataSizeHisysevent_200
 * @tc.desc: Verify OnSendUserDataSizeHisysevent returns false when user data size hisysevent callback is nullptr,
 *           preventing event reporting.
 * @tc.type: FUNC
 */
HWTEST_F(NtfRdbHookMgrTest, OnSendUserDataSizeHisysevent_200, Function | SmallTest | Level1)
{
    NtfRdbHook hooks;
    NtfRdbHookMgr hookMgr(hooks);
    EXPECT_FALSE(hookMgr.OnSendUserDataSizeHisysevent());
}

} // namespace OHOS::Notification::Infra