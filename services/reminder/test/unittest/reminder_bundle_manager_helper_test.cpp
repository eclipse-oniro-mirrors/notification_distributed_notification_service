/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "reminder_bundle_manager_helper.h"

#include "mock_service_registry.h"
#include "mock_bundle_mgr_interface.h"

using namespace testing::ext;
namespace OHOS::Notification {
class ReminderBundleManagerHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.number    : ReminderBundleManagerHelperTest_001
 * @tc.name      : ReminderBundleManagerHelperTest_001
 * @tc.desc      : test Connect function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_001, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    // test bundleMgr == nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    helper.Connect();
    EXPECT_EQ(helper.bundleMgr_, nullptr);
    helper.Disconnect();

    // test bundleMgr != nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    helper.Connect();
    EXPECT_NE(helper.bundleMgr_, nullptr);
    helper.Disconnect();
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_002
 * @tc.name      : ReminderBundleManagerHelperTest_002
 * @tc.desc      : test GetBundleNameByUid function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_002, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    // bundleMgr_ == nullptr -> return ""
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    std::string result = helper.GetBundleNameByUid(20020035);
    EXPECT_EQ(result, "");

    // bundleMgr_ != nullptr -> return target
    sptr<MockIBundleMgr> mockBundleMgr = new MockIBundleMgr();
    helper.bundleMgr_ = mockBundleMgr;
    std::string expect = "com.test.test";
    EXPECT_CALL(*mockBundleMgr, GetNameForUid(testing::_, testing::_)).Times(1)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(expect), testing::Return(0)));
    result = helper.GetBundleNameByUid(20020035);
    EXPECT_EQ(result, expect);
    helper.bundleMgr_ = nullptr;
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_003
 * @tc.name      : ReminderBundleManagerHelperTest_003
 * @tc.desc      : test GetDefaultUidByBundleName function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_003, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    // bundleMgr_ == nullptr -> return -1
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    int32_t uid = helper.GetDefaultUidByBundleName("com.test.test", 100);
    EXPECT_EQ(uid, -1);

    // bundleMgr_ != nullptr -> return target
    sptr<MockIBundleMgr> mockBundleMgr = new MockIBundleMgr();
    helper.bundleMgr_ = mockBundleMgr;
    EXPECT_CALL(*mockBundleMgr, GetUidByBundleName(testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(20020035));
    uid = helper.GetDefaultUidByBundleName("com.test.test", 100);
    EXPECT_EQ(uid, 20020035);
    helper.bundleMgr_ = nullptr;
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_004
 * @tc.name      : ReminderBundleManagerHelperTest_004
 * @tc.desc      : test GetBundleInfo function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_004, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    // bundleMgr_ == nullptr -> return false
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = helper.GetBundleInfo("com.test.test", AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        100, bundleInfo);
    EXPECT_EQ(ret, false);

    // bundleMgr_ != nullptr -> return target
    sptr<MockIBundleMgr> mockBundleMgr = new MockIBundleMgr();
    helper.bundleMgr_ = mockBundleMgr;
    AppExecFwk::BundleInfo mockBundleInfo;
    EXPECT_CALL(*mockBundleMgr, GetBundleInfo(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<2>(mockBundleInfo), testing::Return(true)));
    ret = helper.GetBundleInfo("com.test.test", AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        100, bundleInfo);
    EXPECT_EQ(ret, true);
    helper.bundleMgr_ = nullptr;
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_005
 * @tc.name      : ReminderBundleManagerHelperTest_005
 * @tc.desc      : test GetAppIndexByUid function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_005, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    // bundleMgr_ == nullptr -> return 0
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    int32_t appIndex = helper.GetAppIndexByUid(20020035);
    EXPECT_EQ(appIndex, 0);

    // bundleMgr_ != nullptr -> return target
    sptr<MockIBundleMgr> mockBundleMgr = new MockIBundleMgr();
    helper.bundleMgr_ = mockBundleMgr;
    EXPECT_CALL(*mockBundleMgr, GetNameAndIndexForUid(testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<2>(1), testing::Return(0)));
    appIndex = helper.GetAppIndexByUid(20020035);
    EXPECT_EQ(appIndex, 1);
    helper.bundleMgr_ = nullptr;
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_006
 * @tc.name      : ReminderBundleManagerHelperTest_006
 * @tc.desc      : test GetAppIndexByUid function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_006, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    // bundleMgr_ == nullptr -> return false
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    bool isInRule = helper.CheckControlRule(100, 20020035, "com.test.test");
    EXPECT_EQ(isInRule, false);

    // bundleMgr_ != nullptr and appControlMgr == nullptr -> return false
    sptr<MockIBundleMgr> mockBundleMgr = new MockIBundleMgr();
    helper.bundleMgr_ = mockBundleMgr;
    EXPECT_CALL(*mockBundleMgr, GetAppControlProxy())
        .Times(1).WillOnce(testing::Return(nullptr));
    isInRule = helper.CheckControlRule(100, 20020035, "com.test.test");
    EXPECT_EQ(isInRule, false);

    // bundleMgr_ != nullptr and appControlMgr != nullptr and reulst is empty -> return false
    sptr<MockIAppControlMgr> mockAppControl = new MockIAppControlMgr();
    EXPECT_CALL(*mockBundleMgr, GetAppControlProxy())
        .Times(1).WillOnce(testing::Return(mockAppControl));
    std::vector<AppExecFwk::DisposedRule> disposedRuleList;
    EXPECT_CALL(*mockAppControl, GetAbilityRunningControlRule(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<2>(disposedRuleList), testing::Return(0)));
    isInRule = helper.CheckControlRule(100, 20020035, "com.test.test");
    EXPECT_EQ(isInRule, false);
    helper.bundleMgr_ = nullptr;
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_007
 * @tc.name      : ReminderBundleManagerHelperTest_007
 * @tc.desc      : test GetAppIndexByUid function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_007, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper helper;
    sptr<MockIBundleMgr> mockBundleMgr = new MockIBundleMgr();
    helper.bundleMgr_ = mockBundleMgr;
    sptr<MockIAppControlMgr> mockAppControl = new MockIAppControlMgr();
    EXPECT_CALL(*mockBundleMgr, GetAppControlProxy())
        .Times(1).WillOnce(testing::Return(mockAppControl));

    std::vector<AppExecFwk::DisposedRule> disposedRuleList;
    AppExecFwk::DisposedRule rule;
    rule.callerName = "1111";
    disposedRuleList.push_back(rule);
    rule.callerName = "7007";
    disposedRuleList.push_back(rule);
    EXPECT_CALL(*mockAppControl, GetAbilityRunningControlRule(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<2>(disposedRuleList), testing::Return(0)));
    bool isInRule = helper.CheckControlRule(100, 20020035, "com.test.test");
    EXPECT_EQ(isInRule, true);
    helper.bundleMgr_ = nullptr;
}
}  // namespace OHOS::Notification