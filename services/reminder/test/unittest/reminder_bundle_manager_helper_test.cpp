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
 * @tc.desc      : test Connect function and systemAbilityManager is nullptr
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_001, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_002
 * @tc.name      : ReminderBundleManagerHelperTest_002
 * @tc.desc      : test Connect function and systemAbilityManager is not nullptr
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_002, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    // test Connect and bundleMgr_ == nullptr
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_003
 * @tc.name      : ReminderBundleManagerHelperTest_003
 * @tc.desc      : test Connect function and bundleMgr_ != nullptr
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_003, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    bundleManagerHelper->Connect();
    // test Connect and bundleMgr_ != nullptr
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_004
 * @tc.name      : ReminderBundleManagerHelperTest_004
 * @tc.desc      : test Disconnect function and bundleMgr_ != nullptr
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_004, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    bundleManagerHelper->Connect();
    bundleManagerHelper->Disconnect();
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_005
 * @tc.name      : ReminderBundleManagerHelperTest_005
 * @tc.desc      : test Disconnect function and bundleMgr_ == nullptr
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_005, Function | SmallTest | Level1)
{
    auto bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    bundleManagerHelper->Disconnect();
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_006
 * @tc.name      : ReminderBundleManagerHelperTest_006
 * @tc.desc      : test GetBundleNameByUid function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_006, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    int32_t uid = 1;
    // bundleMgr_ == nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    ASSERT_EQ("", bundleManagerHelper.GetBundleNameByUid(uid));

    // bundleMgr_ != nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    ASSERT_EQ("", bundleManagerHelper.GetBundleNameByUid(uid));
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_007
 * @tc.name      : ReminderBundleManagerHelperTest_007
 * @tc.desc      : test GetDefaultUidByBundleName function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_007, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    std::string bundle = "aa";
    int32_t userId = 1;
    // bundleMgr_ == nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    ASSERT_EQ(-1, bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId));

    // bundleMgr_ != nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    ASSERT_EQ(-1, bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId));
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_008
 * @tc.name      : ReminderBundleManagerHelperTest_008
 * @tc.desc      : test GetDefaultUidByBundleName function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_008, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    std::string bundle = "aa";
    int32_t uid = 1;
    AppExecFwk::BundleInfo bundleInfo;
    // bundleMgr_ == nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    ASSERT_EQ(false, bundleManagerHelper.GetBundleInfo(bundle, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        uid, bundleInfo));

    // bundleMgr_ != nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    ASSERT_EQ(false, bundleManagerHelper.GetBundleInfo(bundle, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        uid, bundleInfo));
}

/**
 * @tc.number    : ReminderBundleManagerHelperTest_009
 * @tc.name      : ReminderBundleManagerHelperTest_009
 * @tc.desc      : test GetAppIndexByUid function
 */
HWTEST_F(ReminderBundleManagerHelperTest, ReminderBundleManagerHelperTest_009, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    int32_t uid = 1;
    // bundleMgr_ == nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    ASSERT_EQ(0, bundleManagerHelper.GetAppIndexByUid(uid));

    // bundleMgr_ != nullptr
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    ASSERT_EQ(0, bundleManagerHelper.GetAppIndexByUid(uid));
}
}  // namespace OHOS::Notification