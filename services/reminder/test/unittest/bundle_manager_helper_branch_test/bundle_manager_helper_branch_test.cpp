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

#include <functional>
#include <gtest/gtest.h>

#include "reminder_ut_constant.h"
#include "reminder_bundle_manager_helper.h"
#include "mock_service_registry.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class BundleManagerHelperBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : BundleManagerHelper_00100
 * @tc.name      : BundleManagerHelper_00100
 * @tc.desc      : test GetBundleNameByUid function and bundleMgr_ != nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelperTest_00100, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    int32_t uid = 1;
    ASSERT_EQ("", bundleManagerHelper.GetBundleNameByUid(uid));
}

/**
 * @tc.number    : BundleManagerHelper_00200
 * @tc.name      : BundleManagerHelper_00200
 * @tc.desc      : test GetBundleNameByUid function and bundleMgr_ == nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00200, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    int32_t uid = 1;
    ASSERT_EQ("", bundleManagerHelper.GetBundleNameByUid(uid));
}

/**
 * @tc.number    : BundleManagerHelper_00800
 * @tc.name      : BundleManagerHelper_00800
 * @tc.desc      : test Connect function and systemAbilityManager is nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00800, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderBundleManagerHelper> bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : BundleManagerHelper_00900
 * @tc.name      : BundleManagerHelper_00900
 * @tc.desc      : test Connect function and systemAbilityManager is not nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00900, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderBundleManagerHelper> bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    // test Connect and bundleMgr_ == nullptr
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : BundleManagerHelper_01000
 * @tc.name      : BundleManagerHelper_01000
 * @tc.desc      : test Connect function and bundleMgr_ != nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_01000, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderBundleManagerHelper> bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    bundleManagerHelper->Connect();
    // test Connect and bundleMgr_ != nullptr
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : BundleManagerHelper_01100
 * @tc.name      : BundleManagerHelper_01100
 * @tc.desc      : test Disconnect function and bundleMgr_ != nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_01100, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderBundleManagerHelper> bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    bundleManagerHelper->Connect();
    bundleManagerHelper->Disconnect();
}

/**
 * @tc.number    : BundleManagerHelper_01200
 * @tc.name      : BundleManagerHelper_01200
 * @tc.desc      : test Disconnect function and bundleMgr_ == nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_01200, Function | SmallTest | Level1)
{
    std::shared_ptr<ReminderBundleManagerHelper> bundleManagerHelper = std::make_shared<ReminderBundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    bundleManagerHelper->Disconnect();
}

/**
 * @tc.number    : BundleManagerHelper_01300
 * @tc.name      : BundleManagerHelper_01300
 * @tc.desc      : test GetDefaultUidByBundleName function and bundleMgr_ == nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_01300, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    MockServiceRegistry::MockGetSystemAbilityManager(true);
    std::string bundle = "aa";
    int32_t userId = 1;
    ASSERT_EQ(-1, bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId));
}

/**
 * @tc.number    : BundleManagerHelper_01400
 * @tc.name      : BundleManagerHelper_01400
 * @tc.desc      : test GetDefaultUidByBundleName function and bundleMgr_ != nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_01400, Function | SmallTest | Level1)
{
    ReminderBundleManagerHelper bundleManagerHelper;
    MockServiceRegistry::MockGetSystemAbilityManager(false);
    std::string bundle = "aa";
    int32_t userId = 1;
    ASSERT_EQ(-1, bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId));
}

}  // namespace Notification
}  // namespace OHOS
