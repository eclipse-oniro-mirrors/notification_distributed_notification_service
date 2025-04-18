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

#include <functional>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "bundle_manager_helper.h"
#undef private
#undef protected

#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "access_token_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class BundleManagerHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number    : BundleManagerHelperTest_00100
 * @tc.name      : ANS_GetBundleNameByUid_0100
 * @tc.desc      : Test GetBundleNameByUid function
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00100, Function | SmallTest | Level1)
{
    pid_t callingUid = IPCSkeleton::GetCallingUid();
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    ASSERT_EQ(bundleManager->GetBundleNameByUid(callingUid), "bundleName");
}

/**
 * @tc.number    : BundleManagerHelperTest_00200
 * @tc.name      : ANS_IsSystemApp_0100
 * @tc.desc      : Test IsSystemApp function
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00200, Function | SmallTest | Level1)
{
    pid_t callingUid = 100;
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    EXPECT_TRUE(bundleManager->IsSystemApp(callingUid));
}

/**
 * @tc.number    : BundleManagerHelperTest_00300
 * @tc.name      : CheckApiCompatibility
 * @tc.desc      : Test CheckApiCompatibility function when the  bundleOption is nullptr,return is true
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00300, Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.CheckApiCompatibility(bundleOption);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number    : BundleManagerHelperTest_00301
 * @tc.name      : CheckApiCompatibility
 * @tc.desc      : Test CheckApiCompatibility function when the  bundleOption is nullptr,return is true
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00301, Level1)
{
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.CheckApiCompatibility(bundleOption);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number    : BundleManagerHelperTest_00400
 * @tc.name      : GetBundleInfoByBundleName
 * @tc.desc      : get bundleinfo by bundlename when the parameeter are normal, return is true
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00400, Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 1;
    AppExecFwk::BundleInfo bundleInfo;
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.GetBundleInfoByBundleName(bundle, userId, bundleInfo);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number    : BundleManagerHelperTest_00500
 * @tc.name      : GetDefaultUidByBundleName
 * @tc.desc      : Test GetDefaultUidByBundleName function  when the parameeter are normal
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, BundleManagerHelperTest_00500, Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 1;
    BundleManagerHelper bundleManagerHelper;
    int32_t result = bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId);
    ASSERT_EQ(result, 1000);
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
/**
 * @tc.number    : GetDistributedNotificationEnabled_00100
 * @tc.name      : GetDistributedNotificationEnabled
 * @tc.desc      : Test GetDistributedNotificationEnabled function  when the parameeter are normal
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, GetDistributedNotificationEnabled_00100, Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 1;
    BundleManagerHelper bundleManagerHelper;
    bool result = bundleManagerHelper.GetDistributedNotificationEnabled(bundle, userId);
    ASSERT_EQ(result, true);
}

/**
 * @tc.number    : GetDistributedNotificationEnabled_00101
 * @tc.name      : GetDistributedNotificationEnabled
 * @tc.desc      : Test GetDistributedNotificationEnabled function  when the parameeter are normal
 * @tc.require   : issueI5S4VP
 */
HWTEST_F(BundleManagerHelperTest, GetDistributedNotificationEnabled_00101, Level1)
{
    std::string bundle = "Bundle";
    int32_t userId = 1;
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    sptr<IRemoteObject> remoteObject;
    bundleManagerHelper->bundleMgr_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    bool result = bundleManagerHelper->GetDistributedNotificationEnabled(bundle, userId);
    ASSERT_EQ(result, true);
}
#endif

/**
 * @tc.number    : OnRemoteDied_00100
 * @tc.name      : OnRemoteDied_00100
 */
HWTEST_F(BundleManagerHelperTest, OnRemoteDied_00100, Level1)
{
    BundleManagerHelper bundleManagerHelper;
    bundleManagerHelper.OnRemoteDied(nullptr);

    ASSERT_EQ(bundleManagerHelper.bundleMgr_, nullptr);
}

/**
 * @tc.number    : GetBundleInfo_00100
 * @tc.name      : GetBundleInfo_00100
 */
HWTEST_F(BundleManagerHelperTest, GetBundleInfo_00100, Level1)
{
    BundleManagerHelper bundleManagerHelper;
    AppExecFwk::BundleInfo info;

    // need mock
    auto res = bundleManagerHelper.GetBundleInfo("test",
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, 100, info);
    ASSERT_FALSE(res);
}

/**
 * @tc.number    : GetAppIndexByUid_00100
 * @tc.name      : GetAppIndexByUid_00100
 */
HWTEST_F(BundleManagerHelperTest, GetAppIndexByUid_00100, Level1)
{
    BundleManagerHelper bundleManagerHelper;
    AppExecFwk::BundleInfo info;

    // need mock
    auto res = bundleManagerHelper.GetAppIndexByUid(100);
    ASSERT_NE(res, 9999);
}

/**
 * @tc.number    : GetDefaultUidByBundleName_00100
 * @tc.name      : GetDefaultUidByBundleName_00100
 */
HWTEST_F(BundleManagerHelperTest, GetDefaultUidByBundleName_00100, Level1)
{
    BundleManagerHelper bundleManagerHelper;
    // need mock
    auto res = bundleManagerHelper.GetDefaultUidByBundleName("test", 100, 0);
    ASSERT_NE(res, 9999);
}
}  // namespace Notification
}  // namespace OHOS
