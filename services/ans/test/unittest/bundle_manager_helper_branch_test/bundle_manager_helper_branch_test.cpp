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

#include "ans_ut_constant.h"
#define private public
#define protected public
#include "bundle_manager_helper.h"
#undef private
#undef protected

extern void MockGetSystemAbilityManager(bool mockRet);

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
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(false);
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
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);
    int32_t uid = 1;
    ASSERT_EQ("", bundleManagerHelper.GetBundleNameByUid(uid));
}

/**
 * @tc.number    : BundleManagerHelper_00300
 * @tc.name      : BundleManagerHelper_00300
 * @tc.desc      : test IsSystemApp function and bundleMgr_ != nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00300, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(false);
    int32_t uid = 1;
    ASSERT_EQ(false, bundleManagerHelper.IsSystemApp(uid));
}

/**
 * @tc.number    : BundleManagerHelper_00400
 * @tc.name      : BundleManagerHelper_00400
 * @tc.desc      : test IsSystemApp function and bundleMgr_ == nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00400, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);
    int32_t uid = 1;
    ASSERT_EQ(false, bundleManagerHelper.IsSystemApp(uid));
}

/**
 * @tc.number    : BundleManagerHelper_00500
 * @tc.name      : BundleManagerHelper_00500
 * @tc.desc      : test GetBundleInfoByBundleName function and bundleMgr_ == nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00500, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);
    bundleManagerHelper.Connect();
    std::string bundle = "aa";
    int32_t userId = 1;
    AppExecFwk::BundleInfo bundleInfo;
    ASSERT_EQ(false, bundleManagerHelper.GetBundleInfoByBundleName(bundle, userId, bundleInfo));
}

/**
 * @tc.number    : BundleManagerHelper_00600
 * @tc.name      : BundleManagerHelper_00600
 * @tc.desc      : test GetBundleInfoByBundleName function and bundleMgr_ != nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00600, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(false);
    bundleManagerHelper.Connect();
    std::string bundle = "aa";
    int32_t userId = 1;
    AppExecFwk::BundleInfo bundleInfo;
    ASSERT_EQ(false, bundleManagerHelper.GetBundleInfoByBundleName(bundle, userId, bundleInfo));
}

/**
 * @tc.number    : BundleManagerHelper_00700
 * @tc.name      : BundleManagerHelper_00700
 * @tc.desc      : test CheckApiCompatibility function and GetBundleInfoByBundleName is false
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00700, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    ASSERT_EQ(false, bundleManagerHelper.CheckApiCompatibility(bundleOption));
}

/**
 * @tc.number    : BundleManagerHelper_00800
 * @tc.name      : BundleManagerHelper_00800
 * @tc.desc      : test Connect function and systemAbilityManager is nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00800, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockGetSystemAbilityManager(true);
    bundleManagerHelper->Connect();
}

/**
 * @tc.number    : BundleManagerHelper_00900
 * @tc.name      : BundleManagerHelper_00900
 * @tc.desc      : test Connect function and systemAbilityManager is not nullptr
 */
HWTEST_F(BundleManagerHelperBranchTest, BundleManagerHelper_00900, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockGetSystemAbilityManager(false);
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
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockGetSystemAbilityManager(false);
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
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
    ASSERT_NE(nullptr, bundleManagerHelper);
    MockGetSystemAbilityManager(false);
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
    std::shared_ptr<BundleManagerHelper> bundleManagerHelper = std::make_shared<BundleManagerHelper>();
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
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);
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
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(false);
    std::string bundle = "aa";
    int32_t userId = 1;
    ASSERT_EQ(-1, bundleManagerHelper.GetDefaultUidByBundleName(bundle, userId));
}

/**
 * @tc.number    : GetBundleInfos_00001
 * @tc.name      : GetBundleInfos_00001
 * @tc.desc      : test GetBundleInfos
 */
HWTEST_F(BundleManagerHelperBranchTest, GetBundleInfos_00001, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    AppExecFwk::BundleFlag flag = AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT;
    std::vector<AppExecFwk::BundleInfo> bundleInfos;

    ASSERT_EQ(false, bundleManagerHelper.GetBundleInfos(flag, bundleInfos, 1));
}

/**
 * @tc.number    : IsAtomicServiceByBundle_00001
 * @tc.name      : IsAtomicServiceByBundle_00001
 * @tc.desc      : test IsAtomicServiceByBundle
 */
HWTEST_F(BundleManagerHelperBranchTest, IsAtomicServiceByBundle_00001, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    int32_t userId = 100;
    std::string bundleName = "testBundleName";

    ASSERT_EQ(false, bundleManagerHelper.IsAtomicServiceByBundle(bundleName, userId));
}

/**
 * @tc.number    : GetCloneBundleInfo_00001
 * @tc.name      : GetCloneBundleInfo_00001
 * @tc.desc      : test GetCloneBundleInfo
 */
HWTEST_F(BundleManagerHelperBranchTest, GetCloneBundleInfo_00001, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);

    AppExecFwk::BundleInfo bundleInfo;
    int32_t flag = (int32_t)AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT;
    auto result = bundleManagerHelper.GetCloneBundleInfo("testBundle", flag, 0, bundleInfo, 100);
    ASSERT_EQ(false, result);

    MockGetSystemAbilityManager(false);
    result = bundleManagerHelper.GetCloneBundleInfo("testBundle", flag, 0, bundleInfo, 100);
    ASSERT_EQ(false, result);
}

/**
 * @tc.number    : GetCloneAppIndexes_00001
 * @tc.name      : GGetCloneAppIndexes_00001
 * @tc.desc      : test GGetCloneAppIndexes
 */
HWTEST_F(BundleManagerHelperBranchTest, GetCloneAppIndexes_00001, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);

    std::vector<int32_t> appIndexes;
    auto result = bundleManagerHelper.GetCloneAppIndexes("testBundle", appIndexes, 100);
    ASSERT_EQ(false, result);

    MockGetSystemAbilityManager(false);
    result = bundleManagerHelper.GetCloneAppIndexes("testBundle", appIndexes, 100);
    ASSERT_EQ(true, result);
}

/**
 * @tc.number    : GetApplicationInfo_00001
 * @tc.name      : GetApplicationInfo_00001
 * @tc.desc      : test GetApplicationInfo
 */
HWTEST_F(BundleManagerHelperBranchTest, GetApplicationInfo_00001, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    MockGetSystemAbilityManager(true);

    AppExecFwk::ApplicationInfo appInfo;
    int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    auto result = bundleManagerHelper.GetApplicationInfo("testBundle", flags, 100, appInfo);
    ASSERT_EQ(-1, result);

    MockGetSystemAbilityManager(false);
    result = bundleManagerHelper.GetApplicationInfo("testBundle", flags, 100, appInfo);
    ASSERT_NE(0, result);
}

/**
 * @tc.number    : CheckSystemApp_00001
 * @tc.name      : CheckSystemApp_00001
 * @tc.desc      : test CheckSystemApp
 */
HWTEST_F(BundleManagerHelperBranchTest, CheckSystemApp_00001, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    auto result = bundleManagerHelper.CheckSystemApp("testBundle", -1);
    ASSERT_EQ(false, result);

    result = bundleManagerHelper.CheckSystemApp("testBundle", 100);
    ASSERT_EQ(false, result);
}

/**
 * @tc.number    : GetAllBundleInfo_00001
 * @tc.name      : GetAllBundleInfo_00001
 * @tc.desc      : test GetAllBundleInfo
 */
HWTEST_F(BundleManagerHelperBranchTest, GetAllBundleInfo_00001, Function | SmallTest | Level1)
{
    MockGetSystemAbilityManager(true);
    BundleManagerHelper bundleManagerHelper;
    std::map<std::string, sptr<NotificationBundleOption>> bundleOptions;
    auto result = bundleManagerHelper.GetAllBundleInfo(bundleOptions, 100);
    ASSERT_NE(result, (int32_t)ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
