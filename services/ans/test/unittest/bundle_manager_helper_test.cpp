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
#include "mock_bundle_manager_helper.h"

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

#ifdef ANS_FEATURE_ORIGINAL_DISTRIBUTED
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
    ASSERT_TRUE(res);
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

namespace {
const std::string VALID_ICON_PNG_BASE64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUA"
    "AAAJcEhZcwAADsMAAA7DAcdvqGQAAAARSURBVBhXY/jPwPAfhBlgDABHygf5POQJCgAAAABJRU5ErkJggg==";
const std::string VALID_ICON_DATA_URI = "data:image/png;base64," + VALID_ICON_PNG_BASE64;
}  // namespace

/**
 * @tc.number    : GetBundleIcon_00001
 * @tc.name      : ANS_GetBundleIcon_0100
 * @tc.desc      : Test GetBundleIcon with valid data uri
 */
HWTEST_F(BundleManagerHelperTest, GetBundleIcon_00001, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleInterfaceResult(ERR_OK);
    MockBundleManager::MockBundleIconData(VALID_ICON_DATA_URI);
    BundleManagerHelper bundleManagerHelper;
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    ErrCode result = bundleManagerHelper.GetBundleIcon("bundle.test", 0, icon);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_NE(icon, nullptr);
    EXPECT_GT(icon->GetWidth(), 0);
    EXPECT_GT(icon->GetHeight(), 0);
    MockBundleManager::MockBundleIconData("");
}

/**
 * @tc.number    : GetBundleIcon_InvalidPrefix_00001
 * @tc.name      : ANS_GetBundleIcon_0200
 * @tc.desc      : Test GetBundleIcon with invalid data uri prefix
 */
HWTEST_F(BundleManagerHelperTest, GetBundleIcon_InvalidPrefix_00001, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleInterfaceResult(ERR_OK);
    MockBundleManager::MockBundleIconData("http://invalid/icon.png");
    BundleManagerHelper bundleManagerHelper;
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    ErrCode result = bundleManagerHelper.GetBundleIcon("bundle.test", 0, icon);
    EXPECT_NE(result, ERR_OK);
    EXPECT_EQ(icon, nullptr);
    MockBundleManager::MockBundleIconData("");
}

/**
 * @tc.number    : GetBundleIcon_DecodeFail_00001
 * @tc.name      : ANS_GetBundleIcon_0300
 * @tc.desc      : Test GetBundleIcon with illegal base64 payload
 */
HWTEST_F(BundleManagerHelperTest, GetBundleIcon_DecodeFail_00001, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleInterfaceResult(ERR_OK);
    MockBundleManager::MockBundleIconData("data:image/png;base64,!!!illegal@@base64??");
    BundleManagerHelper bundleManagerHelper;
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    ErrCode result = bundleManagerHelper.GetBundleIcon("bundle.test", 0, icon);
    EXPECT_NE(result, ERR_OK);
    EXPECT_EQ(icon, nullptr);
    MockBundleManager::MockBundleIconData("");
}

/**
 * @tc.number    : GetBundleIcon_EmptyIcon_00002
 * @tc.name      : ANS_GetBundleIcon_0400
 * @tc.desc      : Test GetBundleIcon with empty icon string
 */
HWTEST_F(BundleManagerHelperTest, GetBundleIcon_EmptyIcon_00002, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleInterfaceResult(ERR_OK);
    MockBundleManager::MockBundleIconData("");
    BundleManagerHelper bundleManagerHelper;
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    ErrCode result = bundleManagerHelper.GetBundleIcon("bundle.test", 0, icon);
    EXPECT_NE(result, ERR_OK);
    EXPECT_EQ(icon, nullptr);
}

/**
 * @tc.number    : GetBundleIcon_00003
 * @tc.name      : ANS_GetBundleIcon_0500
 * @tc.desc      : Test GetBundleIcon with bundle resource query failure
 */
HWTEST_F(BundleManagerHelperTest, GetBundleIcon_00003, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleInterfaceResult(-1);
    BundleManagerHelper bundleManagerHelper;
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    ErrCode result = bundleManagerHelper.GetBundleIcon("bundle.test", 0, icon);
    EXPECT_NE(result, ERR_OK);
    EXPECT_EQ(icon, nullptr);
    MockBundleManager::MockBundleInterfaceResult(ERR_OK);
}

namespace {
// 400 x 400 JPEG payload (3130 bytes): non-PNG payload decoded by the image framework;
const std::string TEST_OVERSIZED_JPEG_DATA_URI = "data:image/png;base64,"
    "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUV"
    "DA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
    "T/wAARCAGQAZADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQR"
    "BRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1d"
    "nd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8"
    "QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobH"
    "BCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaX"
    "mJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD896KKK/1TP"
    "hwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK"
    "KKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiii"
    "gAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/2Q==";
}  // namespace


/**
 * @tc.number    : GetBundleIcon_OversizeNonPngIcon_00005
 * @tc.name      : ANS_GetBundleIcon_0700
 * @tc.desc      : Large non-PNG icon (400 x 400) is decoded and returned without size limits
 */
HWTEST_F(BundleManagerHelperTest, GetBundleIcon_OversizeNonPngIcon_00005, Function | SmallTest | Level1)
{
    MockBundleManager::MockBundleInterfaceResult(ERR_OK);
    MockBundleManager::MockBundleIconData(TEST_OVERSIZED_JPEG_DATA_URI);
    BundleManagerHelper bundleManagerHelper;
    std::shared_ptr<Media::PixelMap> icon = nullptr;
    ErrCode result = bundleManagerHelper.GetBundleIcon("bundle.test", 0, icon);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_NE(icon, nullptr);
    EXPECT_EQ(icon->GetWidth(), 400);
    EXPECT_EQ(icon->GetHeight(), 400);
    MockBundleManager::MockBundleIconData("");
}
}  // namespace Notification
}  // namespace OHOS
