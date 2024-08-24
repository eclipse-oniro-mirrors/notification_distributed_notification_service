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

#include <memory>

#include "gtest/gtest.h"

#define private public
#include "distributed_preferences.h"
#include "distributed_preferences_info.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedPreferencesTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<DistributedPreferences> distributedPreferences_;
};

void DistributedPreferencesTest::SetUp()
{
    distributedPreferences_ = DistributedPreferences::GetInstance();
}

void DistributedPreferencesTest::TearDown()
{
    distributedPreferences_ = nullptr;
    DistributedPreferences::DestroyInstance();
}

/**
 * @tc.name      : DistributedPreferences_SetDistributedEnable_00100
 * @tc.number    : SetDistributedEnable_00100
 * @tc.desc      : Set distributed notification enable.
 */
HWTEST_F(DistributedPreferencesTest, SetDistributedEnable_00100, Function | SmallTest | Level1)
{
    bool enable = true;

    EXPECT_EQ(distributedPreferences_->SetDistributedEnable(enable), ERR_OK);
}

/**
 * @tc.name      : DistributedPreferences_GetDistributedEnable_00100
 * @tc.number    : GetDistributedEnable_00100
 * @tc.desc      : Get distributed notification enable.
 */
HWTEST_F(DistributedPreferencesTest, GetDistributedEnable_00100, Function | SmallTest | Level1)
{
    bool enable;

    EXPECT_EQ(distributedPreferences_->GetDistributedEnable(enable), ERR_OK);
}

/**
 * @tc.name      : DistributedPreferences_SetDistributedBundleEnable_00100
 * @tc.number    : SetDistributedBundleEnable_00100
 * @tc.desc      : Set distributed notification enable of a bundle.
 */
HWTEST_F(DistributedPreferencesTest, SetDistributedBundleEnable_00100, Function | SmallTest | Level1)
{
    bool enable = true;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("<bundleName>", 783);

    EXPECT_EQ(distributedPreferences_->SetDistributedBundleEnable(bundleOption, enable), ERR_OK);
}

/**
 * @tc.name      : DistributedPreferences_SetDistributedBundleEnable_00200
 * @tc.number    : SetDistributedBundleEnable_00200
 * @tc.desc      : Set distributed notification enable of a bundle.
 */
HWTEST_F(DistributedPreferencesTest, SetDistributedBundleEnable_00200, Function | SmallTest | Level1)
{
    bool enable = true;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("<bundleName>", 783);

    EXPECT_EQ(distributedPreferences_->SetDistributedBundleEnable(bundleOption, enable), ERR_OK);
}

/**
 * @tc.name      : DistributedPreferences_ClearDataInRestoreFactorySettings_00100
 * @tc.number    : ClearDataInRestoreFactorySettings_00100
 * @tc.desc      : Clear all data when system restore factory settings.
 */
HWTEST_F(DistributedPreferencesTest, ClearDataInRestoreFactorySettings_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ(distributedPreferences_->ClearDataInRestoreFactorySettings(), ERR_OK);
}

/**
 * @tc.name      : DistributedPreferences_DeleteDistributedBundleInfo_00100
 * @tc.number    : DeleteDistributedBundleInfo_00100
 * @tc.desc      : Clear bundle info with distributed notification enable state.
 */
HWTEST_F(DistributedPreferencesTest, DeleteDistributedBundleInfo_00100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("<bundleName>", 783);
    EXPECT_EQ(distributedPreferences_->DeleteDistributedBundleInfo(bundleOption), ERR_OK);
}

/**
 * @tc.name      : DistributedPreferences_ResolveDistributedEnable_00100
 * @tc.number    : ResolveDistributedEnable_00100
 * @tc.desc      : text ResolveDistributedEnable function.
 */
HWTEST_F(DistributedPreferencesTest, ResolveDistributedEnable_00100, Function | SmallTest | Level1)
{
    std::string value("<value>");
    EXPECT_EQ(distributedPreferences_->ResolveDistributedEnable(value), true);
}

/**
 * @tc.name      : DistributedPreferences_ResolveDistributedBundleEnable_00100
 * @tc.number    : ResolveDistributedBundleEnable_00100
 * @tc.desc      : text ResolveDistributedBundleEnable function.
 */
HWTEST_F(DistributedPreferencesTest, ResolveDistributedBundleEnable_00100, Function | SmallTest | Level1)
{
    int32_t startPos = 0;
    std::string key("<key>");
    std::string value("<value>");
    EXPECT_EQ(distributedPreferences_->ResolveDistributedBundleEnable(key, startPos, value), false);
}

/**
 * @tc.name      : DistributedPreferences_ResolveDistributedBundleEnable_00200
 * @tc.number    : ResolveDistributedBundleEnable_00200
 * @tc.desc      : text ResolveDistributedBundleEnable function.
 */
HWTEST_F(DistributedPreferencesTest, ResolveDistributedBundleEnable_00200, Function | SmallTest | Level1)
{
    int32_t startPos = 1;
    std::string key("bundleName");
    std::string value("<value>");
    EXPECT_EQ(distributedPreferences_->ResolveDistributedBundleEnable(key, startPos, value), false);
}

/**
 * @tc.name      : DistributedPreferences_ResolveDistributedBundleEnable_00300
 * @tc.number    : ResolveDistributedBundleEnable_00300
 * @tc.desc      : text ResolveDistributedBundleEnable function.
 */
HWTEST_F(DistributedPreferencesTest, ResolveDistributedBundleEnable_00300, Function | SmallTest | Level1)
{
    int32_t startPos = 1;
    std::string key("bundleName|100101");
    std::string value("<value>");
    EXPECT_EQ(distributedPreferences_->ResolveDistributedBundleEnable(key, startPos, value), true);
}

/**
 * @tc.name      : DistributedPreferences_ResolveSyncWithoutAppEnable_00100
 * @tc.number    : ResolveSyncWithoutAppEnable_00100
 * @tc.desc      : text ResolveSyncWithoutAppEnable function.
 */
HWTEST_F(DistributedPreferencesTest, ResolveSyncWithoutAppEnable_00100, Function | SmallTest | Level1)
{
    int32_t startPos = 1;
    std::string key("<key>");
    std::string value("<value>");
    EXPECT_EQ(distributedPreferences_->ResolveSyncWithoutAppEnable(key, startPos, value), true);
}

/**
 * @tc.name      : DistributedPreferencesInfo_GetSyncEnabledWithoutApp_00100
 * @tc.number    : GetSyncEnabledWithoutApp_00100
 * @tc.desc      : text GetSyncEnabledWithoutApp function.
 */
HWTEST_F(DistributedPreferencesTest, GetSyncEnabledWithoutApp_00100, Function | SmallTest | Level1)
{
    bool enabled = true;
    DistributedPreferencesInfo distributedPreferencesInfo_;
    distributedPreferencesInfo_.GetSyncEnabledWithoutApp(0, enabled);
    EXPECT_EQ(enabled, false);
}

/**
 * @tc.name      : DistributedPreferencesInfo_GetDistributedBundleEnable_00100
 * @tc.number    : GetDistributedBundleEnable_00100
 * @tc.desc      : text GetDistributedBundleEnable function.
 */
HWTEST_F(DistributedPreferencesTest, GetDistributedBundleEnable_00100, Function | SmallTest | Level1)
{
    DistributedPreferencesInfo distributedPreferencesInfo_;
    bool res = distributedPreferencesInfo_.GetDistributedBundleEnable("bundle", 0);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name      : DistributedPreferencesInfo_GetDistributedBundleEnable_00200
 * @tc.number    : GetDistributedBundleEnable_00200
 * @tc.desc      : text GetDistributedBundleEnable function.
 */
HWTEST_F(DistributedPreferencesTest, GetDistributedBundleEnable_00200, Function | SmallTest | Level1)
{
    DistributedPreferencesInfo distributedPreferencesInfo_;
    bool res = distributedPreferencesInfo_.GetDistributedBundleEnable("com.ohos.mms", 0);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name      : DistributedPreferencesInfo_GetSyncEnabledWithoutApp_00200
 * @tc.number    : GetSyncEnabledWithoutApp_00200
 * @tc.desc      : text GetSyncEnabledWithoutApp function.
 */
HWTEST_F(DistributedPreferencesTest, GetSyncEnabledWithoutApp_00200, Function | SmallTest | Level1)
{
    bool enabled = true;
    DistributedPreferencesInfo distributedPreferencesInfo_;
    distributedPreferencesInfo_.GetSyncEnabledWithoutApp(100, enabled);
    EXPECT_EQ(enabled, false);
}
}  // namespace Notification
}  // namespace OHOS