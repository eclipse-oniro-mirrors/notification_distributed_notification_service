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

#include "ans_inner_errors.h"
#define private public
#include "distributed_preferences.h"
#include "distributed_preferences_info.h"

extern void MockGetEntriesFromDistributedDB(bool mockRet);
extern void MockPutToDistributedDB(bool mockRet);
extern void MockDeleteToDistributedDB(bool mockRet);
extern void MockClearDatabase(bool mockRet);

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
const std::string DISTRIBUTED_LABEL = "distributed";
const std::string DELIMITER = "|";
const std::string MAIN_LABEL = "ans_main";
const std::string BUNDLE_LABEL = "bundle";
const std::string WITHOUT_APP = "without_app";
}
class DistributedPreferencesBranchTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<DistributedPreferences> distributedPreferences_;
};

void DistributedPreferencesBranchTest::SetUp()
{
    distributedPreferences_ = DistributedPreferences::GetInstance();
}

void DistributedPreferencesBranchTest::TearDown()
{
    distributedPreferences_ = nullptr;
    DistributedPreferences::DestroyInstance();
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00100
 * @tc.number    : DistributedPreferencesBranchTest_00100
 * @tc.desc      : test ResolveDistributedKey function and distributedLabelEndPosition == std::string::npos.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00100, Function | SmallTest | Level1)
{
    DistributedKv::Entry entry;
    entry.key = "DistributedPreferencesBranchTest_00100";
    EXPECT_EQ(distributedPreferences_->ResolveDistributedKey(entry), false);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00200
 * @tc.number    : DistributedPreferencesBranchTest_00200
 * @tc.desc      : test ResolveDistributedKey function and typeLabelPosition != std::string::npos.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00200, Function | SmallTest | Level1)
{
    DistributedKv::Entry entry;
    entry.key = DISTRIBUTED_LABEL + DELIMITER + MAIN_LABEL + DELIMITER + BUNDLE_LABEL + DELIMITER + WITHOUT_APP;
    EXPECT_EQ(distributedPreferences_->ResolveDistributedKey(entry), true);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00300
 * @tc.number    : DistributedPreferencesBranchTest_00300
 * @tc.desc      : test InitDistributedAllInfo function and GetEntriesFromDistributedDB is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00300, Function | SmallTest | Level1)
{
    MockGetEntriesFromDistributedDB(false);
    EXPECT_EQ(distributedPreferences_->InitDistributedAllInfo(), false);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00400
 * @tc.number    : DistributedPreferencesBranchTest_00400
 * @tc.desc      : test InitDistributedAllInfo function and ResolveDistributedKey is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00400, Function | SmallTest | Level1)
{
    MockGetEntriesFromDistributedDB(true);
    EXPECT_EQ(distributedPreferences_->InitDistributedAllInfo(), true);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00500
 * @tc.number    : DistributedPreferencesBranchTest_00500
 * @tc.desc      : test GetDistributedBundleKey function and bundleOption is nullptr.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00500, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string key = "DistributedPreferencesBranchTest";
    ASSERT_NE(nullptr, distributedPreferences_);
    distributedPreferences_->GetDistributedBundleKey(bundleOption, key);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00600
 * @tc.number    : DistributedPreferencesBranchTest_00600
 * @tc.desc      : test SetDistributedEnable function and PutToDistributedDB is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00600, Function | SmallTest | Level1)
{
    bool isEnable = true;
    MockPutToDistributedDB(false);
    EXPECT_EQ(distributedPreferences_->SetDistributedEnable(isEnable), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00700
 * @tc.number    : DistributedPreferencesBranchTest_00700
 * @tc.desc      : test SetDistributedBundleEnable function and bundleOption is nullptr.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00700, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool isEnable = true;
    EXPECT_EQ(distributedPreferences_->SetDistributedBundleEnable(bundleOption, isEnable), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00800
 * @tc.number    : DistributedPreferencesBranchTest_00800
 * @tc.desc      : test SetDistributedBundleEnable function and PutToDistributedDB is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00800, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("<bundleName>", 783);
    bool isEnable = true;
    MockPutToDistributedDB(false);
    EXPECT_EQ(distributedPreferences_->SetDistributedBundleEnable(bundleOption, isEnable),
        ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_00900
 * @tc.number    : DistributedPreferencesBranchTest_00900
 * @tc.desc      : test GetDistributedBundleEnable function and bundleOption is nullptr.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_00900, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    bool isEnable = true;
    EXPECT_EQ(distributedPreferences_->GetDistributedBundleEnable(bundleOption, isEnable), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_01000
 * @tc.number    : DistributedPreferencesBranchTest_01000
 * @tc.desc      : test DeleteDistributedBundleInfo function and bundleOption is nullptr.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_01000, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    EXPECT_EQ(distributedPreferences_->DeleteDistributedBundleInfo(bundleOption), ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_01100
 * @tc.number    : DistributedPreferencesBranchTest_01100
 * @tc.desc      : test DeleteDistributedBundleInfo function and DeleteToDistributedDB is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_01100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("<bundleName>", 783);
    MockDeleteToDistributedDB(false);
    EXPECT_EQ(
        distributedPreferences_->DeleteDistributedBundleInfo(bundleOption), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_01200
 * @tc.number    : DistributedPreferencesBranchTest_01200
 * @tc.desc      : test ClearDataInRestoreFactorySettings function and ClearDatabase is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_01200, Function | SmallTest | Level1)
{
    MockClearDatabase(false);
    EXPECT_EQ(distributedPreferences_->ClearDataInRestoreFactorySettings(), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}

/**
 * @tc.name      : DistributedPreferencesBranchTest_01300
 * @tc.number    : DistributedPreferencesBranchTest_01300
 * @tc.desc      : test SetSyncEnabledWithoutApp function and PutToDistributedDB is false.
 */
HWTEST_F(DistributedPreferencesBranchTest, DistributedPreferencesBranchTest_01300, Function | SmallTest | Level1)
{
    MockPutToDistributedDB(false);
    int32_t userId = 1;
    bool enabled = true;
    EXPECT_EQ(distributedPreferences_->SetSyncEnabledWithoutApp(userId, enabled), ERR_ANS_DISTRIBUTED_OPERATION_FAILED);
}
}  // namespace Notification
}  // namespace OHOS