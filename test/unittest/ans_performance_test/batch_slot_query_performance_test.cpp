/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "ans_inner_errors.h"
#include "ans_permission_def.h"
#include "errors.h"
#include "nativetoken_kit.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_helper.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
constexpr int64_t BATCH_QUERY_THRESHOLD_MS = 30;
constexpr int64_t GET_ALL_ENABLED_THRESHOLD_MS = 50;
constexpr int32_t PERFORMANCE_BUNDLE_COUNT = 300;
constexpr int32_t BASE_UID = 10000;

void AddPermission()
{
    uint64_t tokenId;
    const char *perms[2] = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "com.distributed.notification.performance.test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

std::string MakeBundleName(int32_t index)
{
    return "perf_bundle_" + std::to_string(index);
}
}  // namespace

/*
 * Performance benchmark fixture for batch slot enabled query optimization.
 *
 * Covers three scenarios (PT-001 / PT-002 from plan.md):
 *   1. GetEnabledForBundleSlots_Performance_0100 - 300 bundles batch query < 30 ms.
 *   2. GetEnabledForBundleSlot_Single_Baseline_0100 - 300 single queries total as baseline.
 *   3. GetAllNotificationEnabledBundles_Performance_0100 - optimized getAllNotificationEnabledBundles timing.
 *
 * The test is designed to run on-device where the ANS system ability is available.
 * Timing is measured with std::chrono::high_resolution_clock and reported via GTEST_LOG_
 * for manual comparison against historical baselines.
 */
class BatchSlotQueryPerformanceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        AddPermission();
    }
    static void TearDownTestCase() {}

    void SetUp() override
    {
        PrepareBundles();
    }
    void TearDown() override {}

    void PrepareBundles()
    {
        bundleOptions_.clear();
        bundleOptions_.reserve(PERFORMANCE_BUNDLE_COUNT);
        for (int32_t i = 0; i < PERFORMANCE_BUNDLE_COUNT; ++i) {
            bundleOptions_.emplace_back(MakeBundleName(i), BASE_UID + i);
        }
        slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    }

protected:
    std::vector<NotificationBundleOption> bundleOptions_;
    NotificationConstant::SlotType slotType_ {NotificationConstant::SlotType::OTHER};
};

/**
 * @tc.name: GetEnabledForBundleSlots_Performance_0100
 * @tc.desc: Batch query 300 bundles within 30 ms.
 * @tc.type: PERF
 * @tc.require: T016
 */
HWTEST_F(BatchSlotQueryPerformanceTest, GetEnabledForBundleSlots_Performance_0100, Performance | MediumTest | Level2)
{
    std::map<sptr<NotificationBundleOption>, bool> slotEnabled;
    auto start = std::chrono::high_resolution_clock::now();
    ErrCode ret = NotificationHelper::GetEnabledForBundleSlots(bundleOptions_, slotType_, slotEnabled);
    auto end = std::chrono::high_resolution_clock::now();
    auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    int64_t durationMs = durationUs.count() / 1000;

    GTEST_LOG_(INFO) << "GetEnabledForBundleSlots: 300 bundles, duration=" << durationUs.count()
                     << "us (" << durationMs << "ms), result size=" << slotEnabled.size()
                     << ", ret=" << ret;

    EXPECT_LT(durationMs, BATCH_QUERY_THRESHOLD_MS);
}

/**
 * @tc.name: GetEnabledForBundleSlot_Single_Baseline_0100
 * @tc.desc: 300 single GetEnabledForBundleSlot calls as comparison baseline.
 * @tc.type: PERF
 * @tc.require: T016
 */
HWTEST_F(BatchSlotQueryPerformanceTest, GetEnabledForBundleSlot_Single_Baseline_0100,
    Performance | MediumTest | Level2)
{
    int64_t totalUs = 0;
    int32_t okCount = 0;
    for (int32_t i = 0; i < PERFORMANCE_BUNDLE_COUNT; ++i) {
        bool enabled = false;
        auto start = std::chrono::high_resolution_clock::now();
        ErrCode ret = NotificationHelper::GetEnabledForBundleSlot(bundleOptions_[i], slotType_, enabled);
        auto end = std::chrono::high_resolution_clock::now();
        totalUs += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        if (ret == ERR_OK) {
            ++okCount;
        }
    }
    int64_t totalMs = totalUs / 1000;
    int64_t avgUs = PERFORMANCE_BUNDLE_COUNT > 0 ? totalUs / PERFORMANCE_BUNDLE_COUNT : 0;

    GTEST_LOG_(INFO) << "GetEnabledForBundleSlot x300: total=" << totalUs
                     << "us (" << totalMs << "ms), ok=" << okCount
                     << "/" << PERFORMANCE_BUNDLE_COUNT
                     << ", avg=" << avgUs << "us/call";

    EXPECT_GT(totalMs, 0);
}

/**
 * @tc.name: GetAllNotificationEnabledBundles_Performance_0100
 * @tc.desc: getAllNotificationEnabledBundles optimized timing, expected < 50 ms.
 * @tc.type: PERF
 * @tc.require: T016
 */
HWTEST_F(BatchSlotQueryPerformanceTest, GetAllNotificationEnabledBundles_Performance_0100,
    Performance | MediumTest | Level2)
{
    std::vector<NotificationBundleOption> enabledBundles;
    auto start = std::chrono::high_resolution_clock::now();
    ErrCode ret = NotificationHelper::GetAllNotificationEnabledBundles(enabledBundles);
    auto end = std::chrono::high_resolution_clock::now();
    auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    int64_t durationMs = durationUs.count() / 1000;

    GTEST_LOG_(INFO) << "GetAllNotificationEnabledBundles: duration=" << durationUs.count()
                     << "us (" << durationMs << "ms), bundle count=" << enabledBundles.size()
                     << ", ret=" << ret;

    EXPECT_LT(durationMs, GET_ALL_ENABLED_THRESHOLD_MS);
}
}  // namespace Notification
}  // namespace OHOS
