/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#define private public
#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "mock_ipc_skeleton.h"
#include "notification.h"
#include "notification_subscriber.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "ans_permission_def.h"


using namespace OHOS;
using namespace OHOS::Notification;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::Notification;

namespace {
const uint32_t TOKEN_ID = 0x08000000;

void AddPermission()
{
    uint64_t tokenId;
    const char *perms[2];
    perms[0] = OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER;
    perms[1] = OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "com.distributed.notification.service.test",
        .aplStr = "system_core",

    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

class TestAnsSubscriber : public NotificationSubscriber {
public:
    void OnConnected() override
    {}
    void OnDisconnected() override
    {}
    void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override
    {}
    void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnDied() override
    {}
    void OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int deleteReason) override
    {}
    void OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override
    {}
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override
    {}
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override
    {}
    void OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>>
        &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override
    {}
};

class BenchmarkNotificationService : public benchmark::Fixture {
public:
    BenchmarkNotificationService()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }

    ~BenchmarkNotificationService() override = default;

    void SetUp(const ::benchmark::State &state) override
    {
        if (flag) {
            AddPermission();
            flag = false;
        }
    }
    void TearDown(const ::benchmark::State &state) override
    {}
 
protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 100;
    bool flag = true;
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> BenchmarkNotificationService::advancedNotificationService_ =
    AdvancedNotificationService::GetInstance();

/**
 * @tc.name: AddSlotTestCase
 * @tc.desc: AddSlot
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, AddSlotTestCase)(benchmark::State &state)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CUSTOM);
    slots.push_back(slot);
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->AddSlots(slots);
        if (errCode != ERR_OK) {
            state.SkipWithError("AddSlotTestCase failed.");
        }
    }
}

/**
 * @tc.name: RemoveSlotByTypeTestCase
 * @tc.desc: RemoveSlotByType
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, RemoveSlotByTypeTestCase)(benchmark::State &state)
{
    std::vector<sptr<NotificationSlot>> slots;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CUSTOM);
    slots.push_back(slot);
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->AddSlots(slots);
        if (errCode != ERR_OK) {
            state.SkipWithError("RemoveSlotByTypeTestCase add failed.");
        }

        errCode = advancedNotificationService_->RemoveSlotByType(NotificationConstant::SlotType::CUSTOM);
        if (errCode != ERR_OK) {
            state.SkipWithError("RemoveSlotByTypeTestCase remove failed.");
        }
    }
}

/**
 * @tc.name: SubscribeTestCase
 * @tc.desc: Subscribe
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, SubscribeTestCase)(benchmark::State &state)
{
    auto subscriber = new TestAnsSubscriber();
    sptr<NotificationSubscribeInfo> info = new NotificationSubscribeInfo();
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->Subscribe(subscriber->GetImpl(), info);
        if (errCode != ERR_OK) {
            state.SkipWithError("SubscribeTestCase failed.");
        }
    }
}

/**
 * @tc.name: PublishNotificationTestCase001
 * @tc.desc: Publish a normal text type notification.
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, PublishNotificationTestCase001)(benchmark::State &state)
{
    IPCSkeleton::SetCallingTokenID(0);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(1);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    req->SetCreatorUid(100);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);

    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->Publish(label, req);
        if (errCode != ERR_OK) {
            state.SkipWithError("PublishNotificationTestCase001 failed.");
        }
    }
}

/**
 * @tc.name: CancelNotificationTestCase001
 * @tc.desc: Cancel a normal text type notification.
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, CancelNotificationTestCase001)(benchmark::State &state)
{
    IPCSkeleton::SetCallingTokenID(0);
    sptr<NotificationRequest> req = new (std::nothrow) NotificationRequest(0);
    EXPECT_NE(req, nullptr);
    req->SetSlotType(NotificationConstant::SlotType::OTHER);
    req->SetLabel("req's label");
    req->SetCreatorUid(100);
    std::string label = "publish's label";
    std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
    EXPECT_NE(normalContent, nullptr);
    normalContent->SetText("normalContent's text");
    normalContent->SetTitle("normalContent's title");
    std::shared_ptr<NotificationContent> content = std::make_shared<NotificationContent>(normalContent);
    EXPECT_NE(content, nullptr);
    req->SetContent(content);

    int id = 0;
    while (state.KeepRunning()) {
        req->SetNotificationId(id);
        ErrCode errCode = advancedNotificationService_->Publish(label, req);
        if (errCode != ERR_OK) {
            state.SkipWithError("CancelNotificationTestCase001 publish failed.");
        }
        advancedNotificationService_->Cancel(id, label, "");
    }
}

/**
 * @tc.name: SetNotificationBadgeNumTestCase
 * @tc.desc: SetNotificationBadgeNum
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, SetNotificationBadgeNumTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->SetNotificationBadgeNum(2);
        if (errCode != ERR_OK) {
            state.SkipWithError("SetNotificationBadgeNumTestCase failed.");
        }
    }
}

/**
 * @tc.name: GetBundleImportanceTestCase
 * @tc.desc: GetBundleImportance
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, GetBundleImportanceTestCase)(benchmark::State &state)
{
    int importance = 0;
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->GetBundleImportance(importance);
        if (errCode != ERR_OK) {
            state.SkipWithError("GetBundleImportanceTestCase failed.");
        }
    }
}

/**
 * @tc.name: SetShowBadgeEnabledForBundleTestCase
 * @tc.desc: SetShowBadgeEnabledForBundle
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, SetShowBadgeEnabledForBundleTestCase)(benchmark::State &state)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName", 1000);
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundleOption, true);
        if (errCode != ERR_OK) {
            state.SkipWithError("SetShowBadgeEnabledForBundleTestCase failed.");
        }
    }
}

/**
 * @tc.name: GetShowBadgeEnabledForBundleTestCase
 * @tc.desc: GetShowBadgeEnabledForBundle
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, GetShowBadgeEnabledForBundleTestCase)(benchmark::State &state)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName", 1000);
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->SetShowBadgeEnabledForBundle(bundleOption, true);
        if (errCode != ERR_OK) {
            state.SkipWithError("GetShowBadgeEnabledForBundleTestCase set failed.");
        }

        bool allow = false;
        errCode = advancedNotificationService_->GetShowBadgeEnabledForBundle(bundleOption, allow);
        if (!allow || errCode != ERR_OK) {
            state.SkipWithError("GetShowBadgeEnabledForBundleTestCase get failed.");
        }
    }
}

/**
 * @tc.name: GetAllActiveNotificationsTestCase
 * @tc.desc: GetAllActiveNotifications
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, GetAllActiveNotificationsTestCase)(benchmark::State &state)
{
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->GetAllActiveNotifications(notifications);
        if (errCode != ERR_OK) {
            state.SkipWithError("GetAllActiveNotificationsTestCase failed.");
        }
    }
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundlesTestCase
 * @tc.desc: SetNotificationsEnabledForAllBundles
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, SetNotificationsEnabledForAllBundlesTestCase)(benchmark::State &state)
{
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true);
        if (errCode != ERR_OK) {
            state.SkipWithError("SetNotificationsEnabledForAllBundlesTestCase failed.");
        }
    }
}

/**
 * @tc.name: IsAllowedNotifyTestCase
 * @tc.desc: IsAllowedNotify
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, IsAllowedNotifyTestCase)(benchmark::State &state)
{
    std::vector<sptr<OHOS::Notification::Notification>> notifications;
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->SetNotificationsEnabledForAllBundles(std::string(), true);
        if (errCode != ERR_OK) {
            state.SkipWithError("IsAllowedNotifyTestCase set failed.");
        }

        bool allowed = false;
        errCode = advancedNotificationService_->IsAllowedNotify(allowed);
        if (!allowed || errCode != ERR_OK) {
            state.SkipWithError("IsAllowedNotifyTestCase get failed.");
        }
    }
}

/**
 * @tc.name: SetNotificationsEnabledForSpecialBundleTestCase
 * @tc.desc: SetNotificationsEnabledForSpecialBundle
 * @tc.type: FUNC
 * @tc.require:
 */
BENCHMARK_F(BenchmarkNotificationService, SetNotificationsEnabledForSpecialBundleTestCase)(benchmark::State &state)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName", 1000);
    while (state.KeepRunning()) {
        ErrCode errCode = advancedNotificationService_->SetNotificationsEnabledForSpecialBundle(
                std::string(), bundleOption, true);
        if (errCode != ERR_OK) {
            state.SkipWithError("SetNotificationsEnabledForSpecialBundleTestCase failed.");
        }
    }
}
}

// Run the benchmark
BENCHMARK_MAIN();
