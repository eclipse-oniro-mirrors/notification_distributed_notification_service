/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "advanced_notification_service.h"
#undef private
#undef protected
#include "ans_dialog_callback_proxy.h"
#include "ans_permission_def.h"
#include "ans_result_data_synchronizer.h"
#include "ansmanagerstubslotbadge_fuzzer.h"
#include "notification_record.h"
#include "notification_request.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_call_back_proxy.h"
#endif

constexpr uint8_t SLOT_TYPE_NUM = 5;
constexpr size_t OVERLONG_BUNDLE_NAME_LEN = 1024;
constexpr size_t FUZZ_STRING_MAX_LEN = 64;
constexpr uint8_t FIXED_INVALID_NAME_COUNT = 5;
constexpr uint8_t INVALID_NAME_KIND_COUNT = FIXED_INVALID_NAME_COUNT + 1;

namespace OHOS {
    namespace {
        struct FuzzServiceContext {
            sptr<Notification::AdvancedNotificationService> service;
            sptr<Notification::NotificationBundleOption> bundleOption;
            sptr<Notification::AnsResultDataSynchronizerImpl> synchronizer;
            sptr<Notification::IAnsResultDataSynchronizer> remoteSynchronizer;
            std::string stringData;
            int32_t userId;
            bool enabled;
            bool allowed;
        };
    }

    std::string BuildInvalidBundleName(FuzzedDataProvider *fuzzData)
    {
        static const std::string fixedInvalidNames[] = {
            std::string(),
            std::string(OVERLONG_BUNDLE_NAME_LEN, 'b'),
            "\xe9\x9d\x9e\xe6\xb3\x95\xe5\x8c\x85\xe5\x90\x8d\xf0\x9f\x8e\x89",
            "../..\\..%s%s%d%n",
            "\x01\x02\x7f\xff",
        };
        uint8_t kind = fuzzData->ConsumeIntegralInRange<uint8_t>(0, INVALID_NAME_KIND_COUNT - 1);
        if (kind < FIXED_INVALID_NAME_COUNT) {
            return fixedInvalidNames[kind];
        }
        return fuzzData->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
    }

    void TestSlotAndQueryOperations(FuzzedDataProvider *fuzzData, FuzzServiceContext &ctx)
    {
        uint8_t type = fuzzData->ConsumeIntegral<uint8_t>() % SLOT_TYPE_NUM;
        Notification::NotificationConstant::SlotType slotType = Notification::NotificationConstant::SlotType(type);
        ctx.service->AddSlotByType(slotType);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        ctx.service->AddSlots(slots);
        ctx.service->RemoveSlotByType(slotType);
        ctx.service->RemoveAllSlots();
        sptr<Notification::NotificationSlot> slot = new Notification::NotificationSlot();
        ctx.service->GetSlotByType(slotType, slot);
        ctx.service->GetSlots(slots);
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        ctx.service->GetSlotNumAsBundle(ctx.bundleOption, num);
        ctx.service->GetSlotsByBundle(ctx.bundleOption, slots);
        ctx.service->UpdateSlots(ctx.bundleOption, slots);
        std::vector<sptr<Notification::NotificationRequest>> notifications;
        ctx.service->GetActiveNotifications(notifications, fuzzData->ConsumeRandomLengthString());
        if ((ctx.remoteSynchronizer != nullptr) &&
            (ctx.service->GetActiveNotifications(fuzzData->ConsumeRandomLengthString(),
                ctx.remoteSynchronizer) == ERR_OK)) {
            ctx.synchronizer->Wait();
        }
        ctx.service->GetActiveNotificationNums(num);
        std::vector<sptr<Notification::Notification>> notificationss;
        ctx.service->GetAllActiveNotifications(notificationss);
        if ((ctx.remoteSynchronizer != nullptr) &&
            (ctx.service->GetAllActiveNotifications(ctx.remoteSynchronizer) == ERR_OK)) {
            ctx.synchronizer->Wait();
        }
        std::vector<std::string> key;
        ctx.service->GetSpecialActiveNotifications(key, notificationss);
    }

    void TestPreferenceAndBadgeOperations(FuzzedDataProvider *fuzzData, FuzzServiceContext &ctx)
    {
        ctx.service->SetNotificationBadgeNum(fuzzData->ConsumeIntegral<int32_t>());
        int32_t importance = fuzzData->ConsumeIntegral<int32_t>();
        ctx.service->GetBundleImportance(importance);
        bool granted = fuzzData->ConsumeBool();
        ctx.service->HasNotificationPolicyAccessPermission(granted);
        bool enabled = fuzzData->ConsumeBool();
        ctx.service->SetNotificationsEnabledForBundle(ctx.stringData, enabled);
        ctx.service->SetNotificationsEnabledForAllBundles(ctx.stringData, enabled);
        ctx.service->SetNotificationsEnabledForSpecialBundle(ctx.stringData, ctx.bundleOption, ctx.enabled);
        ctx.service->SetShowBadgeEnabledForBundle(ctx.bundleOption, ctx.enabled);
        ctx.service->GetShowBadgeEnabledForBundle(ctx.bundleOption, ctx.enabled);
        if ((ctx.remoteSynchronizer != nullptr) &&
            (ctx.service->GetShowBadgeEnabledForBundle(ctx.bundleOption, ctx.remoteSynchronizer) == ERR_OK)) {
            ctx.synchronizer->Wait();
        }
        ctx.service->GetShowBadgeEnabled(enabled);
        if ((ctx.remoteSynchronizer != nullptr) &&
            (ctx.service->GetShowBadgeEnabled(ctx.remoteSynchronizer) == ERR_OK)) {
            ctx.synchronizer->Wait();
        }
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        ctx.service->SetBadgeNumber(badgeNum, fuzzData->ConsumeRandomLengthString());
        ctx.service->SetBadgeNumberByBundle(ctx.bundleOption, fuzzData->ConsumeIntegral<int32_t>());
        ctx.service->HandleBadgeEnabledChanged(ctx.bundleOption, ctx.enabled);
        ctx.service->SetBadgeNumberForDhByBundle(ctx.bundleOption, badgeNum);
        sptr<Notification::NotificationDoNotDisturbDate> date = new Notification::NotificationDoNotDisturbDate();
        ctx.service->SetDoNotDisturbDateByUser(ctx.userId, date);
        ctx.service->GetDoNotDisturbDateByUser(ctx.userId, date);
        bool doesSupport = fuzzData->ConsumeBool();
        ctx.service->DoesSupportDoNotDisturbMode(doesSupport);
    }

    void TestAllowedAndDistributedOperations(FuzzedDataProvider *fuzzData, FuzzServiceContext &ctx)
    {
        bool enabled = fuzzData->ConsumeBool();
        bool allowed = fuzzData->ConsumeBool();
        ctx.service->IsAllowedNotify(allowed);
        ctx.service->IsAllowedNotifySelf(allowed);
        ctx.service->IsAllowedNotifySelf(ctx.bundleOption, allowed);
        ctx.service->IsAllowedNotifyForBundle(ctx.bundleOption, allowed);
        ctx.service->IsSpecialBundleAllowedNotify(ctx.bundleOption, allowed);
        ctx.service->IsDistributedEnabled(enabled);
        ctx.service->EnableDistributedByBundle(ctx.bundleOption, enabled);
        ctx.service->EnableDistributedSelf(enabled);
        ctx.service->EnableDistributed(enabled);
        ctx.service->IsDistributedEnableByBundle(ctx.bundleOption, enabled);
        int32_t remindType = 0;
        ctx.service->GetDeviceRemindType(remindType);
    }

    void TestBadgeBoundaryMatrix(FuzzServiceContext &ctx)
    {
        static const int32_t badgeBoundaries[] = { 0, 1, 99, INT32_MAX, -1 };
        for (int32_t boundaryBadge : badgeBoundaries) {
            ctx.service->SetNotificationBadgeNum(boundaryBadge);
            ctx.service->SetBadgeNumber(boundaryBadge, ctx.stringData);
            ctx.service->SetBadgeNumberByBundle(ctx.bundleOption, boundaryBadge);
            ctx.service->SetBadgeNumberForDhByBundle(ctx.bundleOption, boundaryBadge);
        }
    }

    void TestInvalidBundleMatrix(FuzzedDataProvider *fuzzData, FuzzServiceContext &ctx)
    {
        // invalid bundle names drive the param-check branches of the badge/distributed APIs
        sptr<Notification::NotificationBundleOption> invalidBundle = new Notification::NotificationBundleOption();
        if (invalidBundle == nullptr) {
            return;
        }
        invalidBundle->SetBundleName(BuildInvalidBundleName(fuzzData));
        invalidBundle->SetUid(fuzzData->ConsumeIntegralInRange<int32_t>(-1, 1));
        uint64_t num = fuzzData->ConsumeIntegral<uint64_t>();
        ctx.service->GetSlotNumAsBundle(invalidBundle, num);
        std::vector<sptr<Notification::NotificationSlot>> slots;
        ctx.service->GetSlotsByBundle(invalidBundle, slots);
        ctx.service->UpdateSlots(invalidBundle, slots);
        ctx.service->SetShowBadgeEnabledForBundle(invalidBundle, ctx.enabled);
        ctx.service->GetShowBadgeEnabledForBundle(invalidBundle, ctx.enabled);
        int32_t badgeNum = fuzzData->ConsumeIntegral<int32_t>();
        ctx.service->SetBadgeNumberByBundle(invalidBundle, badgeNum);
        ctx.service->SetBadgeNumberForDhByBundle(invalidBundle, badgeNum);
        ctx.service->HandleBadgeEnabledChanged(invalidBundle, ctx.enabled);
        ctx.service->EnableDistributedByBundle(invalidBundle, ctx.enabled);
        ctx.service->IsDistributedEnableByBundle(invalidBundle, ctx.enabled);
        ctx.service->IsAllowedNotifySelf(invalidBundle, ctx.allowed);
        ctx.service->IsAllowedNotifyForBundle(invalidBundle, ctx.allowed);
        ctx.service->IsSpecialBundleAllowedNotify(invalidBundle, ctx.allowed);
    }

    void TestBatchBadgeVariants(FuzzServiceContext &ctx)
    {
        std::map<sptr<Notification::NotificationBundleOption>, bool> bundleEnabledMap;
        ctx.service->SetShowBadgeEnabledForBundles(bundleEnabledMap);
        bundleEnabledMap[ctx.bundleOption] = ctx.enabled;
        ctx.service->SetShowBadgeEnabledForBundles(bundleEnabledMap);
        std::vector<sptr<Notification::NotificationBundleOption>> bundleOptions;
        ctx.service->GetShowBadgeEnabledForBundles(bundleOptions, bundleEnabledMap);
        bundleOptions.push_back(ctx.bundleOption);
        ctx.service->GetShowBadgeEnabledForBundles(bundleOptions, bundleEnabledMap);
        int32_t badgeNumber = 0;
        ctx.service->GetBadgeNumber(badgeNumber);
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
    {
        FuzzServiceContext ctx;
        ctx.service = Notification::AdvancedNotificationService::GetInstance();
        if (ctx.service == nullptr) {
            return false;
        }
        ctx.bundleOption = new Notification::NotificationBundleOption();
        if (ctx.bundleOption == nullptr) {
            return false;
        }
        ctx.bundleOption->SetBundleName(fuzzData->ConsumeRandomLengthString());
        ctx.bundleOption->SetUid(fuzzData->ConsumeIntegral<int32_t>());
        ctx.synchronizer = new (std::nothrow) Notification::AnsResultDataSynchronizerImpl();
        if (ctx.synchronizer == nullptr) {
            return false;
        }
        ctx.remoteSynchronizer =
            iface_cast<Notification::IAnsResultDataSynchronizer>(ctx.synchronizer->AsObject());
        ctx.stringData = fuzzData->ConsumeRandomLengthString();
        ctx.userId = fuzzData->ConsumeIntegral<int32_t>();
        ctx.enabled = fuzzData->ConsumeBool();
        ctx.allowed = fuzzData->ConsumeBool();

        TestSlotAndQueryOperations(fuzzData, ctx);
        TestPreferenceAndBadgeOperations(fuzzData, ctx);
        TestAllowedAndDistributedOperations(fuzzData, ctx);
        TestBadgeBoundaryMatrix(ctx);
        TestInvalidBundleMatrix(fuzzData, ctx);
        TestBatchBadgeVariants(ctx);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> requestPermission = {
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER,
        OHOS::Notification::OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION
    };
    SystemHapTokenGet(requestPermission);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    ENSURE_ANS_SERVICE_CLEANED_AT_EXIT();
    return 0;
}
