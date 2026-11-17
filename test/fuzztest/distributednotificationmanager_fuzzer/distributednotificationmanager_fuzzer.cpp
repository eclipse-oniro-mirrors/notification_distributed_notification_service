/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public  // NOLINT
#define protected public  // NOLINT
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_flow_control.h"
#undef private
#undef protected
#include "distributednotificationmanager_fuzzer.h"
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

/**
 * DistributedNotificationManager is a process-wide singleton that stores published notifications in a
 * persistent distributed database, so an entry that is not deleted survives into the next fuzz iteration.
 * This guard deletes the entry on every exit path, including the early returns of the test body.
 */
class PublishedNotificationGuard {
public:
    PublishedNotificationGuard(const std::shared_ptr<DistributedNotificationManager> &manager,
        const std::string &bundleName, const std::string &label, int32_t id)
        : manager_(manager), bundleName_(bundleName), label_(label), id_(id)
    {}

    ~PublishedNotificationGuard()
    {
        if (manager_ != nullptr) {
            manager_->Delete(bundleName_, label_, id_);
        }
    }

    PublishedNotificationGuard(const PublishedNotificationGuard &) = delete;
    PublishedNotificationGuard &operator=(const PublishedNotificationGuard &) = delete;

private:
    std::shared_ptr<DistributedNotificationManager> manager_;
    std::string bundleName_;
    std::string label_;
    int32_t id_;
};

static void TestDistributedNotificationManager(FuzzedDataProvider *fuzzData)
{
    auto manager = DistributedNotificationManager::GetInstance();
    std::string bundleName = fuzzData->ConsumeRandomLengthString();
    std::string label = fuzzData->ConsumeRandomLengthString();
    int32_t id = fuzzData->ConsumeIntegral<int32_t>();

    PublishedNotificationGuard publishedGuard(manager, bundleName, label, id);

    sptr<NotificationRequest> request = sptr<NotificationRequest>::MakeSptr();
    if (request == nullptr) {
        return;
    }
    request->SetNotificationId(id);
    manager->Publish(bundleName, label, id, request);
    manager->Update(bundleName, label, id, request);
    manager->Delete(bundleName, label, id);

    std::string deviceId = fuzzData->ConsumeRandomLengthString();
    manager->DeleteRemoteNotification(deviceId, bundleName, label, id);

    DistributedNotificationManager::IDistributedCallback callback;
    manager->RegisterCallback(callback);
    // The API is declared as UngegisterCallback() in distributed_notification_manager.h, so the
    // upstream spelling is kept here to match the real symbol instead of the correct "Unregister".
    // This comment will be dropped once the upstream header is renamed.
    manager->UngegisterCallback();

    std::vector<sptr<NotificationRequest>> requestList;
    manager->GetCurrentDistributedNotification(requestList);
    for (const auto &distributedRequest : requestList) {
        if (distributedRequest != nullptr) {
            distributedRequest->Dump();
        }
    }

    DistributedDatabase::DeviceInfo deviceInfo;
    manager->GetLocalDeviceInfo(deviceInfo);
    // These two are the only entry points for the corresponding implementations and are idempotent
    // re-initialization paths, so they are kept to preserve the coverage of the manager singleton.
    manager->OnDistributedKvStoreDeathRecipient();
    manager->ResetFfrtQueue();
}

static void TestDistributedPreferences(FuzzedDataProvider *fuzzData)
{
    auto preferences = DistributedPreferences::GetInstance();
    bool isEnable = fuzzData->ConsumeBool();
    int32_t userId = fuzzData->ConsumeIntegral<int32_t>();

    preferences->SetDistributedEnable(isEnable);
    preferences->GetDistributedEnable(isEnable);

    std::string bundleName = fuzzData->ConsumeRandomLengthString();
    int32_t uid = fuzzData->ConsumeIntegral<int32_t>();
    sptr<NotificationBundleOption> bundleOption = sptr<NotificationBundleOption>::MakeSptr(bundleName, uid);
    if (bundleOption == nullptr) {
        return;
    }
    preferences->SetDistributedBundleEnable(bundleOption, isEnable);
    preferences->GetDistributedBundleEnable(bundleOption, isEnable);
    preferences->DeleteDistributedBundleInfo(bundleOption);
    preferences->ClearDataInRestoreFactorySettings();
    preferences->SetSyncEnabledWithoutApp(userId, isEnable);
    preferences->GetSyncEnabledWithoutApp(userId, isEnable);
}

static void TestDistributedFlowControl(FuzzedDataProvider *fuzzData)
{
    size_t kvManagerSecondMax = fuzzData->ConsumeIntegralInRange<size_t>(1, 100);
    size_t kvManagerMinuteMax = fuzzData->ConsumeIntegralInRange<size_t>(1, 1000);
    size_t kvStoreSecondMax = fuzzData->ConsumeIntegralInRange<size_t>(1, 100);
    size_t kvStoreMinuteMax = fuzzData->ConsumeIntegralInRange<size_t>(1, 1000);

    DistributedFlowControl flowControl(kvManagerSecondMax, kvManagerMinuteMax,
        kvStoreSecondMax, kvStoreMinuteMax);
    flowControl.KvManagerFlowControl();
    flowControl.KvStoreFlowControl();
    flowControl.KvManagerFlowControlClear();
    flowControl.KvStoreFlowControlClear();
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestDistributedNotificationManager(fuzzData);
    TestDistributedPreferences(fuzzData);
    TestDistributedFlowControl(fuzzData);
    return true;
}
}  // namespace Notification
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fuzzData(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fuzzData);
    return 0;
}
