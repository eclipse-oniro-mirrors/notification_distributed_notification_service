/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

#include "mock_form_mgr.h"

#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "iservice_registry.h"

namespace OHOS {
namespace {
std::atomic<int32_t> g_systemAbilityManagerRequestCount {0};
std::atomic<bool> g_systemAbilityManagerNull {false};
std::atomic<bool> g_systemAbilityManagerRemoteNull {false};
std::atomic<int32_t> g_failingRemoteSendRequestCount {0};

// The production chain runs in an ffrt task, so the counters below are
// touched from worker threads as well; g_countMutex pairs the counter
// updates with the condition variables so waiting tests cannot miss a
// wakeup, and g_cacheMutex makes the delegate-to-real cache access safe.
std::mutex g_countMutex;
std::condition_variable g_requestCountCV;
std::condition_variable g_failingSendCV;
std::mutex g_cacheMutex;

/**
 * @brief Test-only remote object whose IPC always fails.
 *
 * Mirrors the override set of MockIRemoteObject but is hand-written, so
 * targets without a gmock dependency can use this mock. Wrapped by the
 * real samgr proxy, its failing SendRequest makes GetSystemAbility return
 * nullptr, which lets callers exercise their null-remote-object branch
 * deterministically without a live samgr.
 */
class FailingRemoteObject : public IRemoteObject {
public:
    FailingRemoteObject() : IRemoteObject(u"form_refresh_failing_remote") {}

    ~FailingRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) override
    {
        // Any non-zero result makes the samgr proxy abort GetSystemAbility
        // without parsing the (empty) reply, so it returns nullptr.
        {
            std::lock_guard<std::mutex> lock(g_countMutex);
            g_failingRemoteSendRequestCount.fetch_add(1);
        }
        g_failingSendCV.notify_all();
        return -1;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &) override
    {
        return true;
    }

    bool Marshalling(Parcel &) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int, const std::vector<std::u16string> &) override
    {
        return 0;
    }
};
}  // namespace

namespace AppExecFwk {
void MockFormMgr::Reset()
{
    {
        std::lock_guard<std::mutex> lock(g_countMutex);
        g_systemAbilityManagerRequestCount.store(0);
        g_systemAbilityManagerNull.store(false);
        g_systemAbilityManagerRemoteNull.store(false);
        g_failingRemoteSendRequestCount.store(0);
    }
    g_requestCountCV.notify_all();
    g_failingSendCV.notify_all();
}

int32_t MockFormMgr::GetSystemAbilityManagerRequestCount()
{
    return g_systemAbilityManagerRequestCount.load();
}

int32_t MockFormMgr::GetFailingRemoteSendRequestCount()
{
    return g_failingRemoteSendRequestCount.load();
}

void MockFormMgr::SetSystemAbilityManagerNull(bool nullManager)
{
    g_systemAbilityManagerNull.store(nullManager);
}

void MockFormMgr::SetSystemAbilityManagerRemoteNull(bool remoteNull)
{
    g_systemAbilityManagerRemoteNull.store(remoteNull);
}

bool MockFormMgr::WaitForSystemAbilityManagerRequestCount(int32_t target, int32_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(g_countMutex);
    return g_requestCountCV.wait_for(lock, std::chrono::milliseconds(timeoutMs),
        [target] { return g_systemAbilityManagerRequestCount.load() >= target; });
}

bool MockFormMgr::WaitForFailingRemoteSendRequestCount(int32_t target, int32_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(g_countMutex);
    return g_failingSendCV.wait_for(lock, std::chrono::milliseconds(timeoutMs),
        [target] { return g_failingRemoteSendRequestCount.load() >= target; });
}
}  // namespace AppExecFwk

/**
 * @brief Link-time mock of the samgr client entry used by
 *        ReminderDataManager::RefreshFormsByReminder.
 *
 * Defined with the same signature as the real implementation in
 * libsamgr_proxy.z.so, so the linker binds call sites inside
 * libreminder_static (statically linked into the test binary) to this
 * definition, using the same mechanism as mock_ipc_skeleton.cpp and
 * mock_service_registry.cpp. The FormMgr itself is reached through
 * iface_cast<IFormMgr> virtual dispatch, which cannot be preempted at
 * link time, so this samgr entry is the observation point for the DT.
 *
 * Behavior:
 * - Every request increments the counter observed by MockFormMgr. The
 *   production chain runs in an ffrt task, so the counter is atomic and
 *   tests must use WaitForSystemAbilityManagerRequestCount instead of
 *   polling the getter right after the call.
 * - Default mode delegates to the real client behavior (cached proxy
 *   over the process context object), keeping unrelated tests intact.
 *   The cache access is mutex-protected because ffrt worker threads and
 *   the test thread may interleave.
 * - Null mode (SetSystemAbilityManagerNull(true)) returns nullptr so
 *   callers exercise their null-manager branch.
 * - Remote-null mode (SetSystemAbilityManagerRemoteNull(true)) returns a
 *   fresh real samgr proxy over a fake remote object whose IPC always
 *   fails, so GetSystemAbility returns nullptr and callers exercise
 *   their null-remote-object branch deterministically.
 */
sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    {
        std::lock_guard<std::mutex> lock(g_countMutex);
        g_systemAbilityManagerRequestCount.fetch_add(1);
    }
    g_requestCountCV.notify_all();
    if (g_systemAbilityManagerNull.load()) {
        return nullptr;
    }
    if (g_systemAbilityManagerRemoteNull.load()) {
        // A real samgr proxy over a remote object whose IPC always fails:
        // GetSystemAbility returns nullptr, so callers run their
        // null-remote-object branch without a live samgr. The fresh proxy
        // is deliberately not cached, keeping later default-mode requests
        // on the real chain.
        sptr<IRemoteObject> failingRemote = new FailingRemoteObject();
        return iface_cast<ISystemAbilityManager>(failingRemote);
    }
    std::lock_guard<std::mutex> cacheLock(g_cacheMutex);
    if (systemAbilityManager_ != nullptr) {
        return systemAbilityManager_;
    }
    sptr<IRemoteObject> registryObject = IPCSkeleton::GetContextObject();
    systemAbilityManager_ = iface_cast<ISystemAbilityManager>(registryObject);
    return systemAbilityManager_;
}
}  // namespace OHOS
