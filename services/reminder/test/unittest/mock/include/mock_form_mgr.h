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

#ifndef BASE_NOTIFICATION_REMINDER_MOCK_FORM_MGR_H
#define BASE_NOTIFICATION_REMINDER_MOCK_FORM_MGR_H

#include <cstdint>

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Test-only observation helpers for the form refresh chain of
 *        ReminderDataManager::RefreshFormsByReminder.
 *
 * The production implementation runs the whole refresh chain inside an
 * ffrt task and reaches the FormMgr through
 * SystemAbilityManagerClient::GetSystemAbilityManager followed by an
 * iface_cast<IFormMgr> virtual dispatch, which cannot be intercepted at
 * link time. The samgr client entry is therefore the observable point:
 * mock_form_mgr.cpp preempts that symbol for all objects statically
 * linked into the test binary (same mechanism as mock_ipc_skeleton.cpp
 * and mock_service_registry.cpp) and records how often it was requested.
 *
 * By default the preempted entry delegates to the real samgr client
 * behavior, so unrelated tests are not affected; tests can additionally
 * force a null manager (null-manager branch) or a real proxy over a
 * remote object whose IPC always fails (null-remote-object branch), with
 * the SendRequest count observed on that object distinguishing how deep
 * the driven chain actually got.
 *
 * Because the chain is asynchronous, the counters are atomic and the
 * WaitFor... helpers block until a target count is observed: polling the
 * getters right after the call would be racy. The only exception are the
 * guards that must not schedule a task at all, which run synchronously
 * before the task submission and can be checked without waiting.
 */
class MockFormMgr {
public:
    /**
     * @brief Reset the counters and restore the default
     *        (delegate-to-real) samgr client behavior.
     */
    static void Reset();

    /**
     * @brief Number of GetSystemAbilityManager requests observed since
     *        the last Reset.
     */
    static int32_t GetSystemAbilityManagerRequestCount();

    /**
     * @brief When set to true, the preempted samgr client entry returns
     *        nullptr, so callers exercise their null-manager branch.
     */
    static void SetSystemAbilityManagerNull(bool nullManager);

    /**
     * @brief When set to true, the preempted samgr client entry returns a
     *        real samgr proxy over a fake remote object whose IPC always
     *        fails, so GetSystemAbility returns nullptr and callers
     *        exercise their null-remote-object branch deterministically.
     */
    static void SetSystemAbilityManagerRemoteNull(bool remoteNull);

    /**
     * @brief Number of SendRequest calls observed on the failing fake
     *        remote object since the last Reset. Non-zero only in
     *        remote-null mode, proving the chain reached GetSystemAbility
     *        instead of stopping at an earlier guard.
     */
    static int32_t GetFailingRemoteSendRequestCount();

    /**
     * @brief Block until the GetSystemAbilityManager request count reaches
     *        the target or the timeout (ms) elapses. Returns whether the
     *        target was reached in time. Required because the production
     *        chain runs in an ffrt task.
     */
    static bool WaitForSystemAbilityManagerRequestCount(int32_t target, int32_t timeoutMs);

    /**
     * @brief Block until the SendRequest count observed on the failing
     *        fake remote object reaches the target or the timeout (ms)
     *        elapses. Returns whether the target was reached in time.
     */
    static bool WaitForFailingRemoteSendRequestCount(int32_t target, int32_t timeoutMs);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_REMINDER_MOCK_FORM_MGR_H
