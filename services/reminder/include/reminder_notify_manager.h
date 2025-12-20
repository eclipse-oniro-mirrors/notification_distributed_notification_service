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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_NOTIFY_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_NOTIFY_MANAGER_H

#include "reminder_state.h"

#include "ffrt.h"
#include "iremote_object.h"
#include "remote_death_recipient.h"

#include <unordered_map>

namespace OHOS::Notification {
class ReminderNotifyManager {
public:
    ReminderNotifyManager();
    ~ReminderNotifyManager() = default;

public:
    void RegisterNotify(const int32_t uid, const sptr<IRemoteObject>& callback);
    void UnRegisterNotify(const int32_t uid);

    bool NotifyReminderState(const int32_t uid, const std::vector<ReminderState>& states);

private:
    void OnRemoteDied(const wptr<IRemoteObject>& object);

private:
    ffrt::mutex mutex_;
    std::unordered_map<int32_t, sptr<IRemoteObject>> notifies_;
    sptr<RemoteDeathRecipient> deathRecipient_;
    std::shared_ptr<ffrt::queue> queue_;
};
} // namespace OHOS::Notification
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_NOTIFY_MANAGER_H
