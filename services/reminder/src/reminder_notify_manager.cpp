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

#include "reminder_notify_manager.h"

#include "reminder_state_callback_proxy_ext.h"

namespace OHOS::Notification {
ReminderNotifyManager::ReminderNotifyManager()
{
    deathRecipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&ReminderNotifyManager::OnRemoteDied, this, std::placeholders::_1));
    queue_ = std::make_shared<ffrt::queue>("ReminderNotify");
}

void ReminderNotifyManager::RegisterNotify(const int32_t uid, const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        ANSR_LOGE("callback is nullptr.");
        return;
    }
    if (deathRecipient_ == nullptr) {
        ANSR_LOGE("deathRecipient_ is nullptr.");
        return;
    }
    {
        std::lock_guard<ffrt::mutex> locker(mutex_);
        if (notifies_.find(uid) == notifies_.end()) {
            notifies_.emplace(uid, callback);
            callback->AddDeathRecipient(deathRecipient_);
        }
    }
}

void ReminderNotifyManager::UnRegisterNotify(const int32_t uid)
{
    std::lock_guard<ffrt::mutex> locker(mutex_);
    auto iter = notifies_.find(uid);
    if (iter != notifies_.end()) {
        iter->second->RemoveDeathRecipient(deathRecipient_);
        notifies_.erase(iter);
    }
}

bool ReminderNotifyManager::NotifyReminderState(const int32_t uid, const std::vector<ReminderState>& states)
{
    sptr<IRemoteObject> target;
    {
        std::lock_guard<ffrt::mutex> locker(mutex_);
        for (const auto& notifier : notifies_) {
            if (notifier.first != uid) {
                continue;
            }
            target = notifier.second;
            break;
        }
    }
    if (target == nullptr) {
        return false;
    }
    ANSR_LOGI("Notify reminder state, uid is %{public}d.", uid);
    auto func = [target, states] () {
        if (target == nullptr) {
            ANSR_LOGE("target is nullptr.");
            return;
        }
        auto proxy = std::make_unique<ReminderStateCallbackProxyExt>(target);
        proxy->OnReminderState(states);
    };
    queue_->submit(func);
    return true;
}

void ReminderNotifyManager::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    if (object == nullptr) {
        ANSR_LOGE("object is nullptr.");
        return;
    }
    sptr<IRemoteObject> target = object.promote();
    if (target == nullptr) {
        ANSR_LOGE("target is nullptr.");
        return;
    }
    {
        std::lock_guard<ffrt::mutex> locker(mutex_);
        for (const auto& [uid, notifier] : notifies_) {
            if (notifier != target) {
                continue;
            }
            notifier->RemoveDeathRecipient(deathRecipient_);
            notifies_.erase(uid);
            return;
        }
    }
}
}