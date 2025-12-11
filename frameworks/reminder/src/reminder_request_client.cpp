/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "reminder_request_client.h"

#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "reminder_agent_service_proxy.h"
#include "reminder_service_load_callback.h"

#include "ipc_skeleton.h"
#include "ans_manager_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS::Notification {
static constexpr int32_t REMINDER_SERVICE_LOADSA_TIMEOUT_MS = 10000;
static constexpr int32_t REMINDER_AGENT_SERVICE_ID = 3204;

ErrCode ReminderRequestClient::AddSlotByType(const NotificationConstant::SlotType& slotType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANSR_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddSlotByType(slotType);
}

ErrCode ReminderRequestClient::AddNotificationSlot(const NotificationSlot& slot)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANSR_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    std::vector<sptr<NotificationSlot>> slotsSptr;
    sptr<NotificationSlot> slotSptr = new (std::nothrow) NotificationSlot(slot);
    if (slotSptr == nullptr) {
        ANSR_LOGE("slotSptr is nullptr.");
        return ERR_ANS_NO_MEMORY;
    }
    slotsSptr.emplace_back(slotSptr);
    return proxy->AddSlots(slotsSptr);
}

ErrCode ReminderRequestClient::RemoveNotificationSlot(const NotificationConstant::SlotType& slotType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANSR_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveSlotByType(slotType);
}

ErrCode ReminderRequestClient::PublishReminder(const ReminderRequest& reminder, int32_t& reminderId)
{
    AddSlotByType(reminder.GetSlotType());
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->PublishReminder(reminder, reminderId);
}

ErrCode ReminderRequestClient::UpdateReminder(const int32_t reminderId, const ReminderRequest& reminder)
{
    AddSlotByType(reminder.GetSlotType());
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->UpdateReminder(reminderId, reminder);
}

ErrCode ReminderRequestClient::CancelReminder(const int32_t reminderId)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelReminder(reminderId);
}

ErrCode ReminderRequestClient::CancelAllReminders()
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelAllReminders();
}

ErrCode ReminderRequestClient::CancelReminderOnDisplay(const int32_t reminderId)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelReminderOnDisplay(reminderId);
}

ErrCode ReminderRequestClient::GetValidReminders(std::vector<ReminderRequestAdaptation>& validReminders)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetValidReminders(validReminders);
}

ErrCode ReminderRequestClient::AddExcludeDate(const int32_t reminderId, const int64_t date)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddExcludeDate(reminderId, date);
}

ErrCode ReminderRequestClient::DelExcludeDates(const int32_t reminderId)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->DelExcludeDates(reminderId);
}

ErrCode ReminderRequestClient::GetExcludeDates(const int32_t reminderId, std::vector<int64_t>& dates)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetExcludeDates(reminderId, dates);
}

ErrCode ReminderRequestClient::RegisterReminderState(const sptr<ReminderStateCallback>& object)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    {
        std::lock_guard<std::mutex> locker(listenMutex_);
        if (reminderStateListener_ == nullptr) {
            reminderStateListener_ = new (std::nothrow) ReminderStateListener();
        }
        if (reminderStateListener_ == nullptr) {
            ANSR_LOGE("reminderStateListener_ is nullptr.");
            return ERR_ANS_NO_MEMORY;
        }
        reminderStateListener_->RegisterReminderState(object);
        if (!listenerRegistered_ && !reminderStateListener_->IsEmpty()) {
            proxy->RegisterReminderState(reminderStateListener_);
            listenerRegistered_ = true;
        }
    }
    return ERR_OK;
}

ErrCode ReminderRequestClient::UnRegisterReminderState(const sptr<ReminderStateCallback>& object)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    {
        std::lock_guard<std::mutex> locker(listenMutex_);
        if (reminderStateListener_ == nullptr) {
            return ERR_OK;
        }
        reminderStateListener_->UnRegisterReminderState(object);
        if (!reminderStateListener_->IsEmpty() || !listenerRegistered_) {
            return ERR_OK;
        }
        proxy->UnRegisterReminderState();
        listenerRegistered_ = false;
    }
    return ERR_OK;
}

sptr<IAnsManager> ReminderRequestClient::GetAnsManagerProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ANSR_LOGE("Failed to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (!remoteObject) {
        ANSR_LOGE("Failed to get notification Manager.");
        return nullptr;
    }

    sptr<IAnsManager> proxy = iface_cast<IAnsManager>(remoteObject);
    if ((!proxy) || (!proxy->AsObject())) {
        ANSR_LOGE("Failed to get notification Manager's proxy");
        return nullptr;
    }
    return proxy;
}

sptr<IReminderAgentService> ReminderRequestClient::GetReminderServiceProxy()
{
    {
        std::lock_guard<ffrt::mutex> lock(serviceLock_);
        if (proxy_ != nullptr) {
            return proxy_;
        }
        auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            ANSR_LOGE("GetSystemAbilityManager failed.");
            return nullptr;
        }
        auto object = samgrProxy->CheckSystemAbility(REMINDER_AGENT_SERVICE_ID);
        if (object != nullptr) {
            ANSR_LOGD("Get service succeeded.");
            proxy_ = iface_cast<IReminderAgentService>(object);
            return proxy_;
        }
    }

    if (LoadReminderService()) {
        std::lock_guard<ffrt::mutex> lock(serviceLock_);
        if (proxy_ != nullptr) {
            return proxy_;
        }
    }
    ANSR_LOGE("Load reminder service failed.");
    return nullptr;
}

bool ReminderRequestClient::LoadReminderService()
{
    std::unique_lock<ffrt::mutex> lock(serviceLock_);
    sptr<ReminderServiceCallback> loadCallback = sptr<ReminderServiceCallback>(new ReminderServiceCallback());
    if (loadCallback == nullptr) {
        ANSR_LOGE("loadCallback is nullptr.");
        return false;
    }

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        ANSR_LOGE("GetSystemAbilityManager failed.");
        return false;
    }

    int32_t ret = samgrProxy->LoadSystemAbility(REMINDER_AGENT_SERVICE_ID, loadCallback);
    if (ret != ERR_OK) {
        ANSR_LOGE("Failed to Load systemAbility.");
        return false;
    }

    auto waitStatus = proxyConVar_.wait_for(lock, std::chrono::milliseconds(REMINDER_SERVICE_LOADSA_TIMEOUT_MS),
        [this]() { return proxy_ != nullptr; });
    if (!waitStatus) {
        ANSR_LOGE("Load reminder service timeout.");
        return false;
    }
    return true;
}

void ReminderRequestClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject>& remoteObject)
{
    std::lock_guard<ffrt::mutex> lock(serviceLock_);
    if (remoteObject != nullptr) {
        proxy_ = iface_cast<IReminderAgentService>(remoteObject);
        proxyConVar_.notify_one();
    }
}

void ReminderRequestClient::LoadSystemAbilityFail()
{
    std::lock_guard<ffrt::mutex> lock(serviceLock_);
    proxy_ = nullptr;
}

void ReminderRequestClient::StartReminderAgentService()
{
    auto reminderServiceProxy = GetReminderServiceProxy();
    if (reminderServiceProxy == nullptr) {
        ANSR_LOGE("GetReminderServiceProxy fail.");
        return;
    }
    ANSR_LOGD("StartReminderService success");
}

void ReminderRequestClient::ReminderStateListener::RegisterReminderState(const sptr<ReminderStateCallback>& object)
{
    if (object == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> locker(mutex_);
        for (auto& item : reminderStateCbs_) {
            if (item == object) {
                ANSR_LOGW("Register an exist callback.");
                return;
            }
        }
        reminderStateCbs_.emplace_back(object);
    }
}

void ReminderRequestClient::ReminderStateListener::UnRegisterReminderState(const sptr<ReminderStateCallback>& object)
{
    std::lock_guard<std::mutex> locker(mutex_);
    reminderStateCbs_.remove(object);
}

bool ReminderRequestClient::ReminderStateListener::IsEmpty()
{
    std::lock_guard<std::mutex> locker(mutex_);
    return reminderStateCbs_.empty();
}

ErrCode ReminderRequestClient::ReminderStateListener::OnReminderState(const std::vector<ReminderState>& states)
{
    std::list<sptr<ReminderStateCallback>> lists;
    {
        std::lock_guard<std::mutex> locker(mutex_);
        lists = reminderStateCbs_;
    }
    for (auto& item : lists) {
        if (item != nullptr) {
            item->OnReminderState(states);
        }
    }
    return ERR_OK;
}
}  // namespace OHOS::Notification
