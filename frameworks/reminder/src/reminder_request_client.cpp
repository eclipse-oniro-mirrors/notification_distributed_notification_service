/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "reminder_service_load_callback.h"
#include "ans_manager_proxy.h"
#include "reminder_agent_service_proxy.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include <memory>
#include <thread>

namespace OHOS {
namespace Notification {
constexpr int32_t REMINDER_SERVICE_LOADSA_TIMEOUT_MS = 10000;
constexpr int32_t REMINDER_AGENT_SERVICE_ID = 3204;
ErrCode ReminderRequestClient::AddSlotByType(const NotificationConstant::SlotType &slotType)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddSlotByType(slotType);
}

ErrCode ReminderRequestClient::AddNotificationSlot(const NotificationSlot &slot)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    std::vector<sptr<NotificationSlot>> slotsSptr;
    sptr<NotificationSlot> slotSptr = new (std::nothrow) NotificationSlot(slot);
    if (slotSptr == nullptr) {
        ANS_LOGE("Failed to create NotificationSlot ptr.");
        return ERR_ANS_NO_MEMORY;
    }
    slotsSptr.emplace_back(slotSptr);
    return proxy->AddSlots(slotsSptr);
}

ErrCode ReminderRequestClient::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGI("enter RemoveNotificationSlot，slotType:%{public}d", slotType);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveSlotByType(slotType);
}

ErrCode ReminderRequestClient::PublishReminder(const ReminderRequest& reminder, int32_t& reminderId)
{
    AddSlotByType(reminder.GetSlotType());
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->PublishReminder(reminder, reminderId);
}

ErrCode ReminderRequestClient::UpdateReminder(const int32_t reminderId, const ReminderRequest& reminder)
{
    AddSlotByType(reminder.GetSlotType());
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->UpdateReminder(reminderId, reminder);
}

ErrCode ReminderRequestClient::CancelReminder(const int32_t reminderId)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelReminder(reminderId);
}

ErrCode ReminderRequestClient::CancelAllReminders()
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelAllReminders();
}

ErrCode ReminderRequestClient::GetValidReminders(std::vector<ReminderRequestAdaptation> &validReminders)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetValidReminders(validReminders);
}

ErrCode ReminderRequestClient::AddExcludeDate(const int32_t reminderId, const int64_t date)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddExcludeDate(reminderId, date);
}

ErrCode ReminderRequestClient::DelExcludeDates(const int32_t reminderId)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->DelExcludeDates(reminderId);
}

ErrCode ReminderRequestClient::GetExcludeDates(const int32_t reminderId, std::vector<int64_t>& dates)
{
    sptr<IReminderAgentService> proxy = GetReminderServiceProxy();
    if (!proxy) {
        ANS_LOGE("GetReminderServiceProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetExcludeDates(reminderId, dates);
}

sptr<AnsManagerInterface> ReminderRequestClient::GetAnsManagerProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ANS_LOGE("Failed to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (!remoteObject) {
        ANS_LOGE("Failed to get notification Manager.");
        return nullptr;
    }

    sptr<AnsManagerInterface> proxy = iface_cast<AnsManagerInterface>(remoteObject);
    if ((!proxy) || (!proxy->AsObject())) {
        ANS_LOGE("Failed to get notification Manager's proxy");
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
            ANS_LOGE("get samgr failed");
            return nullptr;
        }
        auto object = samgrProxy->CheckSystemAbility(REMINDER_AGENT_SERVICE_ID);
        if (object != nullptr) {
            ANS_LOGI("get service succeeded");
            proxy_ = iface_cast<IReminderAgentService>(object);
            return proxy_;
        }
    }

    ANS_LOGE("object is null");
    if (LoadReminderService()) {
        std::lock_guard<ffrt::mutex> lock(serviceLock_);
        if (proxy_ != nullptr) {
            return proxy_;
        } else {
            ANS_LOGE("load reminder service failed");
            return nullptr;
        }
    }
    ANS_LOGE("load reminder service failed");
    return nullptr;
}

bool ReminderRequestClient::LoadReminderService()
{
    std::unique_lock<ffrt::mutex> lock(serviceLock_);
    sptr<ReminderServiceCallback> loadCallback = sptr<ReminderServiceCallback>(new ReminderServiceCallback());
    if (loadCallback == nullptr) {
        ANS_LOGE("loadCallback is nullptr.");
        return false;
    }

    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        ANS_LOGE("get samgr failed");
        return false;
    }

    int32_t ret = samgrProxy->LoadSystemAbility(REMINDER_AGENT_SERVICE_ID, loadCallback);
    if (ret != ERR_OK) {
        ANS_LOGE("Failed to Load systemAbility");
        return false;
    }

    auto waitStatus = proxyConVar_.wait_for(lock, std::chrono::milliseconds(REMINDER_SERVICE_LOADSA_TIMEOUT_MS),
        [this]() { return proxy_ != nullptr; });
    if (!waitStatus) {
        ANS_LOGE("reminder service load sa timeout");
        return false;
    }
    return true;
}

void ReminderRequestClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    ANS_LOGI("ReminderRequestClient FinishStartSA");
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
        ANS_LOGE("StartReminderService failed");
        return;
    }
    ANS_LOGI("StartReminderService success");
}

}  // namespace Notification
}  // namespace OHOS
