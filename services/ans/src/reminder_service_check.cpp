/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "reminder_service_check.h"

#include "ipc_skeleton.h"
#include "ans_log_wrapper.h"
#include "reminder_helper.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "time_service_client.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "ability_manager_client.h"
#include "in_process_call_wrapper.h"
#include "system_ability_definition.h"

#include <file_ex.h>

namespace OHOS::Notification {
namespace {
constexpr const char* STATE_COLUMN = "state";
constexpr const char* PARAM_CALLBACK_TYPE = "CallbackType";
constexpr const char* DATA_NAME = "com.ohos.calendardata";
constexpr const char* DATA_ENTRY = "ReminderCallbackExtAbility";
constexpr const char* REMINDER_DB_PATH = "/data/service/el1/public/notification/notification.db";
constexpr const char* REMINDER_AGENT_SERVICE_CONFIG_PATH =
    "/data/service/el1/public/notification/reminder_agent_service_config";
constexpr int8_t STATE_DISMISSED = 2;
}

static int64_t GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

ReminderServiceCheck& ReminderServiceCheck::GetInstance()
{
    static ReminderServiceCheck instance;
    return instance;
}

bool ReminderServiceCheck::CheckNeedStartService()
{
    AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId_);
    if (QueryDataUid()) {
        // check calendardata exist and query db row count
        return Query();
    } else {
        if (access(REMINDER_DB_PATH, F_OK) != 0) {
            return false;
        }
        std::string config;
        OHOS::LoadStringFromFile(REMINDER_AGENT_SERVICE_CONFIG_PATH, config);
        return config == "1";
    }
}

void ReminderServiceCheck::StartListen()
{
    // listen common event
    SubscribeEvent();
    // listen calendar data share
    RegisterObserver();
    // start timer
    StartTimer();
}

void ReminderServiceCheck::StopListen()
{
    // stop listen common event
    UnSubscribeEvent();
    // stop listen calendar data share
    UnRegisterObserver();
    // stop timer
    StopTimer();
}

void ReminderServiceCheck::OnTimeChange()
{

}

void ReminderServiceCheck::OnTimer()
{

}

void ReminderServiceCheck::OnDataChange()
{

}

std::shared_ptr<DataShare::DataShareHelper> ReminderServiceCheck::CreateDataShareHelper();
{
    sptr<ISystemAbilityManager> manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        ANSR_LOGE("Get sa manager failed.");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = manager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (remoteObj == nullptr) {
        ANSR_LOGE("Get system ability failed.");
        return nullptr;
    }

    std::string proxy("datashareproxy://");
    proxy.append(DATA_NAME).append("/CalendarAlerts");
    proxy.append("?user=").append(std::to_string(userId_));
    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> ret =
        DataShare::DataShareHelper::Create(remoteObj, proxy, "");
    if (ret.first == 0 && ret.second != nullptr) {
        return ret.second;
    } else {
        ANSR_LOGE("Create DataShareHelper failed.");
        return nullptr;
    }
}

bool ReminderServiceCheck::RegisterObserver()
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (observer_ != nullptr) {
        return true;
    }
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("Create datashare helper failed.");
        return false;
    }
    observer_ = std::make_shared<ReminderDataObserver>();
    std::string proxy("datashareproxy://");
    proxy.append(DATA_NAME).append("/CalendarAlerts");
    Uri uri(proxy);
    helper->RegisterObserverExt(uri, observer_, false);
    helper->Release();
    return true;
}

bool ReminderServiceCheck::UnRegisterObserver()
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (observer_ == nullptr) {
        return true;
    }
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("Create datashare helper failed.");
        return false;
    }
    std::string proxy("datashareproxy://");
    proxy.append(DATA_NAME).append("/CalendarAlerts");
    Uri uri(proxy);
    helper->UnregisterObserverExt(uri, observer_);
    helper->Release();
    observer_ = nullptr;
    return true;
}

bool ReminderServiceCheck::Query()
{
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("Create datashare helper failed.");
        return false;
    }
    std::string proxy("datashareproxy://");
    proxy.append(DATA_NAME).append("/CalendarAlerts");
    proxy.append("?user=").append(std::to_string(userId_));
    Uri uri(proxy);
    std::vector<std::string> columns{STATE_COLUMN};
    DataShare::DataSharePredicates predicates;
    predicates.NotEqualTo(ReminderCalendarShareTable::STATE, ReminderCalendarShareTable::STATE_DISMISSED);
    auto resultSet = helper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        helper->Release();
        return false;
    }

    int32_t count = 0;
    resultSet->GetRowCount(count);
    helper->Release();
    return count != 0;
}

void ReminderServiceCheck::StartTimer()
{
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Get timeServiceClient failed");
        return;
    }
    std::lock_guard<std::mutex> locker(mutex_);
    if (timerId_ == 0) {
        auto timerInfo = std::make_shared<ReminderTimerInfo>();
        timerInfo->SetRepeat(false);
        timerInfo->SetInterval(0);
        uint8_t timerTypeWakeup = static_cast<uint8_t>(timerInfo->TIMER_TYPE_WAKEUP);
        uint8_t timerTypeExact = static_cast<uint8_t>(timerInfo->TIMER_TYPE_EXACT);
        int32_t timerType = static_cast<int32_t>(timerTypeWakeup | timerTypeExact);
        timerInfo->SetType(timerType);
        timerInfo->SetReminderTimerType(ReminderTimerInfo::ReminderTimerType::REMINDER_TIMER_LOAD);
        timerInfo->SetName("reminderLoadTimer");
        timerId_ = timer->CreateTimer(timerInfo);
    }
    timer->StopTimer(timerId_);
    uint64_t nowMilli = static_cast<uint64_t>(GetCurrentTime()) + NEXT_LOAD_TIME;
    timer->StartTimer(timerId_, nowMilli);
}

void ReminderServiceCheck::StopTimer()
{
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Get timeServiceClient failed");
        return;
    }
    std::lock_guard<std::mutex> locker(mutex_);
    if (timerId_ == 0) {
        return;
    }
    timer->StopTimer(timerId_);
    timer->DestroyTimer(timerId_);
    timerId_ = 0;
}

void ReminderServiceCheck::SubscribeEvent()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriber_ = std::make_shared<ReminderEventSubscriber>(subscriberInfo);
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
    IPCSkeleton::SetCallingIdentity(identity);
}

void ReminderServiceCheck::UnSubscribeEvent()
{
    if (subscriber_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        subscriber_ = nullptr;
    }
}

void ReminderServiceCheck::QueryDataUid()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        return;
    }
    sptr<AppExecFwk::IBundleMgr> bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    int32_t uid = 0;
    if (bundleMgr != nullptr) {
        std::string identity = IPCSkeleton::ResetCallingIdentity();
        uid = bundleMgr_->GetUidByBundleName(bundle, userId);
        IPCSkeleton::SetCallingIdentity(identity);
    }
    return uid != 0;
}

void ReminderServiceCheck::ReminderDataObserver::OnChange(const ChangeInfo& info)
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}

void ReminderServiceCheck::ReminderTimerInfo::OnTrigger()
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}

void ReminderServiceCheck::ReminderTimerInfo::SetType(const int32_t& type)
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}

void ReminderServiceCheck::ReminderTimerInfo::SetRepeat(bool repeat)
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}

void ReminderServiceCheck::ReminderTimerInfo::SetInterval(const uint64_t& interval)
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}

void ReminderServiceCheck::ReminderTimerInfo::SetWantAgent(
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}

ReminderServiceCheck::ReminderEventSubscriber::ReminderEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo& subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{}

void ReminderServiceCheck::ReminderEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    ReminderServiceCheck::GetInstance().OnDataChange();
}
}