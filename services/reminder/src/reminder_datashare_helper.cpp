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

#include "reminder_datashare_helper.h"

#include "ans_log_wrapper.h"
#include "iservice_registry.h"
#include "reminder_calendar_share_table.h"
#include "system_ability_definition.h"
#include "reminder_request_calendar.h"
#include "reminder_data_manager.h"
#include "ability_manager_client.h"
#include "in_process_call_wrapper.h"
#include "reminder_bundle_manager_helper.h"
#include "reminder_utils.h"

namespace OHOS::Notification {
namespace {
constexpr int64_t DURATION_PRELOAD_TIME = 10 * 60 * 60 * 1000;  // 10h, millisecond
constexpr int64_t DURATION_DELAY_TASK = 1 * 1000 * 1000;  // 1s, microsecond
constexpr int64_t CYCLE_DATASHARE_TASK = 1;  // 1s
constexpr int64_t DURATION_ONE_SECOND = 1000;  // 1s, millisecond
}

template<typename T>
void GetRdbValue(const std::shared_ptr<DataShare::DataShareResultSet>& resultSet,
    const std::string& name, T& value)
{
    value = T();
    int32_t columnIndex = -1;
    resultSet->GetColumnIndex(name, columnIndex);
    if (columnIndex == -1) {
        ANSR_LOGE("the column %{public}s does not exsit.", name.c_str());
        return;
    }

    if constexpr (std::is_same_v<T, std::string>) {
        resultSet->GetString(columnIndex, value);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        resultSet->GetLong(columnIndex, value);
    } else if constexpr (std::is_same_v<T, uint64_t>) {
        int64_t t = 0;
        resultSet->GetLong(columnIndex, t);
        value = static_cast<uint64_t>(t);
    } else if constexpr (std::is_integral_v<T>) {
        int32_t t = 0;
        resultSet->GetInt(columnIndex, t);
        value = static_cast<T>(t);
    }
}

ReminderDataShareHelper& ReminderDataShareHelper::GetInstance()
{
    static ReminderDataShareHelper helper;
    return helper;
}

bool ReminderDataShareHelper::RegisterObserver()
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (observer_ != nullptr) {
        return true;
    }
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("null helper");
        return false;
    }
    observer_ = std::make_shared<ReminderDataObserver>();
    Uri uri(ReminderCalendarShareTable::PROXY);
    helper->RegisterObserverExt(uri, observer_, false);
    ReleaseDataShareHelper(helper);
    return true;
}

bool ReminderDataShareHelper::UnRegisterObserver()
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (observer_ == nullptr) {
        return true;
    }
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("null helper");
        return false;
    }
    Uri uri(ReminderCalendarShareTable::PROXY);
    helper->UnregisterObserverExt(uri, observer_);
    ReleaseDataShareHelper(helper);
    observer_ = nullptr;
    return true;
}

bool ReminderDataShareHelper::Query(std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("null helper");
        return false;
    }
    int64_t timestamp = GetCurrentTime();
    int64_t targetTimestamp = timestamp + DURATION_PRELOAD_TIME;

    std::string proxy = ReminderCalendarShareTable::PROXY;
    proxy.append("?user=").append(std::to_string(curUserId_));
    Uri uri(proxy);
    std::vector<std::string> columns = GetColumns();
    DataShare::DataSharePredicates predicates;
    predicates.NotEqualTo(ReminderCalendarShareTable::STATE, ReminderCalendarShareTable::STATE_DISMISSED);
    predicates.And();
    predicates.BeginWrap();
    predicates.BeginWrap();
    predicates.LessThanOrEqualTo(ReminderCalendarShareTable::ALARM_TIME, timestamp);
    predicates.And();
    predicates.GreaterThanOrEqualTo(ReminderCalendarShareTable::END, timestamp);
    predicates.EndWrap();
    predicates.Or();
    predicates.BeginWrap();
    predicates.GreaterThanOrEqualTo(ReminderCalendarShareTable::ALARM_TIME, timestamp);
    predicates.And();
    predicates.LessThanOrEqualTo(ReminderCalendarShareTable::ALARM_TIME, targetTimestamp);
    predicates.EndWrap();
    predicates.EndWrap();
    auto resultSet = helper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        ReleaseDataShareHelper(helper);
        return false;
    }

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        sptr<ReminderRequest> reminder = CreateReminder(resultSet);
        if (reminder == nullptr) {
            continue;
        }
        reminders[reminder->GetIdentifier()] = reminder;
    }
    ReleaseDataShareHelper(helper);
    ANSR_LOGD("Query size: %{public}d.", static_cast<int32_t>(reminders.size()));
    return true;
}

bool ReminderDataShareHelper::Update(const int32_t reminderId, const int32_t state)
{
    auto helper = CreateDataShareHelper();
    if (helper == nullptr) {
        ANSR_LOGE("null helper");
        return false;
    }
    std::string proxy = ReminderCalendarShareTable::PROXY;
    proxy.append("?user=").append(std::to_string(curUserId_));
    Uri uri(proxy);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ReminderCalendarShareTable::ID, reminderId);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ReminderCalendarShareTable::STATE, state);
    helper->UpdateEx(uri, predicates, valuesBucket);
    ReleaseDataShareHelper(helper);
    return true;
}

void ReminderDataShareHelper::StartDataExtension(const int32_t reason)
{
    AAFwk::Want want;
    want.SetElementName(ReminderCalendarShareTable::DATA_NAME, ReminderCalendarShareTable::ENTRY);
    want.SetParam(ReminderCalendarShareTable::PARAM_CALLBACK_TYPE, reason);
    IN_PROCESS_CALL_WITHOUT_RET(AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr));
}

void ReminderDataShareHelper::UpdateCalendarUid()
{
    uid_ = ReminderBundleManagerHelper::GetInstance().GetDefaultUidByBundleName(ReminderCalendarShareTable::NAME,
        curUserId_);
    dataUid_ = ReminderBundleManagerHelper::GetInstance().GetDefaultUidByBundleName(
        ReminderCalendarShareTable::DATA_NAME, curUserId_);
    AppExecFwk::BundleInfo bundleInfo;
    if (!ReminderBundleManagerHelper::GetInstance().GetBundleInfo(ReminderCalendarShareTable::DATA_NAME,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO, dataUid_, bundleInfo)) {
        ANSR_LOGE("GetBundleInfo failed.");
        return;
    }
    for (const auto& moduleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& metaData : moduleInfo.metadata) {
            if (metaData.name == "hmos.calendardata.reminderDbVersion") {
                isNewRdbVer_ = true;
                ANSR_LOGE("New calendar rdb version");
                return;
            }
        }
    }
}

std::map<std::string, sptr<ReminderRequest>> ReminderDataShareHelper::GetCacheReminders()
{
    std::map<std::string, sptr<ReminderRequest>> results;
    {
        std::lock_guard<std::mutex> locker(cacheMutex_);
        results = std::move(cache_);
    }
    return results;
}

void ReminderDataShareHelper::InsertCacheReminders(const std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    std::lock_guard<std::mutex> locker(cacheMutex_);
    for (auto& each : reminders) {
        cache_[each.first] = each.second;
    }
}

void ReminderDataShareHelper::OnDataInsertOrDelete()
{
    auto func = []() {
        auto manager = ReminderDataManager::GetInstance();
        if (manager == nullptr) {
            ANSR_LOGE("null manager");
            return;
        }
        manager->OnDataShareInsertOrDelete();
    };
    int64_t timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    if (timestamp - insertTime_ > CYCLE_DATASHARE_TASK) {
        insertTime_ = timestamp;
        insertTask_ = false;
        queue_->submit(func);
    } else {
        bool expected = false;
        if (insertTask_.compare_exchange_strong(expected, true)) {
            ffrt::task_attr taskAttr;
            taskAttr.delay(DURATION_DELAY_TASK);
            queue_->submit(func, taskAttr);
        }
    }
}

void ReminderDataShareHelper::OnDataUpdate(const DataShare::DataShareObserver::ChangeInfo& info)
{
    auto func = []() {
        auto manager = ReminderDataManager::GetInstance();
        if (manager == nullptr) {
            ANSR_LOGE("null manager");
            return;
        }
        auto reminders = ReminderDataShareHelper::GetInstance().GetCacheReminders();
        manager->OnDataShareUpdate(reminders);
    };

    std::map<std::string, sptr<ReminderRequest>> reminders = CreateReminder(info);
    InsertCacheReminders(reminders);
    int64_t timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    if (timestamp - updateTime_ > CYCLE_DATASHARE_TASK) {
        updateTime_ = timestamp;
        updateTask_ = false;
        queue_->submit(func);
    } else {
        bool expected = false;
        if (updateTask_.compare_exchange_strong(expected, true)) {
            ffrt::task_attr taskAttr;
            taskAttr.delay(DURATION_DELAY_TASK);
            queue_->submit(func, taskAttr);
        }
    }
}

std::shared_ptr<DataShare::DataShareHelper> ReminderDataShareHelper::CreateDataShareHelper()
{
    sptr<ISystemAbilityManager> manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        ANSR_LOGE("null manager");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = manager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (remoteObj == nullptr) {
        ANSR_LOGE("null remoteObj");
        return nullptr;
    }

    std::string proxy = ReminderCalendarShareTable::PROXY;
    proxy.append("?user=").append(std::to_string(curUserId_));
    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> ret =
        DataShare::DataShareHelper::Create(remoteObj, proxy, "");
    if (ret.first == 0 && ret.second != nullptr) {
        return ret.second;
    } else {
        ANSR_LOGE("Create DataShareHelper failed.");
        return nullptr;
    }
}

bool ReminderDataShareHelper::ReleaseDataShareHelper(const std::shared_ptr<DataShare::DataShareHelper>& helper)
{
    if (helper == nullptr) {
        ANSR_LOGE("null helper");
        return false;
    }
    return helper->Release();
}

std::vector<std::string> ReminderDataShareHelper::GetColumns() const
{
    if (isNewRdbVer_) {
        return std::vector<std::string> {
            ReminderCalendarShareTable::ID, ReminderCalendarShareTable::EVENT_ID,
            ReminderCalendarShareTable::END, ReminderCalendarShareTable::ALARM_TIME,
            ReminderCalendarShareTable::STATE, ReminderCalendarShareTable::TITLE,
            ReminderCalendarShareTable::CONTENT, ReminderCalendarShareTable::WANT_AGENT,
            ReminderCalendarShareTable::BUTTONS, ReminderCalendarShareTable::SLOT_TYPE,
            ReminderCalendarShareTable::IDENTIFIER, ReminderCalendarShareTable::TIME_INTERVAL,
            ReminderCalendarShareTable::SNOOZE_TIMES, ReminderCalendarShareTable::RING_DURATION,
            ReminderCalendarShareTable::SNOOZE_SLOT_TYPE, ReminderCalendarShareTable::SNOOZE_CONTENT,
            ReminderCalendarShareTable::EXPIRED_CONTENT, ReminderCalendarShareTable::MAX_SCREEN_WANT_AGENT,
            ReminderCalendarShareTable::CUSTOM_RING_URI
        };
    } else {
        return std::vector<std::string> {
            ReminderCalendarShareTable::ID, ReminderCalendarShareTable::EVENT_ID,
            ReminderCalendarShareTable::END, ReminderCalendarShareTable::ALARM_TIME,
            ReminderCalendarShareTable::STATE, ReminderCalendarShareTable::TITLE,
            ReminderCalendarShareTable::CONTENT, ReminderCalendarShareTable::WANT_AGENT,
            ReminderCalendarShareTable::BUTTONS, ReminderCalendarShareTable::SLOT_TYPE,
            ReminderCalendarShareTable::IDENTIFIER
        };
    }
}

sptr<ReminderRequest> ReminderDataShareHelper::CreateReminder(
    const std::shared_ptr<DataShare::DataShareResultSet>& result)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    InitNormalInfo(reminder);
    BuildReminderV1(result, reminder);
    uint64_t triggerTime = 0;
    GetRdbValue<uint64_t>(result, ReminderCalendarShareTable::ALARM_TIME, triggerTime);
    reminder->SetTriggerTimeInMilli(triggerTime);

    int32_t reminderId = 0;
    GetRdbValue<int32_t>(result, ReminderCalendarShareTable::ID, reminderId);
    reminder->SetReminderId(reminderId);
    int32_t notificationId = 0;
    GetRdbValue<int32_t>(result, ReminderCalendarShareTable::EVENT_ID, notificationId);
    reminder->SetNotificationId(notificationId);

    int32_t slotType = 0;
    GetRdbValue<int32_t>(result, ReminderCalendarShareTable::SLOT_TYPE, slotType);
    reminder->SetSlotType(NotificationConstant::SlotType(slotType));

    std::string strValue;
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::TITLE, strValue);
    reminder->SetTitle(strValue);
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::CONTENT, strValue);
    reminder->SetContent(strValue);
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::BUTTONS, strValue);
    reminder->DeserializeButtonInfoFromJson(strValue);
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::WANT_AGENT, strValue);
    reminder->DeserializeWantAgent(strValue, 0);
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::IDENTIFIER, strValue);
    reminder->SetIdentifier(strValue);
    uint64_t endDateTime = 0;
    GetRdbValue<uint64_t>(result, ReminderCalendarShareTable::END, endDateTime);
    reminder->SetAutoDeletedTime(endDateTime);

    ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
    calendar->SetDateTime(triggerTime);
    calendar->SetEndDateTime(endDateTime);

    time_t now = static_cast<time_t>(triggerTime / DURATION_ONE_SECOND);
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    calendar->SetFirstDesignateYear(static_cast<uint16_t>(ReminderRequest::GetActualTime(
        ReminderRequest::TimeTransferType::YEAR, nowTime.tm_year)));
    calendar->SetFirstDesignageMonth(static_cast<uint16_t>(ReminderRequest::GetActualTime(
        ReminderRequest::TimeTransferType::MONTH, nowTime.tm_mon)));
    calendar->SetFirstDesignateDay(nowTime.tm_mday);
    return reminder;
}

std::map<std::string, sptr<ReminderRequest>> ReminderDataShareHelper::CreateReminder(
    const DataShare::DataShareObserver::ChangeInfo& info)
{
    std::map<std::string, sptr<ReminderRequest>> reminders;
    for (auto& values : info.valueBuckets_) {
        sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
        InitNormalInfo(reminder);
        uint64_t triggerTime = 0;
        auto iter = values.find(ReminderCalendarShareTable::ALARM_TIME);
        if (iter != values.end()) {
            triggerTime = static_cast<uint64_t>(std::get<double>(iter->second));
            reminder->SetTriggerTimeInMilli(triggerTime);
        }
        InitBaseInfo(values, reminder);
        BuildReminderV1(values, reminder);
        uint64_t endDateTime = 0;
        iter = values.find(ReminderCalendarShareTable::END);
        if (iter != values.end()) {
            endDateTime = static_cast<uint64_t>(std::get<double>(iter->second));
            reminder->SetAutoDeletedTime(endDateTime);
        }

        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        calendar->SetDateTime(triggerTime);
        calendar->SetEndDateTime(endDateTime);

        time_t now = static_cast<time_t>(calendar->GetDateTime() / DURATION_ONE_SECOND);
        struct tm nowTime;
        (void)localtime_r(&now, &nowTime);
        calendar->SetFirstDesignateYear(static_cast<uint16_t>(ReminderRequest::GetActualTime(
            ReminderRequest::TimeTransferType::YEAR, nowTime.tm_year)));
        calendar->SetFirstDesignageMonth(static_cast<uint16_t>(ReminderRequest::GetActualTime(
            ReminderRequest::TimeTransferType::MONTH, nowTime.tm_mon)));
        calendar->SetFirstDesignateDay(nowTime.tm_mday);
        reminders[reminder->GetIdentifier()] = reminder;
    }
    return reminders;
}

void ReminderDataShareHelper::InitNormalInfo(sptr<ReminderRequest>& reminder)
{
    reminder->SetRingDuration(0);
    reminder->SetRingLoop(false);
    reminder->InitUserId(curUserId_);
    reminder->InitUid(uid_);
    reminder->InitCreatorUid(dataUid_);
    reminder->SetShare(true);
    reminder->InitBundleName(ReminderCalendarShareTable::NAME);
    reminder->InitCreatorBundleName(ReminderCalendarShareTable::DATA_NAME);
    reminder->SetSystemApp(true);
    reminder->SetTapDismissed(true);
}

void ReminderDataShareHelper::InitBaseInfo(const DataShare::DataShareObserver::ChangeInfo::VBucket& info,
    sptr<ReminderRequest>& reminder)
{
    auto iter = info.find(ReminderCalendarShareTable::ID);
    if (iter != info.end()) {
        reminder->SetReminderId(static_cast<int32_t>(std::get<double>(iter->second)));
    }
    iter = info.find(ReminderCalendarShareTable::EVENT_ID);
    if (iter != info.end()) {
        reminder->SetNotificationId(static_cast<int32_t>(std::get<double>(iter->second)));
    }
    iter = info.find(ReminderCalendarShareTable::SLOT_TYPE);
    if (iter != info.end()) {
        reminder->SetSlotType(
            NotificationConstant::SlotType(static_cast<int32_t>(std::get<double>(iter->second))));
    }
    iter = info.find(ReminderCalendarShareTable::TITLE);
    if (iter != info.end()) {
        reminder->SetTitle(std::get<std::string>(iter->second));
    }
    iter = info.find(ReminderCalendarShareTable::CONTENT);
    if (iter != info.end()) {
        reminder->SetContent(std::get<std::string>(iter->second));
    }
    iter = info.find(ReminderCalendarShareTable::BUTTONS);
    if (iter != info.end()) {
        reminder->DeserializeButtonInfoFromJson(std::get<std::string>(iter->second));
    }
    iter = info.find(ReminderCalendarShareTable::WANT_AGENT);
    if (iter != info.end()) {
        reminder->DeserializeWantAgent(std::get<std::string>(iter->second), 0);
    }
    iter = info.find(ReminderCalendarShareTable::IDENTIFIER);
    if (iter != info.end()) {
        reminder->SetIdentifier(std::get<std::string>(iter->second));
    }
}

void ReminderDataShareHelper::BuildReminderV1(const std::shared_ptr<DataShare::DataShareResultSet>& result,
    sptr<ReminderRequest>& reminder)
{
    if (!isNewRdbVer_) {
        return;
    }
    uint64_t timeInterval = 0;
    GetRdbValue<uint64_t>(result, ReminderCalendarShareTable::TIME_INTERVAL, timeInterval);
    reminder->SetTimeInterval(timeInterval);
    uint8_t snoozeTimes = 0;
    GetRdbValue<uint8_t>(result, ReminderCalendarShareTable::SNOOZE_TIMES, snoozeTimes);
    reminder->SetSnoozeTimes(snoozeTimes);
    uint64_t ringDuration = 0;
    GetRdbValue<uint64_t>(result, ReminderCalendarShareTable::RING_DURATION, ringDuration);
    reminder->SetRingDuration(ringDuration);
    int32_t snoozeSlotType = 0;
    GetRdbValue<int32_t>(result, ReminderCalendarShareTable::SNOOZE_SLOT_TYPE, snoozeSlotType);
    reminder->SetSnoozeSlotType(NotificationConstant::SlotType(snoozeSlotType));
    std::string snoozeContent;
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::SNOOZE_CONTENT, snoozeContent);
    reminder->SetSnoozeContent(snoozeContent);
    std::string expiredContent;
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::EXPIRED_CONTENT, expiredContent);
    reminder->SetExpiredContent(expiredContent);
    std::string maxScreenWantAgent;
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::MAX_SCREEN_WANT_AGENT, maxScreenWantAgent);
    reminder->DeserializeWantAgent(maxScreenWantAgent, 1);
    std::string customRingUri;
    GetRdbValue<std::string>(result, ReminderCalendarShareTable::CUSTOM_RING_URI, customRingUri);
    reminder->SetCustomRingUri(customRingUri);
}

void ReminderDataShareHelper::BuildReminderV1(const DataShare::DataShareObserver::ChangeInfo::VBucket& info,
    sptr<ReminderRequest>& reminder)
{
    if (!isNewRdbVer_) {
        return;
    }
    auto iter = info.find(ReminderCalendarShareTable::TIME_INTERVAL);
    if (iter != info.end()) {
        reminder->SetTimeInterval(static_cast<uint64_t>(std::get<double>(iter->second)));
    }
    iter = info.find(ReminderCalendarShareTable::SNOOZE_TIMES);
    if (iter != info.end()) {
        reminder->SetSnoozeTimes(static_cast<uint8_t>(std::get<double>(iter->second)));
    }
    iter = info.find(ReminderCalendarShareTable::RING_DURATION);
    if (iter != info.end()) {
        reminder->SetRingDuration(static_cast<uint64_t>(std::get<double>(iter->second)));
    }
    iter = info.find(ReminderCalendarShareTable::SNOOZE_SLOT_TYPE);
    if (iter != info.end()) {
        reminder->SetSnoozeSlotType(
            NotificationConstant::SlotType(static_cast<int32_t>(std::get<double>(iter->second))));
    }
    iter = info.find(ReminderCalendarShareTable::SNOOZE_CONTENT);
    if (iter != info.end()) {
        reminder->SetSnoozeContent(std::get<std::string>(iter->second));
    }
    iter = info.find(ReminderCalendarShareTable::EXPIRED_CONTENT);
    if (iter != info.end()) {
        reminder->SetExpiredContent(std::get<std::string>(iter->second));
    }
    iter = info.find(ReminderCalendarShareTable::MAX_SCREEN_WANT_AGENT);
    if (iter != info.end()) {
        reminder->DeserializeWantAgent(std::get<std::string>(iter->second), 1);
    }
    iter = info.find(ReminderCalendarShareTable::CUSTOM_RING_URI);
    if (iter != info.end()) {
        reminder->SetCustomRingUri(std::get<std::string>(iter->second));
    }
}

ReminderDataShareHelper::ReminderDataShareHelper()
{
    queue_ = std::make_shared<ffrt::queue>("ReminderDataShareHelper");
    insertTime_ =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    updateTime_.store(insertTime_.load());
}

void ReminderDataShareHelper::ReminderDataObserver::OnChange(const ChangeInfo& info)
{
    switch (info.changeType_) {
        case DataShare::DataShareObserver::ChangeType::INSERT: {
            ANSR_LOGI("DataShare insert.");
            ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
            break;
        }
        case DataShare::DataShareObserver::ChangeType::UPDATE: {
            ANSR_LOGI("DataShare update.");
            ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
            break;
        }
        case DataShare::DataShareObserver::ChangeType::DELETE: {
            ANSR_LOGI("DataShare delete.");
            ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
            break;
        }
        default: {
            break;
        }
    }
}
}