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
#include "reminder_data_manager.h"
#include "reminder_request_calendar.h"
#include "reminder_calendar_share_table.h"

#include "iservice_registry.h"
#include "ability_manager_client.h"
#include "in_process_call_wrapper.h"
#include "system_ability_definition.h"
#include "reminder_bundle_manager_helper.h"

namespace OHOS::Notification {
static constexpr int64_t DURATION_PRELOAD_TIME = 10 * 60 * 60 * 1000;  // 10h, millisecond
static constexpr int64_t DURATION_DELAY_TASK = 1 * 1000 * 1000;  // 1s, microsecond
static constexpr int64_t CYCLE_DATASHARE_TASK = 1;  // 1s
static constexpr int64_t DURATION_ONE_SECOND = 1000;  // 1s, millisecond
static constexpr int8_t CALENDAR_RDB_V1 = 1;
static constexpr int8_t CALENDAR_RDB_V2 = 2;
static constexpr int8_t FLAG_COLUMN_INDEX_NOT_FETCH = -2;
static constexpr int8_t FLAG_COLUMN_INDEX_NOT_EXIST = -1;

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
    auto helper = CreateDataShareHelper(ReminderCalendarShareTable::PROXY);
    if (helper == nullptr) {
        ANSR_LOGE("DataShareHelper is null.");
        return false;
    }
    observer_ = std::make_shared<ReminderDataObserver>();
    Uri uri(ReminderCalendarShareTable::PROXY);
    int32_t ret = helper->TryRegisterObserverExt(uri, observer_, false);
    if (ret != ERR_OK) {
        ANSR_LOGE("RegisterObserver failed[%{public}d]", ret);
        observer_ = nullptr;
        helper->Release();
        return false;
    }
    helper->Release();
    return true;
}

bool ReminderDataShareHelper::UnRegisterObserver()
{
    std::lock_guard<std::mutex> locker(mutex_);
    if (observer_ == nullptr) {
        return true;
    }
    auto helper = CreateDataShareHelper(ReminderCalendarShareTable::PROXY);
    if (helper == nullptr) {
        ANSR_LOGE("DataShareHelper is null.");
        return false;
    }
    Uri uri(ReminderCalendarShareTable::PROXY);
    helper->TryUnregisterObserverExt(uri, observer_);
    helper->Release();
    observer_ = nullptr;
    return true;
}

DataShare::DataSharePredicates ReminderDataShareHelper::BuildQueryPredicates(int64_t timestamp, int64_t targetTimestamp)
{
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
    return predicates;
}

bool ReminderDataShareHelper::Query(std::map<std::string, sptr<ReminderRequest>>& reminders)
{
    auto helper = CreateDataShareHelper(ReminderCalendarShareTable::PROXY);
    if (helper == nullptr) {
        ANSR_LOGE("DataShareHelper is null.");
        return false;
    }
    int64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int64_t targetTimestamp = timestamp + DURATION_PRELOAD_TIME;

    std::string proxy = ReminderCalendarShareTable::PROXY;
    proxy.append("?user=").append(std::to_string(userId_));
    Uri uri(proxy);
    std::vector<std::string> columns;
    DataShare::DataSharePredicates predicates = BuildQueryPredicates(timestamp, targetTimestamp);
    auto resultSet = helper->Query(uri, predicates, columns);
    if (resultSet == nullptr) {
        helper->Release();
        return false;
    }
    int32_t totalCount = 0;
    int32_t needAgentColumnIndex = FLAG_COLUMN_INDEX_NOT_FETCH;
    resultSet->GetRowCount(totalCount);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        // use cache if column index is fetched
        if (needAgentColumnIndex == FLAG_COLUMN_INDEX_NOT_FETCH) {
            resultSet->GetColumnIndex(ReminderCalendarShareTable::NEED_AGENT, needAgentColumnIndex);
        }
        // needAgent column exist
        if (needAgentColumnIndex != FLAG_COLUMN_INDEX_NOT_EXIST) {
            int32_t needAgent = 0;
            GetRdbValue<int32_t>(resultSet, ReminderCalendarShareTable::NEED_AGENT, needAgent);
            // send by calendar
            if (needAgent == 0) {
                continue;
            }
        }
        sptr<ReminderRequest> reminder = CreateReminder(resultSet);
        if (reminder == nullptr) {
            continue;
        }
        // send by reminder agent
        reminders[reminder->GetIdentifier()] = reminder;
    }
    helper->Release();
    ANSR_LOGI("total: %{public}d, with agent: %{public}d, needAgent column index: %{public}d",
        totalCount,
        static_cast<int32_t>(reminders.size()),
        needAgentColumnIndex);
    return true;
}

bool ReminderDataShareHelper::Query(Uri& uri, const std::string& key, std::string& value)
{
    constexpr const char* SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
    constexpr const char* DATA_COLUMN_KEYWORD = "KEYWORD";
    constexpr const char* DATA_COLUMN_VALUE = "VALUE";
    auto helper = CreateDataShareHelper(SETTINGS_DATA_EXT_URI);
    if (helper == nullptr) {
        ANSR_LOGE("DataShareHelper is null.");
        return false;
    }
    DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    predicates.EqualTo(DATA_COLUMN_KEYWORD, key);
    auto result = helper->Query(uri, predicates, columns);
    if (result == nullptr) {
        ANSR_LOGE("Query failed, result is null");
        return false;
    }
    if (result->GoToFirstRow() != DataShare::E_OK) {
        ANSR_LOGE("GoToFirstRow failed.");
        result->Close();
        helper->Release();
        return true;
    }
    int32_t columnIndex;
    result->GetColumnIndex(DATA_COLUMN_VALUE, columnIndex);
    result->GetString(columnIndex, value);
    result->Close();
    helper->Release();
    return true;
}

bool ReminderDataShareHelper::Update(const std::string& identifier, const int32_t state)
{
    auto helper = CreateDataShareHelper(ReminderCalendarShareTable::PROXY);
    if (helper == nullptr) {
        ANSR_LOGE("DataShareHelper is null.");
        return false;
    }
    std::string proxy = ReminderCalendarShareTable::PROXY;
    proxy.append("?user=").append(std::to_string(userId_));
    Uri uri(proxy);

    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ReminderCalendarShareTable::IDENTIFIER, identifier);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(ReminderCalendarShareTable::STATE, state);
    auto ret = helper->UpdateEx(uri, predicates, valuesBucket);
    if (ret.first != ERR_OK) {
        ANSR_LOGE("Update calendar rdb failed[%{public}d].", ret.first);
    }
    helper->Release();
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
    ANSR_LOGI("Update calendar uid and query calendar info");
    uid_ = ReminderBundleManagerHelper::GetInstance().GetDefaultUidByBundleName(ReminderCalendarShareTable::NAME,
        userId_);
    dataUid_ = ReminderBundleManagerHelper::GetInstance().GetDefaultUidByBundleName(
        ReminderCalendarShareTable::DATA_NAME, userId_);
    AppExecFwk::BundleInfo bundleInfo;
    if (!ReminderBundleManagerHelper::GetInstance().GetBundleInfo(ReminderCalendarShareTable::DATA_NAME,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO, dataUid_, bundleInfo)) {
        ANSR_LOGE("GetBundleInfo failed.");
        return;
    }
    for (const auto& moduleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& metaData : moduleInfo.metadata) {
            if (metaData.name != "hmos.calendardata.reminderDbVersion") {
                continue;
            }
            ANSR_LOGI("calendar rdb is new version.");
            if (metaData.value == "1") {
                rdbVersion_ = CALENDAR_RDB_V1;
            } else if (metaData.value == "2") {
                rdbVersion_ = CALENDAR_RDB_V2;
            }
            return;
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

std::shared_ptr<DataShare::DataShareHelper> ReminderDataShareHelper::CreateDataShareHelper(const std::string& uriStr)
{
    sptr<ISystemAbilityManager> manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        ANSR_LOGE("GetSystemAbilityManager is null.");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = manager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (remoteObj == nullptr) {
        ANSR_LOGE("GetSystemAbility is null.");
        return nullptr;
    }

    std::string proxy = uriStr;
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

sptr<ReminderRequest> ReminderDataShareHelper::CreateReminder(
    const std::shared_ptr<DataShare::DataShareResultSet>& result)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    InitNormalInfo(reminder);
    BuildReminderV1(result, reminder);
    uint64_t triggerTime = 0;
    GetRdbValue<uint64_t>(result, ReminderCalendarShareTable::ALARM_TIME, triggerTime);
    reminder->SetTriggerTimeInMilli(triggerTime);
    reminder->SetOriTriggerTimeInMilli(triggerTime);

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
            reminder->SetOriTriggerTimeInMilli(triggerTime);
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
    reminder->SetRingChannel(ReminderRequest::RingChannel::NOTIFICATION);
    reminder->InitUserId(userId_);
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
    if (rdbVersion_ == 0) {
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
    if (rdbVersion_ == 0) {
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