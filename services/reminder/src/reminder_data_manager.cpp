/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "reminder_data_manager.h"

#include "ability_manager_client.h"
#include "ans_log_wrapper.h"
#include "ans_const_define.h"
#include "common_event_support.h"
#include "common_event_manager.h"
#include "reminder_request_calendar.h"
#include "in_process_call_wrapper.h"
#ifdef DEVICE_STANDBY_ENABLE
#include "standby_service_client.h"
#include "allow_type.h"
#endif
#include "ipc_skeleton.h"
#include "notification_slot.h"
#include "os_account_manager.h"
#include "reminder_os_account_manager_helper.h"
#include "reminder_event_manager.h"
#include "time_service_client.h"
#include "singleton.h"
#include "locale_config.h"
#include "reminder_bundle_manager_helper.h"
#include "datashare_predicates_object.h"
#include "datashare_value_object.h"
#include "datashare_helper.h"
#include "data_share_permission.h"
#include "datashare_errno.h"
#include "datashare_template.h"
#include "system_ability_definition.h"
#include "app_mgr_constants.h"
#include "iservice_registry.h"
#include "config_policy_utils.h"
#include "hitrace_meter_adapter.h"
#ifdef HAS_HISYSEVENT_PART
#include "hisysevent.h"
#endif
#include "reminder_utils.h"
#include "notification_helper.h"

namespace OHOS {
namespace Notification {
namespace {
const std::string ALL_PACKAGES = "allPackages";
const int32_t MAIN_USER_ID = 100;
#ifdef DEVICE_STANDBY_ENABLE
const int REASON_APP_API = 1;
#endif
const int INDEX_KEY = 0;
const int INDEX_TYPE = 1;
const int INDEX_VALUE = 2;
const int64_t ONE_MIN_TIME = 60 * 1000;
const int64_t NEXT_LOAD_TIME = 20 * ONE_MIN_TIME;
constexpr int8_t NORMAL_CALLBACK = 0;  // timer callback
constexpr int8_t REISSUE_CALLBACK = 1;  // time change, boot complte callback
}

/**
 * Default reminder sound.
 */
const std::string DEFAULT_REMINDER_SOUND_1 = "/system/etc/capture.ogg";
const std::string DEFAULT_REMINDER_SOUND_2 = "resource/media/audio/alarms/Aegean_Sea.ogg";

std::shared_ptr<ReminderDataManager> ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
std::mutex ReminderDataManager::MUTEX;
std::mutex ReminderDataManager::SHOW_MUTEX;
std::mutex ReminderDataManager::ALERT_MUTEX;
std::mutex ReminderDataManager::TIMER_MUTEX;
std::mutex ReminderDataManager::ACTIVE_MUTEX;
constexpr int32_t CONNECT_EXTENSION_INTERVAL = 100;
constexpr int32_t CONNECT_EXTENSION_MAX_RETRY_TIMES = 3;
std::shared_ptr<ffrt::queue> ReminderDataManager::serviceQueue_ = nullptr;
ReminderDataManager::ReminderDataManager() = default;
ReminderDataManager::~ReminderDataManager() = default;

ErrCode ReminderDataManager::PublishReminder(const sptr<ReminderRequest> &reminder,
    const int32_t callingUid)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    uint32_t callerTokenId = IPCSkeleton::GetCallingTokenID();
    if (callerTokenId == 0) {
        ANSR_LOGE("pushlish failed, callerTokenId is 0");
        return ERR_REMINDER_CALLER_TOKEN_INVALID;
    }

    if (!IsActionButtonDataShareValid(reminder, callerTokenId)) {
        return ERR_REMINDER_DATA_SHARE_PERMISSION_DENIED;
    }

    if (CheckReminderLimitExceededLocked(callingUid, reminder)) {
        return ERR_REMINDER_NUMBER_OVERLOAD;
    }
    UpdateAndSaveReminderLocked(reminder);
    queue_->submit([this, reminder]() {
        StartRecentReminder();
    });
    return ERR_OK;
}

ErrCode ReminderDataManager::CancelReminder(
    const int32_t &reminderId, const int32_t callingUid)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGI("cancel reminder id: %{public}d", reminderId);
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGW("Cancel reminder, not find the reminder");
        return ERR_REMINDER_NOT_EXIST;
    }
    if (!CheckIsSameApp(reminder, callingUid)) {
        ANSR_LOGW("Not find the reminder due to not match");
        return ERR_REMINDER_NOT_EXIST;
    }
    if (activeReminderId_ == reminderId) {
        ANSR_LOGD("Cancel active reminder, id=%{public}d", reminderId);
        {
            std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
            activeReminder_->OnStop();
        }
        StopTimerLocked(TimerType::TRIGGER_TIMER);
    }
    if (alertingReminderId_ == reminderId) {
        StopSoundAndVibrationLocked(reminder);
        StopTimerLocked(TimerType::ALERTING_TIMER);
    }
    CancelNotification(reminder);
    RemoveReminderLocked(reminderId);
    StartRecentReminder();
    return ERR_OK;
}

ErrCode ReminderDataManager::CancelAllReminders(const std::string& bundleName,
    const int32_t userId, const int32_t callingUid)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    ANSR_LOGD("CancelAllReminders, userId=%{private}d", userId);
    CancelRemindersImplLocked(bundleName, userId, callingUid);
    return ERR_OK;
}

sptr<ReminderRequest> ReminderDataManager::CheckExcludeDateParam(const int32_t reminderId,
    const int32_t callingUid)
{
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGW("Check reminder failed, not find the reminder");
        return nullptr;
    }
    if (!CheckIsSameApp(reminder, callingUid)) {
        ANSR_LOGW("Check reminder failed, due to not match");
        return nullptr;
    }
    if (reminder->GetReminderType() != ReminderRequest::ReminderType::CALENDAR
        || !reminder->IsRepeat()) {
        ANSR_LOGW("Check reminder failed, due to type not match or not repeat");
        return nullptr;
    }
    return reminder;
}

ErrCode ReminderDataManager::AddExcludeDate(const int32_t reminderId, const int64_t date,
    const int32_t callingUid)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    sptr<ReminderRequest> reminder = CheckExcludeDateParam(reminderId, callingUid);
    if (reminder == nullptr) {
        return ERR_REMINDER_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        calendar->AddExcludeDate(date);
        store_->UpdateOrInsert(reminder);
    }
    return ERR_OK;
}

ErrCode ReminderDataManager::DelExcludeDates(const int32_t reminderId,
    const int32_t callingUid)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    sptr<ReminderRequest> reminder = CheckExcludeDateParam(reminderId, callingUid);
    if (reminder == nullptr) {
        return ERR_REMINDER_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        calendar->DelExcludeDates();
        store_->UpdateOrInsert(reminder);
    }
    return ERR_OK;
}

ErrCode ReminderDataManager::GetExcludeDates(const int32_t reminderId,
    const int32_t callingUid, std::vector<int64_t>& dates)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    sptr<ReminderRequest> reminder = CheckExcludeDateParam(reminderId, callingUid);
    if (reminder == nullptr) {
        return ERR_REMINDER_NOT_EXIST;
    }
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        dates = calendar->GetExcludeDates();
    }
    return ERR_OK;
}

void ReminderDataManager::GetValidReminders(
    const int32_t callingUid, std::vector<ReminderRequestAdaptation> &reminders)
{
    HITRACE_METER_NAME(HITRACE_TAG_OHOS, __PRETTY_FUNCTION__);
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    auto reminderVector = store_->GetAllValidReminders();
    for (auto& eachReminder : reminderVector) {
        if (eachReminder->IsExpired()) {
            continue;
        }
        ReminderRequestAdaptation reminderRequestAdaptation;

        if (CheckIsSameApp(eachReminder, callingUid)) {
            reminderRequestAdaptation.reminderRequest_ = eachReminder;
            reminders.push_back(reminderRequestAdaptation);
        }
    }
}

void ReminderDataManager::CancelAllReminders(const int32_t userId)
{
    ANSR_LOGD("CancelAllReminders, userId=%{private}d", userId);
    CancelRemindersImplLocked(ALL_PACKAGES, userId, -1, true);
}

void ReminderDataManager::CancelRemindersImplLocked(const std::string& packageName, const int32_t userId,
    const int32_t uid, bool isCancelAllPackage)
{
    MUTEX.lock();
    {
        std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
        if (activeReminderId_ != -1 && IsMatched(activeReminder_, userId, uid, isCancelAllPackage)) {
            activeReminder_->OnStop();
            StopTimer(TimerType::TRIGGER_TIMER);
            ANSR_LOGD("Stop active reminder, reminderId=%{public}d", activeReminderId_.load());
        }
    }
    for (auto vit = reminderVector_.begin(); vit != reminderVector_.end();) {
        if (IsMatched(*vit, userId, uid, isCancelAllPackage)) {
            if ((*vit)->IsAlerting()) {
                StopAlertingReminder(*vit);
            }
            CancelNotification(*vit);
            RemoveFromShowedReminders(*vit);
            vit = reminderVector_.erase(vit);
            totalCount_--;
            continue;
        }
        ++vit;
    }
    if (store_ == nullptr) {
        MUTEX.unlock();
        ANSR_LOGE("CancelRemindersImplLocked failed, store_ is null");
        return;
    }
    if (isCancelAllPackage) {
        store_->DeleteUser(userId);
    } else {
        store_->Delete(packageName, userId, uid);
    }
    MUTEX.unlock();
    StartRecentReminder();
}

bool ReminderDataManager::IsMatchedForGroupIdAndPkgName(const sptr<ReminderRequest> &reminder,
    const std::string &packageName, const std::string &groupId) const
{
    std::string packageNameTemp = reminder->GetBundleName();
    if (packageNameTemp.empty()) {
        ANSR_LOGW("reminder package name is null");
        return false;
    }
    if (packageNameTemp == packageName && reminder->GetGroupId() == groupId) {
        return true;
    }
    return false;
}

bool ReminderDataManager::IsMatched(const sptr<ReminderRequest> &reminder,
    const int32_t userId, const int32_t uid, bool isCancelAllPackage) const
{
    if (reminder->GetUserId() != userId) {
        return false;
    }
    if (isCancelAllPackage) {
        return true;
    }
    if (uid != -1 && reminder->GetUid() == uid) {
        return true;
    }
    return false;
}

void ReminderDataManager::CancelNotification(const sptr<ReminderRequest> &reminder) const
{
    if (!(reminder->IsShowing())) {
        ANSR_LOGD("No need to cancel notification");
        return;
    }
    ANSR_LOGD("Cancel notification");
    IN_PROCESS_CALL_WITHOUT_RET(NotificationHelper::CancelNotification(
        ReminderRequest::NOTIFICATION_LABEL, reminder->GetNotificationId()));
}

bool ReminderDataManager::CheckReminderLimitExceededLocked(const int32_t callingUid,
    const sptr<ReminderRequest>& reminder) const
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    if (totalCount_ >= ReminderDataManager::MAX_NUM_REMINDER_LIMIT_SYSTEM) {
        ANSR_LOGW("The number of validate reminders exceeds the system upper limit:%{public}d, \
            and new reminder can not be published", MAX_NUM_REMINDER_LIMIT_SYSTEM);
        return true;
    }
    int32_t count = 0;
    for (const auto& eachReminder : reminderVector_) {
        if (eachReminder->IsExpired()) {
            continue;
        }
        if (CheckIsSameApp(eachReminder, callingUid)) {
            count++;
        }
    }
    auto maxReminderNum = reminder->IsSystemApp() ? MAX_NUM_REMINDER_LIMIT_SYS_APP : MAX_NUM_REMINDER_LIMIT_APP;
    if (count >= maxReminderNum) {
        ANSR_LOGW("The number of validate reminders exceeds the application upper limit:%{public}d, and new \
            reminder can not be published", maxReminderNum);
        return true;
    }
    return false;
}

void ReminderDataManager::AddToShowedReminders(const sptr<ReminderRequest> &reminder)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
    for (auto it = showedReminderVector_.begin(); it != showedReminderVector_.end(); ++it) {
        if (reminder->GetReminderId() == (*it)->GetReminderId()) {
            ANSR_LOGD("Showed reminder is already exist");
            return;
        }
    }
    showedReminderVector_.push_back(reminder);
}

void ReminderDataManager::OnUserRemove(const int32_t& userId)
{
    if (!IsReminderAgentReady()) {
        ANSR_LOGW("Give up to remove user id: %{private}d for reminderAgent is not ready", userId);
        return;
    }
    CancelAllReminders(userId);
}

void ReminderDataManager::OnUserSwitch(const int32_t& userId)
{
    ANSR_LOGD("Switch user id from %{private}d to %{private}d", currentUserId_, userId);
    currentUserId_ = userId;
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    if ((alertingReminderId_ != -1) && IsReminderAgentReady()) {
        TerminateAlerting(alertingReminder_, "OnUserSwitch");
    }
}

void ReminderDataManager::OnProcessDiedLocked(const int32_t callingUid)
{
    ANSR_LOGD("OnProcessDiedLocked, uid=%{public}d", callingUid);
    std::lock_guard<std::mutex> locker(ReminderDataManager::MUTEX);
    std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
    for (auto it = showedReminderVector_.begin(); it != showedReminderVector_.end(); ++it) {
        if ((*it)->GetUid() != callingUid) {
            continue;
        }
        if ((*it)->IsAlerting()) {
            TerminateAlerting((*it), "onProcessDied");
        } else {
            CancelNotification(*it);
            (*it)->OnClose(false);
            showedReminderVector_.erase(it);
            --it;
        }
        store_->UpdateOrInsert((*it));
    }
}

void ReminderDataManager::InitTimerInfo(std::shared_ptr<ReminderTimerInfo> &sharedTimerInfo,
    const sptr<ReminderRequest> &reminderRequest, TimerType reminderType) const
{
    uint8_t timerTypeWakeup = static_cast<uint8_t>(sharedTimerInfo->TIMER_TYPE_WAKEUP);
    uint8_t timerTypeExact = static_cast<uint8_t>(sharedTimerInfo->TIMER_TYPE_EXACT);
    sharedTimerInfo->SetRepeat(false);
    sharedTimerInfo->SetInterval(0);

    sharedTimerInfo->SetBundleName(reminderRequest->GetBundleName());
    sharedTimerInfo->SetUid(reminderRequest->GetUid());

    int32_t timerType = static_cast<int32_t>(timerTypeWakeup | timerTypeExact);
    sharedTimerInfo->SetType(timerType);
}

std::shared_ptr<ReminderTimerInfo> ReminderDataManager::CreateTimerInfo(TimerType type,
    const sptr<ReminderRequest> &reminderRequest) const
{
    auto sharedTimerInfo = std::make_shared<ReminderTimerInfo>();
    if ((sharedTimerInfo->TIMER_TYPE_WAKEUP > UINT8_MAX) || (sharedTimerInfo->TIMER_TYPE_EXACT > UINT8_MAX)) {
        ANSR_LOGE("Failed to set timer type.");
        return nullptr;
    }
    InitTimerInfo(sharedTimerInfo, reminderRequest, type);

    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);

    auto want = std::make_shared<OHOS::AAFwk::Want>();
    switch (type) {
        case (TimerType::TRIGGER_TIMER): {
            want->SetAction(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
            sharedTimerInfo->SetAction(ReminderRequest::REMINDER_EVENT_ALARM_ALERT);
            want->SetParam(ReminderRequest::PARAM_REMINDER_ID, activeReminderId_);
            break;
        }
        case (TimerType::ALERTING_TIMER): {
            if (alertingReminderId_ == -1) {
                ANSR_LOGE("Create alerting time out timer Illegal.");
                return sharedTimerInfo;
            }
            want->SetAction(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
            sharedTimerInfo->SetAction(ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT);
            want->SetParam(ReminderRequest::PARAM_REMINDER_ID, alertingReminderId_);
            break;
        }
        default:
            ANSR_LOGE("TimerType not support");
            break;
    }
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags, wants, nullptr);

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, 0);
    IPCSkeleton::SetCallingIdentity(identity);

    sharedTimerInfo->SetWantAgent(wantAgent);
    return sharedTimerInfo;
}

sptr<ReminderRequest> ReminderDataManager::FindReminderRequestLocked(const int32_t &reminderId)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        if (reminderId == (*it)->GetReminderId()) {
            return *it;
        }
    }
    ANSR_LOGD("Not find the reminder");
    return nullptr;
}

bool ReminderDataManager::cmp(sptr<ReminderRequest> &reminderRequest, sptr<ReminderRequest> &other)
{
    return reminderRequest->GetTriggerTimeInMilli() < other->GetTriggerTimeInMilli();
}

void ReminderDataManager::CloseReminder(const OHOS::EventFwk::Want &want, bool cancelNotification, bool isButtonClick)
{
    int32_t reminderId = static_cast<int32_t>(want.GetIntParam(ReminderRequest::PARAM_REMINDER_ID, -1));
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGW("Invalid reminder id: %{public}d", reminderId);
        return;
    }
    std::string packageName = reminder->GetBundleName();
    std::string groupId = reminder->GetGroupId();
    if (!(packageName.empty() || groupId.empty())) {
        ANSR_LOGD("this reminder can close by groupId");
        CloseRemindersByGroupId(reminderId, packageName, groupId);
    }
    CloseReminder(reminder, cancelNotification);
    if (isButtonClick) {
        UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::CLOSE);
        CheckNeedNotifyStatus(reminder, ReminderRequest::ActionButtonType::CLOSE);
    }
    StartRecentReminder();
}

void ReminderDataManager::CloseRemindersByGroupId(const int32_t &oldReminderId, const std::string &packageName,
    const std::string &groupId)
{
    if (packageName == "") {
        ANSR_LOGD("packageName is empty");
        return;
    }
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    for (auto vit = reminderVector_.begin(); vit != reminderVector_.end(); vit++) {
        sptr<ReminderRequest> reminder = *vit;
        if (reminder == nullptr) {
            ANSR_LOGD("reminder is null");
            continue;
        }
        int32_t reminderId = reminder->GetReminderId();
        if (reminderId == oldReminderId) {
            ANSR_LOGD("The old and new reminder are the same");
            continue;
        }
        if (IsMatchedForGroupIdAndPkgName(reminder, packageName, groupId)) {
            reminder->SetExpired(true);
            reminder->SetStateToInActive();
            store_->UpdateOrInsert(reminder);
            ResetStates(TimerType::TRIGGER_TIMER);
            ANSR_LOGD("Cancel reminders by groupid, reminder is %{public}s", reminder->Dump().c_str());
        }
    }
}

void ReminderDataManager::CloseReminder(const sptr<ReminderRequest> &reminder, bool cancelNotification)
{
    int32_t reminderId = reminder->GetReminderId();
    if (activeReminderId_ == reminderId) {
        ANSR_LOGD("Stop active reminder due to CloseReminder");
        {
            std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
            activeReminder_->OnStop();
        }
        StopTimerLocked(TimerType::TRIGGER_TIMER);
    }
    if (alertingReminderId_ == reminderId) {
        StopSoundAndVibrationLocked(reminder);
        StopTimerLocked(TimerType::ALERTING_TIMER);
    }
    reminder->OnClose(true);
    RemoveFromShowedReminders(reminder);
    store_->UpdateOrInsert(reminder);
    if (cancelNotification) {
        CancelNotification(reminder);
    }
}

std::shared_ptr<ReminderDataManager> ReminderDataManager::GetInstance()
{
    return REMINDER_DATA_MANAGER;
}

std::shared_ptr<ReminderDataManager> ReminderDataManager::InitInstance()
{
    if (REMINDER_DATA_MANAGER == nullptr) {
        REMINDER_DATA_MANAGER = std::make_shared<ReminderDataManager>();
        ReminderEventManager reminderEventManager(REMINDER_DATA_MANAGER);
    }
    return REMINDER_DATA_MANAGER;
}

void ReminderDataManager::StartReminderLoadTimer()
{
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Get timeServiceClient failed");
        return;
    }
    std::lock_guard<std::mutex> locker(timeLoadMutex_);
    if (reminderLoadtimerId_ == 0) {
        reminderLoadtimerId_ = CreateReminderLoadTimer(timer);
    }
    timer->StopTimer(reminderLoadtimerId_);
    uint64_t nowMilli = GetCurrentTime() + NEXT_LOAD_TIME;
    timer->StartTimer(reminderLoadtimerId_, nowMilli);
}

int64_t ReminderDataManager::CreateReminderLoadTimer(const sptr<MiscServices::TimeServiceClient> timer)
{
    auto sharedTimerInfo = std::make_shared<ReminderTimerInfo>();
    sharedTimerInfo->SetRepeat(true);
    sharedTimerInfo->SetInterval(NEXT_LOAD_TIME);
    uint8_t timerTypeWakeup = static_cast<uint8_t>(sharedTimerInfo->TIMER_TYPE_WAKEUP);
    uint8_t timerTypeExact = static_cast<uint8_t>(sharedTimerInfo->TIMER_TYPE_EXACT);
    int32_t timerType = static_cast<int32_t>(timerTypeWakeup | timerTypeExact);
    sharedTimerInfo->SetType(timerType);

    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);

    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetAction(ReminderRequest::REMINDER_EVENT_LOAD_REMINDER);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags, wants, nullptr);

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, 0);
    IPCSkeleton::SetCallingIdentity(identity);

    sharedTimerInfo->SetWantAgent(wantAgent);
    return timer->CreateTimer(sharedTimerInfo);
}

bool ReminderDataManager::CheckUpdateConditions(const sptr<ReminderRequest> &reminder,
    const ReminderRequest::ActionButtonType &actionButtonType,
    const std::map<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo> &actionButtonMap)
{
    if (!reminder->IsSystemApp()) {
        ANSR_LOGI("UpdateAppDatabase faild, is not SystemApp");
        return false;
    }
    if (actionButtonType == ReminderRequest::ActionButtonType::INVALID) {
        ANSR_LOGI("actionButtonType is NVALID");
        return false;
    }
    if (!actionButtonMap.count(actionButtonType)) {
        ANSR_LOGI("actionButtonType does not exist");
        return false;
    }
    if (actionButtonMap.at(actionButtonType).dataShareUpdate == nullptr) {
        ANSR_LOGI("dataShareUpdate is null");
        return false;
    }
    if (actionButtonMap.at(actionButtonType).dataShareUpdate->uri == "" ||
        actionButtonMap.at(actionButtonType).dataShareUpdate->equalTo == "" ||
        actionButtonMap.at(actionButtonType).dataShareUpdate->valuesBucket == "") {
        ANSR_LOGI("datashare parameter is invalid");
        return false;
    }
    return true;
}

void ReminderDataManager::UpdateAppDatabase(const sptr<ReminderRequest> &reminder,
    const ReminderRequest::ActionButtonType &actionButtonType)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    auto actionButtonMap = reminder->GetActionButtons();
    if (!CheckUpdateConditions(reminder, actionButtonType, actionButtonMap)) {
        return;
    }
    // init default dstBundleName
    std::string dstBundleName = reminder->GetBundleName();
    GenDstBundleName(dstBundleName, actionButtonMap.at(actionButtonType).dataShareUpdate->uri);

    DataShare::CreateOptions options;
    options.enabled_ = true;
    auto userID = reminder->GetUserId();
    auto tokenID = IPCSkeleton::GetSelfTokenID();
    std::string uriStr = actionButtonMap.at(actionButtonType).dataShareUpdate->uri + "?user=" + std::to_string(userID) +
        "&srcToken=" + std::to_string(tokenID) + "&dstBundleName=" + dstBundleName;

    // create datashareHelper
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = DataShare::DataShareHelper::Creator(uriStr, options);
    if (dataShareHelper == nullptr) {
        ANSR_LOGE("create datashareHelper failed");
        return;
    }
    // gen uri equalTo valuesBucket
    Uri uri(uriStr);

    DataShare::DataSharePredicates predicates;
    std::vector<std::string> equalToVector = ReminderRequest::StringSplit(
        actionButtonMap.at(actionButtonType).dataShareUpdate->equalTo, ReminderRequest::SEP_BUTTON_VALUE_TYPE);
    GenPredicates(predicates, equalToVector);

    DataShare::DataShareValuesBucket valuesBucket;
    std::vector<std::string> valuesBucketVector = ReminderRequest::StringSplit(
        actionButtonMap.at(actionButtonType).dataShareUpdate->valuesBucket, ReminderRequest::SEP_BUTTON_VALUE_TYPE);
    GenValuesBucket(valuesBucket, valuesBucketVector);

    // update app store
    int retVal = dataShareHelper->Update(uri, predicates, valuesBucket);
    if (retVal > 0) {
        // update success
        ANSR_LOGI("update app store success retval:%{public}d", retVal);
    }
}

void ReminderDataManager::GenPredicates(DataShare::DataSharePredicates &predicates,
    const std::vector<std::string> &equalToVector)
{
    // predicates
    for (auto &it : equalToVector) {
        std::vector<std::string> temp = ReminderRequest::StringSplit(it, ReminderRequest::SEP_BUTTON_VALUE);
        if (temp.size() <= INDEX_VALUE) {
            continue;
        }
        if (temp[INDEX_TYPE] == "string") {
            predicates.EqualTo(temp[INDEX_KEY], temp[INDEX_VALUE]);
        } else if (temp[INDEX_TYPE] == "double") {
            predicates.EqualTo(temp[INDEX_KEY], ReminderRequest::StringToDouble(temp[INDEX_VALUE]));
        } else if (temp[INDEX_TYPE] == "bool") {
            bool valueBool = false;
            if (temp[INDEX_VALUE] == "1" || temp[INDEX_VALUE] == "true" || temp[INDEX_VALUE] == "True") {
                valueBool = true;
            }
            predicates.EqualTo(temp[INDEX_KEY], valueBool);
        }
    }
}

void ReminderDataManager::GenValuesBucket(DataShare::DataShareValuesBucket & valuesBucket,
    const std::vector<std::string> &valuesBucketVector)
{
    // valuesBucket
    for (auto &it : valuesBucketVector) {
        std::vector<std::string> temp = ReminderRequest::StringSplit(it, ReminderRequest::SEP_BUTTON_VALUE);
        if (temp.size() <= INDEX_VALUE) {
            continue;
        }
        if (temp[INDEX_TYPE] == "string") {
            valuesBucket.Put(temp[INDEX_KEY], temp[INDEX_VALUE]);
        } else if (temp[INDEX_TYPE] == "double") {
            valuesBucket.Put(temp[INDEX_KEY], ReminderRequest::StringToDouble(temp[INDEX_VALUE]));
        } else if (temp[INDEX_TYPE] == "bool") {
            bool valueBool = false;
            if (temp[INDEX_VALUE] == "1" || temp[INDEX_VALUE] == "true") {
                valueBool = true;
            }
            valuesBucket.Put(temp[INDEX_KEY], valueBool);
        } else if (temp[INDEX_TYPE] == "null") {
            valuesBucket.Put(temp[INDEX_KEY]);
        } else if (temp[INDEX_TYPE] == "vector") {
            std::vector<std::string> arr = ReminderRequest::StringSplit(temp[INDEX_VALUE],
                ReminderRequest::SEP_BUTTON_VALUE_BLOB);
            std::vector<uint8_t> value;
            for (auto &num : arr) {
                value.emplace_back(static_cast<uint8_t>(std::atoi(num.c_str())));
            }
            valuesBucket.Put(temp[INDEX_KEY], value);
        }
    }
}

void ReminderDataManager::GenDstBundleName(std::string &dstBundleName, const std::string &uri) const
{
    size_t left = 0;
    size_t right = 0;
    left = uri.find("/", left);
    right = uri.find("/", left + 1);
    while (right != std::string::npos && right - left <= 1) {
        left = right + 1;
        right = uri.find("/", left);
    }
    if (left == std::string::npos) {
        return;
    }
    if (right != std::string::npos) {
        dstBundleName = uri.substr(left, right - left);
    } else {
        dstBundleName = uri.substr(left);
    }
}

void ReminderDataManager::RefreshRemindersDueToSysTimeChange(uint8_t type)
{
    if (!IsSystemReady()) {
        ANSR_LOGW("bundle service or ability service not ready.");
        return;
    }
    std::string typeInfo = type == TIME_ZONE_CHANGE ? "timeZone" : "dateTime";
    ANSR_LOGI("Refresh all reminders due to %{public}s changed by user", typeInfo.c_str());
    if (activeReminderId_ != -1) {
        ANSR_LOGD("Stop active reminder due to date/time or timeZone change");
        {
            std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
            activeReminder_->OnStop();
        }
        StopTimerLocked(TimerType::TRIGGER_TIMER);
    }
    LoadReminderFromDb();
    std::vector<sptr<ReminderRequest>> showImmediately;
    std::vector<sptr<ReminderRequest>> extensionReminders;
    RefreshRemindersLocked(type, showImmediately, extensionReminders);
    HandleImmediatelyShow(showImmediately, true);
    HandleExtensionReminder(extensionReminders, REISSUE_CALLBACK);
    StartRecentReminder();
}

void ReminderDataManager::TerminateAlerting(const OHOS::EventFwk::Want &want)
{
    int32_t reminderId = static_cast<int32_t>(want.GetIntParam(ReminderRequest::PARAM_REMINDER_ID, -1));
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGE("Invalid reminder id: %{public}d", reminderId);
        return;
    }
    TerminateAlerting(reminder, "timeOut");
}

void ReminderDataManager::TerminateAlerting(const uint16_t waitInSecond, const sptr<ReminderRequest> &reminder)
{
    sleep(waitInSecond);
    TerminateAlerting(reminder, "waitInMillis");
}

void ReminderDataManager::TerminateAlerting(const sptr<ReminderRequest> &reminder, const std::string &reason)
{
    if (reminder == nullptr) {
        ANSR_LOGE("TerminateAlerting illegal.");
        return;
    }
    ANSR_LOGI("Terminate the alerting reminder, %{public}s, called by %{public}s",
        reminder->Dump().c_str(), reason.c_str());
    StopAlertingReminder(reminder);

    if (!reminder->OnTerminate()) {
        return;
    }
    int32_t reminderId = reminder->GetReminderId();
    int32_t uid = reminder->GetUid();
    ANSR_LOGD("publish(update) notification.(reminderId=%{public}d)", reminder->GetReminderId());
    NotificationRequest notificationRequest(reminder->GetNotificationId());
    reminder->UpdateNotificationRequest(notificationRequest, false);
    IN_PROCESS_CALL_WITHOUT_RET(NotificationHelper::PublishNotification(
        ReminderRequest::NOTIFICATION_LABEL, notificationRequest));
    store_->UpdateOrInsert(reminder);
}

void ReminderDataManager::UpdateAndSaveReminderLocked(
    const sptr<ReminderRequest> &reminder)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    reminder->InitReminderId();

    if (reminder->GetTriggerTimeInMilli() == ReminderRequest::INVALID_LONG_LONG_VALUE) {
        ANSR_LOGW("now publish reminder is expired. reminder is =%{public}s", reminder->Dump().c_str());
        reminder->SetExpired(true);
    }
    reminderVector_.push_back(reminder);
    totalCount_++;
    store_->UpdateOrInsert(reminder);
}

bool ReminderDataManager::ShouldAlert(const sptr<ReminderRequest> &reminder) const
{
    if (reminder == nullptr) {
        return false;
    }
    int32_t reminderId = reminder->GetReminderId();
    int32_t userId = -1;
    ReminderOsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(reminder->GetUid(), userId);
    if (currentUserId_ != userId) {
        ANSR_LOGD("The reminder (reminderId=%{public}d) is silent for not in active user, " \
            "current user id: %{private}d, reminder user id: %{private}d", reminderId, currentUserId_, userId);
        return false;
    }

    NotificationDoNotDisturbDate date;
    ErrCode errCode = IN_PROCESS_CALL(NotificationHelper::GetDoNotDisturbDate(date));
    if (errCode != ERR_OK) {
        ANSR_LOGE("The reminder (reminderId=%{public}d) is silent for get disturbDate error", reminderId);
        return true;
    }
    if (date.GetDoNotDisturbType() == NotificationConstant::DoNotDisturbType::NONE) {
        return true;
    }
    NotificationBundleOption bundleOption(reminder->GetBundleName(), reminder->GetUid());
    std::vector<sptr<NotificationSlot>> slots;
    errCode = IN_PROCESS_CALL(NotificationHelper::GetNotificationSlotsForBundle(bundleOption, slots));
    if (errCode != ERR_OK) {
        ANSR_LOGE("The reminder (reminderId=%{public}d) is silent for get slots error", reminderId);
        return false;
    }
    for (auto slot : slots) {
        if (slot->GetType() != reminder->GetSlotType()) {
            continue;
        }
        if (slot->IsEnableBypassDnd()) {
            ANSR_LOGD("Not silent for enable by pass Dnd, reminderId=%{public}d", reminderId);
            return true;
        }
    }
    ANSR_LOGD("The reminder (reminderId=%{public}d) is silent for Dnd", reminderId);
    return false;
}

void ReminderDataManager::ShowActiveReminder(const EventFwk::Want &want)
{
    int32_t reminderId = static_cast<int32_t>(want.GetIntParam(ReminderRequest::PARAM_REMINDER_ID, -1));
    ANSR_LOGI("Begin to show reminder(reminderId=%{public}d)", reminderId);
    if (reminderId == activeReminderId_) {
        ResetStates(TimerType::TRIGGER_TIMER);
    }
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGW("Invalid reminder id: %{public}d", reminderId);
        return;
    }
    if (HandleSysTimeChange(reminder)) {
        return;
    }
    std::vector<sptr<ReminderRequest>> extensionReminders;
    ShowActiveReminderExtendLocked(reminder, extensionReminders);
    HandleExtensionReminder(extensionReminders, NORMAL_CALLBACK);
    StartRecentReminder();
}

bool ReminderDataManager::HandleSysTimeChange(const sptr<ReminderRequest> reminder) const
{
    if (reminder->CanShow()) {
        return false;
    } else {
        ANSR_LOGI("handleSystimeChange, no need to show reminder again.");
        return true;
    }
}

void ReminderDataManager::SetActiveReminder(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        // activeReminder_ should not be set with null as it point to actual object.
        activeReminderId_ = -1;
    } else {
        activeReminderId_ = reminder->GetReminderId();
        std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
        activeReminder_ = reminder;
    }
    ANSR_LOGD("Set activeReminderId=%{public}d", activeReminderId_.load());
}

void ReminderDataManager::SetAlertingReminder(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        // alertingReminder_ should not be set with null as it point to actual object.
        alertingReminderId_ = -1;
    } else {
        alertingReminderId_ = reminder->GetReminderId();
        alertingReminder_ = reminder;
    }
    ANSR_LOGD("Set alertingReminderId=%{public}d", alertingReminderId_.load());
}

void ReminderDataManager::ShowActiveReminderExtendLocked(sptr<ReminderRequest>& reminder,
    std::vector<sptr<ReminderRequest>>& extensionReminders)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    uint64_t triggerTime = reminder->GetTriggerTimeInMilli();
    bool isAlerting = false;
    sptr<ReminderRequest> playSoundReminder = nullptr;
    std::unordered_map<std::string, int32_t> limits;
    int32_t totalCount = 0;
    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        if ((*it)->IsExpired()) {
            continue;
        }
        uint64_t tempTriggerTime = (*it)->GetTriggerTimeInMilli();
        if (tempTriggerTime < triggerTime) {
            ANSR_LOGD("this reminder triggerTime is less than target triggerTime.");
            continue;
        }
        if (tempTriggerTime - triggerTime > ReminderRequest::SAME_TIME_DISTINGUISH_MILLISECONDS) {
            continue;
        }
        if (!(*it)->IsNeedNotification()) {
            continue;
        }
        extensionReminders.push_back((*it));
        if ((*it)->CheckExcludeDate()) {
            ANSR_LOGI("reminder[%{public}d] trigger time is in exclude date", (*it)->GetReminderId());
            continue;
        }
        if (!CheckShowLimit(limits, totalCount, (*it))) {
            (*it)->OnShow(false, false, false);
            store_->UpdateOrInsert((*it));
            continue;
        }
        if (((*it)->GetRingDuration() > 0) && !isAlerting) {
            playSoundReminder = (*it);
            isAlerting = true;
        } else {
            ShowReminder((*it), false, false, false, false);
        }
    }
    if (playSoundReminder != nullptr) {
        ShowReminder(playSoundReminder, true, false, false, true);
    }
}

bool ReminderDataManager::StartExtensionAbility(const sptr<ReminderRequest> &reminder, const int8_t type)
{
    ANSR_LOGD("StartExtensionAbility");
    if (reminder->GetReminderType() == ReminderRequest::ReminderType::CALENDAR) {
        ReminderRequestCalendar* calendar = static_cast<ReminderRequestCalendar*>(reminder.GetRefPtr());
        std::shared_ptr<ReminderRequest::WantAgentInfo> wantInfo = calendar->GetRRuleWantAgentInfo();
        if (wantInfo != nullptr && wantInfo->pkgName.size() != 0 && wantInfo->abilityName.size() != 0) {
            AAFwk::Want want;
            want.SetElementName(wantInfo->pkgName, wantInfo->abilityName);
            want.SetParam(ReminderRequest::PARAM_REMINDER_ID, reminder->GetReminderId());
            want.SetParam("PULL_TYPE", type);
            int32_t result = IN_PROCESS_CALL(
                AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr));
            if (result != ERR_OK) {
                ANSR_LOGE("StartExtensionAbility failed[%{public}d]", result);
                return false;
            }
        }
    }
    return true;
}

void ReminderDataManager::AsyncStartExtensionAbility(const sptr<ReminderRequest> &reminder, int32_t times,
    const int8_t type)
{
    auto manager = ReminderDataManager::GetInstance();
    if (manager == nullptr) {
        ANSR_LOGW("ReminderDataManager is nullptr.");
        return;
    }
    if (!manager->IsSystemReady()) {
        ANSR_LOGW("bundle service or ability service not ready.");
        return;
    }
    if (!reminder->IsSystemApp()) {
        ANSR_LOGI("Start extension ability failed, is not system app");
        return;
    }
    times--;
    bool ret = ReminderDataManager::StartExtensionAbility(reminder, type);
    if (!ret && times > 0 && serviceQueue_ != nullptr) {
        ANSR_LOGD("StartExtensionAbilty failed, reminder times: %{public}d", times);
        ffrt::task_attr taskAttr;
        taskAttr.delay(CONNECT_EXTENSION_INTERVAL);
        auto callback = [reminder, times, type]() {
            ReminderDataManager::AsyncStartExtensionAbility(reminder, times, type);
        };
        serviceQueue_->submit(callback, taskAttr);
    }
}

void ReminderDataManager::ShowReminder(const sptr<ReminderRequest> &reminder, const bool &isNeedToPlaySound,
    const bool &isNeedToStartNext, const bool &isSysTimeChanged, const bool &needScheduleTimeout)
{
    ANSR_LOGD("Show the reminder(Play sound: %{public}d), %{public}s",
        static_cast<int32_t>(isNeedToPlaySound), reminder->Dump().c_str());
    int32_t reminderId = reminder->GetReminderId();
    if (!IsAllowedNotify(reminder)) {
        ANSR_LOGE("Not allow to notify.");
        reminder->OnShow(false, isSysTimeChanged, false);
        store_->UpdateOrInsert(reminder);
        return;
    }
    ReportSysEvent(reminder);
    bool toPlaySound = isNeedToPlaySound && ShouldAlert(reminder) ? true : false;
    reminder->OnShow(toPlaySound, isSysTimeChanged, true);
    AddToShowedReminders(reminder);
    NotificationRequest notificationRequest(reminder->GetNotificationId());
    reminder->UpdateNotificationRequest(notificationRequest, false);
    if (alertingReminderId_ != -1) {
        TerminateAlerting(alertingReminder_, "PlaySoundAndVibration");
    }
    ErrCode errCode = IN_PROCESS_CALL(NotificationHelper::PublishNotification(ReminderRequest::NOTIFICATION_LABEL,
        notificationRequest));
    if (errCode != ERR_OK) {
        reminder->OnShowFail();
        RemoveFromShowedReminders(reminder);
    } else {
        if (toPlaySound) {
            PlaySoundAndVibration(reminder);  // play sound and vibration
            if (needScheduleTimeout) {
                StartTimer(reminder, TimerType::ALERTING_TIMER);
            } else {
                TerminateAlerting(1, reminder);
            }
        }
        HandleSameNotificationIdShowing(reminder);
    }
    store_->UpdateOrInsert(reminder);

    if (isNeedToStartNext) {
        StartRecentReminder();
    }
}

void ReminderDataManager::SnoozeReminder(const OHOS::EventFwk::Want &want)
{
    int32_t reminderId = static_cast<int32_t>(want.GetIntParam(ReminderRequest::PARAM_REMINDER_ID, -1));
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGW("Invalid reminder id: %{public}d", reminderId);
        return;
    }
    SnoozeReminderImpl(reminder);
    UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::SNOOZE);
    CheckNeedNotifyStatus(reminder, ReminderRequest::ActionButtonType::SNOOZE);
}

void ReminderDataManager::SnoozeReminderImpl(sptr<ReminderRequest> &reminder)
{
    ANSR_LOGI("Snooze the reminder request, %{public}s", reminder->Dump().c_str());
    int32_t reminderId = reminder->GetReminderId();
    if (activeReminderId_ == reminderId) {
        ANSR_LOGD("Cancel active reminder, id=%{public}d", activeReminderId_.load());
        {
            std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
            activeReminder_->OnStop();
        }
        StopTimerLocked(TimerType::TRIGGER_TIMER);
    }

    // 1) Snooze the reminder by manual
    if (alertingReminderId_ == reminder->GetReminderId()) {
        StopSoundAndVibrationLocked(reminder);
        StopTimerLocked(TimerType::ALERTING_TIMER);
    }
    reminder->OnSnooze();
    store_->UpdateOrInsert(reminder);

    // 2) Show the notification dialog in the systemUI

    ANSR_LOGD("publish(update) notification.(reminderId=%{public}d)", reminder->GetReminderId());
    NotificationRequest notificationRequest(reminder->GetNotificationId());
    reminder->UpdateNotificationRequest(notificationRequest, true);
    IN_PROCESS_CALL_WITHOUT_RET(NotificationHelper::PublishNotification(
        ReminderRequest::NOTIFICATION_LABEL, notificationRequest));
    StartRecentReminder();
}

void ReminderDataManager::StartRecentReminder()
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    sptr<ReminderRequest> reminder = GetRecentReminder();
    if (reminder == nullptr) {
        ANSR_LOGI("No reminder need to start");
        SetActiveReminder(reminder);
        return;
    }
    if (activeReminderId_ == reminder->GetReminderId()) {
        ANSR_LOGI("Recent reminder has already run, no need to start again.");
        return;
    }
    if (activeReminderId_ != -1) {
        {
            std::lock_guard<std::mutex> locker(ReminderDataManager::ACTIVE_MUTEX);
            activeReminder_->OnStop();
            store_->UpdateOrInsert(activeReminder_);
        }
        StopTimerLocked(TimerType::TRIGGER_TIMER);
    }
    ANSR_LOGI("Start recent reminder");
    StartTimerLocked(reminder, TimerType::TRIGGER_TIMER);
    reminder->OnStart();
    store_->UpdateOrInsert(reminder);
}

void ReminderDataManager::StopAlertingReminder(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        ANSR_LOGE("StopAlertingReminder illegal.");
        return;
    }
    if ((alertingReminderId_ == -1) || (reminder->GetReminderId() != alertingReminderId_)) {
        ANSR_LOGE("StopAlertingReminder is illegal.");
        return;
    }
    StopSoundAndVibration(alertingReminder_);
    StopTimer(TimerType::ALERTING_TIMER);
}

std::string ReminderDataManager::Dump() const
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    std::map<std::string, std::vector<sptr<ReminderRequest>>> bundleNameMap;
    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        if ((*it)->IsExpired()) {
            continue;
        }
        std::string bundleName = (*it)->GetBundleName();
        auto val = bundleNameMap.find(bundleName);
        if (val == bundleNameMap.end()) {
            std::vector<sptr<ReminderRequest>> reminders;
            reminders.push_back(*it);
            bundleNameMap.insert(std::pair<std::string, std::vector<sptr<ReminderRequest>>>(bundleName, reminders));
        } else {
            val->second.push_back(*it);
        }
    }

    std::string allReminders = "";
    for (auto it = bundleNameMap.begin(); it != bundleNameMap.end(); ++it) {
        std::string bundleName = it->first;
        std::vector<sptr<ReminderRequest>> reminders = it->second;
        sort(reminders.begin(), reminders.end(), cmp);
        std::string oneBundleReminders = bundleName + ":{\n";
        oneBundleReminders += "    totalCount:" + std::to_string(reminders.size()) + ",\n";
        oneBundleReminders += "    reminders:{\n";
        for (auto vit = reminders.begin(); vit != reminders.end(); ++vit) {
            oneBundleReminders += "        [\n";
            std::string reminderInfo = (*vit)->Dump();
            oneBundleReminders += "            " + reminderInfo + "\n";
            oneBundleReminders += "        ],\n";
        }
        oneBundleReminders += "    },\n";
        oneBundleReminders += "},\n";
        allReminders += oneBundleReminders;
    }

    return "ReminderDataManager{ totalCount:" + std::to_string(totalCount_) + ",\n" +
           "timerId:" + std::to_string(timerId_) + ",\n" +
           "activeReminderId:" + std::to_string(activeReminderId_) + ",\n" +
           allReminders + "}";
}

sptr<ReminderRequest> ReminderDataManager::GetRecentReminder()
{
    sort(reminderVector_.begin(), reminderVector_.end(), cmp);
    for (auto it = reminderVector_.begin(); it != reminderVector_.end();) {
        if (!(*it)->IsExpired()) {
            time_t now;
            (void)time(&now);  // unit is seconds.
            if (now < 0
                || ReminderRequest::GetDurationSinceEpochInMilli(now) > (*it)->GetTriggerTimeInMilli()) {
                it++;
                continue;
            }
            ANSR_LOGI("GetRecentReminder: %{public}s", (*it)->Dump().c_str());
            return *it;
        }
        if (!(*it)->CanRemove()) {
            ANSR_LOGD("Reminder has been expired: %{public}s", (*it)->Dump().c_str());
            it++;
            continue;
        }
        int32_t reminderId = (*it)->GetReminderId();
        ANSR_LOGD("Containers(vector) remove. reminderId=%{public}d", reminderId);
        it = reminderVector_.erase(it);
        totalCount_--;
        store_->Delete(reminderId);
    }
    return nullptr;
}

void ReminderDataManager::HandleImmediatelyShow(
    std::vector<sptr<ReminderRequest>> &showImmediately, bool isSysTimeChanged)
{
    bool isAlerting = false;
    std::unordered_map<std::string, int32_t> limits;
    int32_t totalCount = 0;
    for (auto it = showImmediately.begin(); it != showImmediately.end(); ++it) {
        if ((*it)->IsShowing()) {
            continue;
        }
        if (!CheckShowLimit(limits, totalCount, (*it))) {
            std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
            (*it)->OnShow(false, isSysTimeChanged, false);
            store_->UpdateOrInsert((*it));
            continue;
        }
        if (((*it)->GetRingDuration() > 0) && !isAlerting) {
            std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
            ShowReminder((*it), true, false, isSysTimeChanged, true);
            isAlerting = true;
        } else {
            std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
            ShowReminder((*it), false, false, isSysTimeChanged, false);
        }
    }
}

void ReminderDataManager::HandleExtensionReminder(std::vector<sptr<ReminderRequest>>& extensionReminders,
    const int8_t type)
{
    for (auto& reminder : extensionReminders) {
        ReminderDataManager::AsyncStartExtensionAbility(reminder, CONNECT_EXTENSION_MAX_RETRY_TIMES, type);
    }
}

sptr<ReminderRequest> ReminderDataManager::HandleRefreshReminder(const uint8_t &type, sptr<ReminderRequest> &reminder)
{
    reminder->SetReminderTimeInMilli(ReminderRequest::INVALID_LONG_LONG_VALUE);
    uint64_t triggerTimeBefore = reminder->GetTriggerTimeInMilli();
    bool needShowImmediately = false;
    if (type == TIME_ZONE_CHANGE) {
        needShowImmediately = reminder->OnTimeZoneChange();
    }
    if (type == DATE_TIME_CHANGE) {
        needShowImmediately = reminder->OnDateTimeChange();
    }
    if (!needShowImmediately) {
        uint64_t triggerTimeAfter = reminder->GetTriggerTimeInMilli();
        if (triggerTimeBefore != triggerTimeAfter || reminder->GetReminderId() == alertingReminderId_) {
            CloseReminder(reminder, true);
        }
        store_->UpdateOrInsert(reminder);
        return nullptr;
    }
    store_->UpdateOrInsert(reminder);
    return reminder;
}

void ReminderDataManager::HandleSameNotificationIdShowing(const sptr<ReminderRequest> reminder)
{
    // not add ReminderDataManager::MUTEX, as ShowActiveReminderExtendLocked has locked
    int32_t notificationId = reminder->GetNotificationId();
    ANSR_LOGD("HandleSameNotificationIdShowing notificationId=%{public}d", notificationId);
    int32_t curReminderId = reminder->GetReminderId();

    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        int32_t tmpId = (*it)->GetReminderId();
        if (tmpId == curReminderId) {
            continue;
        }
        if (!(*it)->IsShowing()) {
            continue;
        }
        if (notificationId == (*it)->GetNotificationId() && IsBelongToSameApp((*it)->GetUid(), reminder->GetUid())) {
            if ((*it)->IsAlerting()) {
                StopAlertingReminder(*it);
            }
            (*it)->OnSameNotificationIdCovered();
            RemoveFromShowedReminders(*it);
            store_->UpdateOrInsert((*it));
        }
    }
}

void ReminderDataManager::Init()
{
    ANSR_LOGD("ReminderDataManager Init");
    if (IsReminderAgentReady()) {
        return;
    }
    // Register config observer for language change
    if (!RegisterConfigurationObserver()) {
        ANSR_LOGW("Register configuration observer failed.");
        return;
    }
    if (queue_ == nullptr) {
        queue_ = std::make_shared<ffrt::queue>("ReminderDataManager");
        if (queue_ == nullptr) {
            ANSR_LOGE("create ffrt queue failed!");
            return;
        }
    }
    if (store_ == nullptr) {
        store_ = std::make_shared<ReminderStore>();
    }
    if (store_->Init() != ReminderStore::STATE_OK) {
        ANSR_LOGW("Db init fail.");
        return;
    }
    InitServiceHandler();
    LoadReminderFromDb();
    InitUserId();
    std::vector<sptr<ReminderRequest>> immediatelyReminders;
    std::vector<sptr<ReminderRequest>> extensionReminders;
    CheckReminderTime(immediatelyReminders, extensionReminders);
    HandleImmediatelyShow(immediatelyReminders, false);
    HandleExtensionReminder(extensionReminders, REISSUE_CALLBACK);
    StartRecentReminder();
    StartReminderLoadTimer();
    isReminderAgentReady_ = true;
    ANSR_LOGD("ReminderAgent is ready.");
}

void ReminderDataManager::InitServiceHandler()
{
    ANSR_LOGD("InitServiceHandler started");
    if (serviceQueue_ != nullptr) {
        ANSR_LOGD("InitServiceHandler already init.");
        return;
    }
    serviceQueue_ = std::make_shared<ffrt::queue>("ReminderService");

    ANSR_LOGD("InitServiceHandler suceeded.");
}

void ReminderDataManager::CheckReminderTime(std::vector<sptr<ReminderRequest>>& immediatelyReminders,
    std::vector<sptr<ReminderRequest>>& extensionReminders)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    for (auto reminder : reminderVector_) {
        if (reminder->GetReminderType() != ReminderRequest::ReminderType::CALENDAR) {
            continue;
        }

        if (reminder->IsPullUpService()) {
            extensionReminders.push_back(reminder);
        }

        if (reminder->OnDateTimeChange()) {
            immediatelyReminders.push_back(reminder);
        }
    }
}

void ReminderDataManager::InitUserId()
{
    currentUserId_ = MAIN_USER_ID;
    ReminderOsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(currentUserId_);
}

bool ReminderDataManager::RegisterConfigurationObserver()
{
    if (configChangeObserver_ != nullptr) {
        return true;
    }

    auto appMgrClient = std::make_shared<AppExecFwk::AppMgrClient>();
    configChangeObserver_ = sptr<AppExecFwk::IConfigurationObserver>(
        new (std::nothrow) ReminderConfigChangeObserver());
    if (appMgrClient->RegisterConfigurationObserver(configChangeObserver_) != ERR_OK) {
        ANSR_LOGE("Register configuration observer failed.");
        return false;
    }
    return true;
}

void ReminderDataManager::GetImmediatelyShowRemindersLocked(std::vector<sptr<ReminderRequest>> &reminders) const
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    for (auto reminderSptr : reminderVector_) {
        if (!(reminderSptr->ShouldShowImmediately())) {
            break;
        }
        if (reminderSptr->GetReminderType() != ReminderRequest::ReminderType::TIMER) {
            reminderSptr->SetSnoozeTimesDynamic(0);
        }
        reminders.push_back(reminderSptr);
    }
}

bool ReminderDataManager::IsAllowedNotify(const sptr<ReminderRequest> &reminder) const
{
    if (reminder == nullptr) {
        return false;
    }
    bool isAllowed = false;
    NotificationBundleOption bundleOption(reminder->GetBundleName(), reminder->GetUid());
    ErrCode errCode = IN_PROCESS_CALL(NotificationHelper::IsAllowedNotify(bundleOption, isAllowed));
    if (errCode != ERR_OK) {
        ANSR_LOGE("Failed to call IsAllowedNotify, errCode=%{public}d", errCode);
        return false;
    }
    return isAllowed;
}

bool ReminderDataManager::IsReminderAgentReady() const
{
    return isReminderAgentReady_;
}

bool ReminderDataManager::CheckIsSameApp(const sptr<ReminderRequest> &reminder,
    const int32_t callingUid) const
{
    std::string bundleName = reminder->GetCreatorBundleName();
    int32_t uid = reminder->GetCreatorUid();
    if (uid == -1) {
        uid = ReminderBundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, reminder->GetUserId());
    }
    return uid == callingUid;
}

bool ReminderDataManager::IsBelongToSameApp(const int32_t uidSrc,
    const int32_t uidTar) const
{
    bool result = uidSrc == uidTar;
    int32_t userIdSrc = -1;
    ReminderOsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uidSrc, userIdSrc);
    int32_t userIdTar = -1;
    ReminderOsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uidTar, userIdTar);
    result = result && (userIdSrc == userIdTar);
    return result;
}

void ReminderDataManager::ReceiveLoadReminderEvent()
{
    LoadReminderFromDb();
    StartRecentReminder();
}

void ReminderDataManager::LoadReminderFromDb()
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    std::vector<sptr<ReminderRequest>> existReminders = store_->GetHalfHourReminders();
    reminderVector_ = existReminders;
    totalCount_ = static_cast<int16_t>(reminderVector_.size());
    ReminderRequest::GLOBAL_ID = store_->GetMaxId() + 1;
}

void ReminderDataManager::PlaySoundAndVibrationLocked(const sptr<ReminderRequest> &reminder)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::ALERT_MUTEX);
    PlaySoundAndVibration(reminder);
}

std::string ReminderDataManager::GetCustomRingUri(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        return "";
    }
    return reminder->GetCustomRingUri();
}

std::string ReminderDataManager::GetFullPath(const std::string& oriPath)
{
    char buf[MAX_PATH_LEN] = {0};
    char* path = GetOneCfgFile(oriPath.c_str(), buf, MAX_PATH_LEN);
    if (path == nullptr || *path == '\0') {
        ANSR_LOGE("GetOneCfgFile failed");
        return "";
    }
    std::string filePath = path;
    return filePath;
}

void ReminderDataManager::PlaySoundAndVibration(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        ANSR_LOGE("Play sound and vibration failed as reminder is null.");
        return;
    }
    if (alertingReminderId_ != -1) {
        TerminateAlerting(alertingReminder_, "PlaySoundAndVibration");
    }
    ANSR_LOGD("Play sound and vibration, reminderId=%{public}d", reminder->GetReminderId());
#ifdef PLAYER_FRAMEWORK_ENABLE
    if (soundPlayer_ == nullptr) {
        soundPlayer_ = Media::PlayerFactory::CreatePlayer();
        if (soundPlayer_ == nullptr) {
            ANSR_LOGE("Fail to creat player.");
            return;
        }
    }
    std::string customRingUri = reminder->GetCustomRingUri();
    if (customRingUri.empty()) {
        // use default ring
        std::string defaultPath;
        if (access(DEFAULT_REMINDER_SOUND_1.c_str(), F_OK) == 0) {
            defaultPath = "file:/" + DEFAULT_REMINDER_SOUND_1;
        } else {
            defaultPath = "file:/" + GetFullPath(DEFAULT_REMINDER_SOUND_2);
        }
        Uri defaultSound(defaultPath);
        soundPlayer_->SetSource(defaultSound.GetSchemeSpecificPart());
        ANSR_LOGI("Play default sound.");
    } else {
        Global::Resource::ResourceManager::RawFileDescriptor desc;
        if (GetCustomRingFileDesc(reminder, desc)) {
            soundPlayer_->SetSource(desc.fd, desc.offset, desc.length);
        }
        ANSR_LOGI("Play custom sound, reminderId:[%{public}d].", reminder->GetReminderId());
    }
    constexpr int32_t STREAM_ALARM = 4;
    constexpr int32_t DEFAULT_VALUE = 0;  // CONTENT_UNKNOWN
    Media::Format format;
    (void)format.PutIntValue(Media::PlayerKeys::CONTENT_TYPE, DEFAULT_VALUE);
    (void)format.PutIntValue(Media::PlayerKeys::STREAM_USAGE, STREAM_ALARM);
    (void)format.PutIntValue(Media::PlayerKeys::RENDERER_FLAG, DEFAULT_VALUE);
    soundPlayer_->SetParameter(format);
    soundPlayer_->SetLooping(true);
    soundPlayer_->PrepareAsync();
    soundPlayer_->Play();
#endif
    SetAlertingReminder(reminder);
}

void ReminderDataManager::StopSoundAndVibrationLocked(const sptr<ReminderRequest> &reminder)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::ALERT_MUTEX);
    StopSoundAndVibration(reminder);
}

void ReminderDataManager::StopSoundAndVibration(const sptr<ReminderRequest> &reminder)
{
    if (reminder == nullptr) {
        ANSR_LOGE("Stop sound and vibration failed as reminder is null.");
        return;
    }
    if ((alertingReminderId_ == -1) || (reminder->GetReminderId() != alertingReminderId_)) {
        ANSR_LOGE("Stop sound and vibration failed as alertingReminder is illegal, alertingReminderId_=" \
            "%{public}d, tarReminderId=%{public}d", alertingReminderId_.load(), reminder->GetReminderId());
        return;
    }
    ANSR_LOGD("Stop sound and vibration, reminderId=%{public}d", reminder->GetReminderId());
#ifdef PLAYER_FRAMEWORK_ENABLE
    if (soundPlayer_ == nullptr) {
        ANSR_LOGW("Sound player is null");
    } else {
        std::string customRingUri = reminder->GetCustomRingUri();
        if (customRingUri.empty()) {
            ANSR_LOGI("Stop default sound.");
        } else {
            CloseCustomRingFileDesc(reminder->GetReminderId(), customRingUri);
        }
        soundPlayer_->Stop();
        soundPlayer_->Release();
        soundPlayer_ = nullptr;
    }
#endif
    sptr<ReminderRequest> nullReminder = nullptr;
    SetAlertingReminder(nullReminder);
}

void ReminderDataManager::RemoveFromShowedReminders(const sptr<ReminderRequest> &reminder)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
    for (auto it = showedReminderVector_.begin(); it != showedReminderVector_.end(); ++it) {
        if ((*it)->GetReminderId() == reminder->GetReminderId()) {
            ANSR_LOGD("Containers(shownVector) remove. reminderId=%{public}d", reminder->GetReminderId());
            showedReminderVector_.erase(it);
            break;
        }
    }
}

void ReminderDataManager::RefreshRemindersLocked(uint8_t type,
    std::vector<sptr<ReminderRequest>>& immediatelyReminders, std::vector<sptr<ReminderRequest>>& extensionReminders)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
        if ((*it)->IsPullUpService()) {
            extensionReminders.push_back((*it));
        }

        sptr<ReminderRequest> reminder = HandleRefreshReminder(type, (*it));
        if (reminder != nullptr) {
            immediatelyReminders.push_back(reminder);
        }
    }
}

void ReminderDataManager::RemoveReminderLocked(const int32_t &reminderId)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
    for (auto it = reminderVector_.begin(); it != reminderVector_.end();) {
        if (reminderId == (*it)->GetReminderId()) {
            ANSR_LOGD("Containers(vector) remove. reminderId=%{public}d", reminderId);
            it = reminderVector_.erase(it);
            totalCount_--;
            store_->Delete(reminderId);
            break;
        } else {
            ++it;
        }
    }
}

void ReminderDataManager::StartTimerLocked(const sptr<ReminderRequest> &reminderRequest, TimerType type)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::TIMER_MUTEX);
    StartTimer(reminderRequest, type);
}

void ReminderDataManager::StartTimer(const sptr<ReminderRequest> &reminderRequest, TimerType type)
{
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return;
    }
    time_t now;
    (void)time(&now);  // unit is seconds.
    if (now < 0) {
        ANSR_LOGE("Get now time error");
        return;
    }
    uint64_t triggerTime = 0;
    switch (type) {
        case TimerType::TRIGGER_TIMER: {
            if (timerId_ != 0) {
                ANSR_LOGE("Trigger timer has already started.");
                break;
            }
            triggerTime = HandleTriggerTimeInner(reminderRequest, type, timer);
            break;
        }
        case TimerType::ALERTING_TIMER: {
            if (timerIdAlerting_ != 0) {
                ANSR_LOGE("Alerting time out timer has already started.");
                break;
            }
            triggerTime = HandleAlertingTimeInner(reminderRequest, type, timer, now);
            break;
        }
        default: {
            ANSR_LOGE("TimerType not support");
            break;
        }
    }
    if (triggerTime == 0) {
        ANSR_LOGW("Start timer fail");
    } else {
        ANSR_LOGD("Timing info: now:(%{public}" PRIu64 "), tar:(%{public}" PRIu64 ")",
            ReminderRequest::GetDurationSinceEpochInMilli(now), triggerTime);
    }
}

uint64_t ReminderDataManager::HandleTriggerTimeInner(const sptr<ReminderRequest> &reminderRequest, TimerType type,
    const sptr<MiscServices::TimeServiceClient> &timer)
{
    uint64_t triggerTime = 0;
    SetActiveReminder(reminderRequest);
    timerId_ = timer->CreateTimer(REMINDER_DATA_MANAGER->CreateTimerInfo(type, reminderRequest));
    triggerTime = reminderRequest->GetTriggerTimeInMilli();
    timer->StartTimer(timerId_, triggerTime);
    ANSR_LOGD("Start timing (next triggerTime), timerId=%{public}" PRIu64 "", timerId_);
    return triggerTime;
}

uint64_t ReminderDataManager::HandleAlertingTimeInner(const sptr<ReminderRequest> &reminderRequest, TimerType type,
    const sptr<MiscServices::TimeServiceClient> &timer, time_t now)
{
    uint64_t triggerTime = 0;
    triggerTime = ReminderRequest::GetDurationSinceEpochInMilli(now)
        + static_cast<uint64_t>(reminderRequest->GetRingDuration() * ReminderRequest::MILLI_SECONDS);
    timerIdAlerting_ = timer->CreateTimer(REMINDER_DATA_MANAGER->CreateTimerInfo(type, reminderRequest));
    timer->StartTimer(timerIdAlerting_, triggerTime);
    ANSR_LOGD("Start timing (alerting time out), timerId=%{public}" PRIu64 "", timerIdAlerting_.load());
    return triggerTime;
}

void ReminderDataManager::StopTimerLocked(TimerType type)
{
    std::lock_guard<std::mutex> lock(ReminderDataManager::TIMER_MUTEX);
    StopTimer(type);
}

void ReminderDataManager::StopTimer(TimerType type)
{
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Failed to stop timer due to get TimeServiceClient is null.");
        return;
    }
    uint64_t timerId = 0;
    switch (type) {
        case TimerType::TRIGGER_TIMER: {
            timerId = timerId_;
            ANSR_LOGD("Stop timing (next triggerTime)");
            break;
        }
        case TimerType::ALERTING_TIMER: {
            timerId = timerIdAlerting_;
            ANSR_LOGD("Stop timing (alerting time out)");
            break;
        }
        default: {
            ANSR_LOGE("TimerType not support");
            break;
        }
    }
    if (timerId == 0) {
        ANSR_LOGD("Timer is not running");
        return;
    }
    ANSR_LOGD("Stop timer id=%{public}" PRIu64 "", timerId);
    timer->StopTimer(timerId);
    ResetStates(type);
}

void ReminderDataManager::ResetStates(TimerType type)
{
    uint64_t timerId = 0;
    switch (type) {
        case TimerType::TRIGGER_TIMER: {
            ANSR_LOGD("ResetStates(activeReminderId, timerId(next triggerTime))");
            timerId = timerId_;
            timerId_ = 0;
            activeReminderId_ = -1;
            break;
        }
        case TimerType::ALERTING_TIMER: {
            ANSR_LOGD("ResetStates(alertingReminderId, timeId(alerting time out))");
            timerId = timerIdAlerting_;
            timerIdAlerting_ = 0;
            alertingReminderId_ = -1;
            break;
        }
        default: {
            ANSR_LOGE("TimerType not support");
            break;
        }
    }
    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANSR_LOGE("Failed to destroy timer due to get TimeServiceClient is null.");
        return;
    }
    if (timerId != 0) {
        timer->DestroyTimer(timerId);
    }
}

void ReminderDataManager::HandleCustomButtonClick(const OHOS::EventFwk::Want &want)
{
    int32_t reminderId = static_cast<int32_t>(want.GetIntParam(ReminderRequest::PARAM_REMINDER_ID, -1));
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGE("Invalid reminder id: %{public}d", reminderId);
        return;
    }
    if (!reminder->IsSystemApp()) {
        ANSR_LOGI("Custom button click, is not system app");
        return;
    }
    CloseReminder(reminder, false);
    UpdateAppDatabase(reminder, ReminderRequest::ActionButtonType::CUSTOM);
    std::string buttonPkgName = want.GetStringParam("PkgName");
    std::string buttonAbilityName = want.GetStringParam("AbilityName");

    AAFwk::Want abilityWant;
    abilityWant.SetElementName(buttonPkgName, buttonAbilityName);
    abilityWant.SetUri(reminder->GetCustomButtonUri());
    auto client = AppExecFwk::AbilityManagerClient::GetInstance();
    if (client == nullptr) {
        return;
    }
    uint32_t specifyTokenId = static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID());
    int32_t result = client->StartAbilityOnlyUIAbility(abilityWant, nullptr, specifyTokenId);
    if (result != 0) {
        ANSR_LOGE("Start ability failed, result = %{public}d", result);
        return;
    }
}

void ReminderDataManager::ClickReminder(const OHOS::EventFwk::Want &want)
{
    int32_t reminderId = static_cast<int32_t>(want.GetIntParam(ReminderRequest::PARAM_REMINDER_ID, -1));
    ANSR_LOGI("click reminder[%{public}d] start", reminderId);
    sptr<ReminderRequest> reminder = FindReminderRequestLocked(reminderId);
    if (reminder == nullptr) {
        ANSR_LOGW("Invalid reminder id: %{public}d", reminderId);
        return;
    }
    CloseReminder(reminder, true);
    StartRecentReminder();

    auto wantInfo = reminder->GetWantAgentInfo();
    if (wantInfo == nullptr || (wantInfo->pkgName.empty() && wantInfo->abilityName.empty())) {
        ANSR_LOGW("want info is nullptr or no pkg name");
        return;
    }
    AAFwk::Want abilityWant;
    AppExecFwk::ElementName element("", wantInfo->pkgName, wantInfo->abilityName);
    abilityWant.SetElement(element);
    abilityWant.SetUri(wantInfo->uri);
    abilityWant.SetParams(wantInfo->parameters);
    int32_t appIndex = ReminderBundleManagerHelper::GetInstance()->GetAppIndexByUid(reminder->GetUid());
    abilityWant.SetParam("ohos.extra.param.key.appCloneIndex", appIndex);

    auto client = AppExecFwk::AbilityManagerClient::GetInstance();
    if (client == nullptr) {
        ANSR_LOGE("start ability failed, due to ability mgr client is nullptr.");
        return;
    }
    uint32_t specifyTokenId = static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID());
    int32_t result = client->StartAbilityOnlyUIAbility(abilityWant, nullptr, specifyTokenId);
    if (result != 0) {
        ANSR_LOGE("Start ability failed, result = %{public}d", result);
    }
}

std::shared_ptr<Global::Resource::ResourceManager> ReminderDataManager::GetResourceMgr(const std::string& bundleName,
    const int32_t uid)
{
    AppExecFwk::BundleInfo bundleInfo;
    if (!ReminderBundleManagerHelper::GetInstance()->GetBundleInfo(bundleName,
        AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, uid, bundleInfo)) {
        ANSR_LOGE("GetBundleInfo[%{public}s][%{public}d] fail.", bundleName.c_str(), uid);
        return nullptr;
    }
    // obtains the resource manager
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    if (!resourceManager) {
        ANSR_LOGE("CreateResourceManager fail.");
        return nullptr;
    }
    // obtains the resource path.
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string moduleResPath = hapModuleInfo.hapPath.empty() ? hapModuleInfo.resourcePath : hapModuleInfo.hapPath;
        if (moduleResPath.empty()) {
            continue;
        }
        if (!resourceManager->AddResource(moduleResPath.c_str())) {
            ANSR_LOGW("AddResource fail.");
        }
    }
    // obtains the current system language.
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(Global::I18n::LocaleConfig::GetSystemLanguage(), status);
    resConfig->SetLocaleInfo(locale);
    resourceManager->UpdateResConfig(*resConfig);
    return resourceManager;
}

void ReminderDataManager::UpdateReminderLanguageLocked(const int32_t uid,
    const std::vector<sptr<ReminderRequest>>& reminders)
{
    // obtains the bundle info by bundle name
    if (reminders.empty()) {
        return;
    }

    std::string bundleName = reminders[0]->GetBundleName();
    // obtains the resource manager
    auto resourceMgr = GetResourceMgr(bundleName, uid);
    if (resourceMgr == nullptr) {
        ANSR_LOGE("Get reminder request[%{public}d][%{public}s] resource manager failed.",
            uid, bundleName.c_str());
        return;
    }
    // update action button title
    for (auto reminder : reminders) {
        std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
        reminder->OnLanguageChange(resourceMgr);
    }
}

void ReminderDataManager::OnLanguageChanged()
{
    ANSR_LOGI("System language config changed start.");
    std::unordered_map<int32_t, std::vector<sptr<ReminderRequest>>> reminders;
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
        for (auto it = reminderVector_.begin(); it != reminderVector_.end(); ++it) {
            reminders[(*it)->GetUid()].push_back((*it));
        }
    }
    for (auto& each : reminders) {
        UpdateReminderLanguageLocked(each.first, each.second);
    }
    std::vector<sptr<ReminderRequest>> showedReminder;
    {
        std::lock_guard<std::mutex> lock(ReminderDataManager::SHOW_MUTEX);
        showedReminder = showedReminderVector_;
    }
    for (auto it = showedReminder.begin(); it != showedReminder.end(); ++it) {
        std::lock_guard<std::mutex> lock(ReminderDataManager::MUTEX);
        ShowReminder((*it), false, false, false, false);
    }
    ANSR_LOGI("System language config changed end.");
}

void ReminderDataManager::OnRemoveAppMgr()
{
    std::lock_guard<std::mutex> lock(appMgrMutex_);
    appMgrProxy_ = nullptr;
}

bool ReminderDataManager::ConnectAppMgr()
{
    if (appMgrProxy_ != nullptr) {
        return true;
    }

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ANSR_LOGE("get SystemAbilityManager failed");
        return false;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        ANSR_LOGE("get app manager service failed");
        return false;
    }

    appMgrProxy_ = iface_cast<AppExecFwk::IAppMgr>(remoteObject);
    if (!appMgrProxy_ || !appMgrProxy_->AsObject()) {
        ANSR_LOGE("get app mgr proxy failed!");
        return false;
    }
    return true;
}

void ReminderDataManager::CheckNeedNotifyStatus(const sptr<ReminderRequest> &reminder,
    const ReminderRequest::ActionButtonType buttonType)
{
    const std::string bundleName = reminder->GetBundleName();
    if (bundleName.empty()) {
        return;
    }
    bool isRunning = false;
    {
        std::lock_guard<std::mutex> lock(appMgrMutex_);
        if (!ConnectAppMgr()) {
            return;
        }
        isRunning = appMgrProxy_->GetAppRunningStateByBundleName(bundleName);
    }
    if (!isRunning) {
        return;
    }

    int32_t userId = reminder->GetUserId();
    EventFwk::Want want;
    // common event not add COMMON_EVENT_REMINDER_STATUS_CHANGE, Temporary use of string
    want.SetAction("usual.event.REMINDER_STATUS_CHANGE");
    want.SetParam("userId", userId);
    EventFwk::CommonEventData eventData(want);

    std::string data;
    data.append(std::to_string(static_cast<int>(buttonType))).append(",");
    data.append(std::to_string(reminder->GetReminderId()));
    eventData.SetData(data);

    EventFwk::CommonEventPublishInfo info;
    info.SetBundleName(bundleName);
    if (EventFwk::CommonEventManager::PublishCommonEventAsUser(eventData, info, userId)) {
        ANSR_LOGI("notify reminder status change %{public}s", bundleName.c_str());
    }
}
int32_t ReminderDataManager::QueryActiveReminderCount()
{
    return store_->QueryActiveReminderCount();
}
}
}
