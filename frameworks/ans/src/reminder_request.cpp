/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "reminder_request.h"

#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "locale_config.h"
#include "system_ability_definition.h"
#include "want_agent_helper.h"
#include "nlohmann/json.hpp"
#include "want_params_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
const int32_t BASE_YEAR = 1900;
const int32_t SINGLE_BUTTON_INVALID = 0;
const int32_t SINGLE_BUTTON_JSONSTRING = 0;
const int32_t SINGLE_BUTTON_ONLY_ONE = 1;
const int32_t SINGLE_BUTTON_MIN_LEN = 2;
const int32_t SINGLE_BUTTON_MAX_LEN = 4;
const int32_t BUTTON_TYPE_INDEX = 0;
const int32_t BUTTON_TITLE_INDEX = 1;
const int32_t BUTTON_PKG_INDEX = 2;
const int32_t BUTTON_ABILITY_INDEX = 3;
const int32_t WANT_AGENT_URI_INDEX = 2;
const int32_t INDENT = -1;

const char* const PARAM_EXTRA_KEY = "NotificationRequest_extraInfo";
}

int32_t ReminderRequest::GLOBAL_ID = 0;
const uint64_t ReminderRequest::INVALID_LONG_LONG_VALUE = 0;
const uint16_t ReminderRequest::INVALID_U16_VALUE = 0;
const uint16_t ReminderRequest::MILLI_SECONDS = 1000;
const uint16_t ReminderRequest::SAME_TIME_DISTINGUISH_MILLISECONDS = 1000;
const uint32_t ReminderRequest::MIN_TIME_INTERVAL_IN_MILLI = 5 * 60 * 1000;
const uint8_t ReminderRequest::INVALID_U8_VALUE = 0;
const uint8_t ReminderRequest::REMINDER_STATUS_INACTIVE = 0;
const uint8_t ReminderRequest::REMINDER_STATUS_ACTIVE = 1;
const uint8_t ReminderRequest::REMINDER_STATUS_ALERTING = 2;
const uint8_t ReminderRequest::REMINDER_STATUS_SHOWING = 4;
const uint8_t ReminderRequest::REMINDER_STATUS_SNOOZE = 8;
const uint8_t ReminderRequest::TIME_HOUR_OFFSET = 12;
const std::string ReminderRequest::NOTIFICATION_LABEL = "REMINDER_AGENT";
const std::string ReminderRequest::REMINDER_EVENT_ALARM_ALERT = "ohos.event.notification.reminder.ALARM_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_CLOSE_ALERT = "ohos.event.notification.reminder.CLOSE_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_SNOOZE_ALERT = "ohos.event.notification.reminder.SNOOZE_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_CUSTOM_ALERT = "ohos.event.notification.reminder.COSTUM_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_CLICK_ALERT = "ohos.event.notification.reminder.CLICK_ALERT";
const std::string ReminderRequest::REMINDER_EVENT_ALERT_TIMEOUT = "ohos.event.notification.reminder.ALERT_TIMEOUT";
const std::string ReminderRequest::REMINDER_EVENT_REMOVE_NOTIFICATION =
    "ohos.event.notification.reminder.REMOVE_NOTIFICATION";
const std::string ReminderRequest::PARAM_REMINDER_ID = "REMINDER_ID";
const std::string ReminderRequest::SEP_BUTTON_SINGLE = "<SEP,/>";
const std::string ReminderRequest::SEP_BUTTON_MULTI = "<SEP#/>";
const std::string ReminderRequest::SEP_WANT_AGENT = "<SEP#/>";
const std::string ReminderRequest::SEP_BUTTON_VALUE_TYPE = "<SEP;/>";
const std::string ReminderRequest::SEP_BUTTON_VALUE = "<SEP:/>";
const std::string ReminderRequest::SEP_BUTTON_VALUE_BLOB = "<SEP-/>";
const uint8_t ReminderRequest::DAYS_PER_WEEK = 7;
const uint8_t ReminderRequest::MONDAY = 1;
const uint8_t ReminderRequest::SUNDAY = 7;
const uint8_t ReminderRequest::HOURS_PER_DAY = 24;
const uint16_t ReminderRequest::SECONDS_PER_HOUR = 3600;

template <typename T>
void GetJsonValue(const nlohmann::json& root, const std::string& name, T& value)
{
    using ValueType = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (std::is_same_v<std::string, ValueType>) {
        if (!root.contains(name) || !root[name].is_string()) {
            value = T();
            return;
        }
        value = root[name].get<std::string>();
        return;
    }
    value = T();
}

inline static bool IsVaildButtonType(const std::string& type)
{
    // check action button type range
    if (type.size() != 1) {
        return false;
    }
    if (type[0] >= '0' && type[0] <= '3') {
        return true;
    }
    return false;
}

ReminderRequest::ReminderRequest()
{
    InitServerObj();
}

ReminderRequest::ReminderRequest(const ReminderRequest &other)
{
    this->content_ = other.content_;
    this->expiredContent_ = other.expiredContent_;
    this->snoozeContent_ = other.snoozeContent_;
    this->displayContent_ = other.displayContent_;
    this->title_ = other.title_;
    this->isExpired_ = other.isExpired_;
    this->isSystemApp_ = other.isSystemApp_;
    this->snoozeTimes_ = other.snoozeTimes_;
    this->snoozeTimesDynamic_ = other.snoozeTimesDynamic_;
    this->state_ = other.state_;
    this->notificationId_ = other.notificationId_;
    this->reminderId_ = other.reminderId_;
    this->reminderTimeInMilli_ = other.reminderTimeInMilli_;
    this->ringDurationInMilli_ = other.ringDurationInMilli_;
    this->triggerTimeInMilli_ = other.triggerTimeInMilli_;
    this->timeIntervalInMilli_ = other.timeIntervalInMilli_;
    this->reminderType_ = other.reminderType_;
    this->slotType_ = other.slotType_;
    this->snoozeSlotType_ = other.snoozeSlotType_;
    this->notificationRequest_ = other.notificationRequest_;
    this->wantAgentInfo_ = other.wantAgentInfo_;
    this->maxScreenWantAgentInfo_ = other.maxScreenWantAgentInfo_;
    this->actionButtonMap_ = other.actionButtonMap_;
    this->tapDismissed_= other.tapDismissed_;
    this->autoDeletedTime_ = other.autoDeletedTime_;
    this->customButtonUri_ = other.customButtonUri_;
    this->groupId_ = other.groupId_;
    this->customRingUri_ = other.customRingUri_;
    this->creatorBundleName_ = other.creatorBundleName_;
}

ReminderRequest::ReminderRequest(int32_t reminderId)
{
    reminderId_ = reminderId;
    InitServerObj();
}

ReminderRequest::ReminderRequest(ReminderType reminderType)
{
    reminderType_ = reminderType;
    InitServerObj();
}

bool ReminderRequest::CanRemove() const
{
    if ((state_ & (REMINDER_STATUS_SHOWING | REMINDER_STATUS_ALERTING | REMINDER_STATUS_ACTIVE)) == 0) {
        return true;
    }
    return false;
}

bool ReminderRequest::CanShow() const
{
    // when system time change by user manually, and the reminde is to show immediately,
    // the show reminder just need to be triggered by ReminderDataManager#RefreshRemindersLocked(uint8_t).
    // we need to make the REMINDER_EVENT_ALARM_ALERT do nothing.
    uint64_t nowInstantMilli = GetNowInstantMilli();
    if (nowInstantMilli == 0) {
        return false;
    }
    if (nowInstantMilli < (GetReminderTimeInMilli() + MIN_TIME_INTERVAL_IN_MILLI)) {
        return false;
    }
    return true;
}

std::string ReminderRequest::Dump() const
{
    const time_t nextTriggerTime = static_cast<time_t>(triggerTimeInMilli_ / MILLI_SECONDS);
    std::string dateTimeInfo = GetTimeInfoInner(nextTriggerTime, TimeFormat::YMDHMS, true);
    return "Reminder["
           "reminderId=" + std::to_string(reminderId_) +
           ", type=" + std::to_string(static_cast<uint8_t>(reminderType_)) +
           ", state=" + GetState(state_) +
           ", nextTriggerTime=" + dateTimeInfo.c_str() +
           "]";
}

ReminderRequest& ReminderRequest::SetActionButton(const std::string &title, const ActionButtonType &type,
    const std::string &resource, const std::shared_ptr<ButtonWantAgent> &buttonWantAgent,
    const std::shared_ptr<ButtonDataShareUpdate> &buttonDataShareUpdate)
{
    if ((type != ActionButtonType::CLOSE) && (type != ActionButtonType::SNOOZE) && (type != ActionButtonType::CUSTOM)) {
        ANSR_LOGI("Button type is not support: %{public}d.", static_cast<uint8_t>(type));
        return *this;
    }
    ActionButtonInfo actionButtonInfo;
    actionButtonInfo.type = type;
    actionButtonInfo.title = title;
    actionButtonInfo.resource = resource;
    actionButtonInfo.wantAgent = buttonWantAgent;
    actionButtonInfo.dataShareUpdate = buttonDataShareUpdate;

    actionButtonMap_.insert(std::pair<ActionButtonType, ActionButtonInfo>(type, actionButtonInfo));
    return *this;
}

ReminderRequest& ReminderRequest::SetContent(const std::string &content)
{
    content_ = content;
    return *this;
}

ReminderRequest& ReminderRequest::SetExpiredContent(const std::string &expiredContent)
{
    expiredContent_ = expiredContent;
    return *this;
}

void ReminderRequest::SetExpired(bool isExpired)
{
    isExpired_ = isExpired;
}

void ReminderRequest::InitCreatorBundleName(const std::string &creatorBundleName)
{
    creatorBundleName_ = creatorBundleName;
}

void ReminderRequest::InitCreatorUid(const int32_t creatorUid)
{
    creatorUid_ = creatorUid;
}

void ReminderRequest::InitReminderId()
{
    std::lock_guard<std::mutex> lock(std::mutex);
    if (GLOBAL_ID < 0) {
        ANSR_LOGW("GLOBAL_ID overdule");
        GLOBAL_ID = 0;
    }
    reminderId_ = ++GLOBAL_ID;
    ANSR_LOGI("reminderId_=%{public}d", reminderId_);
}

void ReminderRequest::InitUserId(const int32_t &userId)
{
    userId_ = userId;
}

void ReminderRequest::InitUid(const int32_t &uid)
{
    uid_ = uid;
}

void ReminderRequest::InitBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

bool ReminderRequest::IsExpired() const
{
    return isExpired_;
}

bool ReminderRequest::IsShowing() const
{
    if ((state_ & REMINDER_STATUS_SHOWING) != 0) {
        return true;
    }
    return false;
}

void ReminderRequest::OnClose(bool updateNext)
{
    if ((state_ & REMINDER_STATUS_SHOWING) == 0) {
        ANSR_LOGE("onClose, the state of reminder is incorrect, state:%{public}s", GetState(state_).c_str());
        return;
    }
    SetState(false, REMINDER_STATUS_SHOWING | REMINDER_STATUS_SNOOZE, "onClose()");
    if ((state_ & REMINDER_STATUS_ALERTING) != 0) {
        SetState(false, REMINDER_STATUS_ALERTING, "onClose");
    }
    if (updateNext) {
        uint64_t nextTriggerTime = PreGetNextTriggerTimeIgnoreSnooze(true, false);
        if (nextTriggerTime == INVALID_LONG_LONG_VALUE) {
            isExpired_ = true;
        } else {
            SetTriggerTimeInMilli(nextTriggerTime);
            snoozeTimesDynamic_ = snoozeTimes_;
        }
    }
}

bool ReminderRequest::OnDateTimeChange()
{
    uint64_t nextTriggerTime = PreGetNextTriggerTimeIgnoreSnooze(true, false);
    return HandleSysTimeChange(triggerTimeInMilli_, nextTriggerTime);
}

bool ReminderRequest::HandleSysTimeChange(uint64_t oriTriggerTime, uint64_t optTriggerTime)
{
    if (isExpired_) {
        return false;
    }
    uint64_t now = GetNowInstantMilli();
    if (now == 0) {
        ANSR_LOGE("get now time failed.");
        return false;
    }
    if (oriTriggerTime == 0 && optTriggerTime < now) {
        ANSR_LOGW("trigger time is less than now time.");
        return false;
    }
    bool showImmediately = false;
    if (optTriggerTime != INVALID_LONG_LONG_VALUE && (optTriggerTime <= oriTriggerTime || oriTriggerTime == 0)) {
        // case1. switch to a previous time
        SetTriggerTimeInMilli(optTriggerTime);
        snoozeTimesDynamic_ = snoozeTimes_;
    } else {
        if (oriTriggerTime <= now) {
            // case2. switch to a future time, trigger time is less than now time.
            // when the reminder show immediately, trigger time will update in onShow function.
            snoozeTimesDynamic_ = 0;
            showImmediately = true;
        } else {
            // case3. switch to a future time, trigger time is larger than now time.
            showImmediately = false;
        }
    }
    return showImmediately;
}

bool ReminderRequest::HandleTimeZoneChange(
    uint64_t oldZoneTriggerTime, uint64_t newZoneTriggerTime, uint64_t optTriggerTime)
{
    if (isExpired_) {
        return false;
    }
    ANSR_LOGD("Handle timezone change, old:%{public}" PRIu64 ", new:%{public}" PRIu64 "",
        oldZoneTriggerTime, newZoneTriggerTime);
    if (oldZoneTriggerTime == newZoneTriggerTime) {
        return false;
    }
    bool showImmediately = false;
    if (optTriggerTime != INVALID_LONG_LONG_VALUE && oldZoneTriggerTime < newZoneTriggerTime) {
        // case1. timezone change to smaller
        SetTriggerTimeInMilli(optTriggerTime);
        snoozeTimesDynamic_ = snoozeTimes_;
    } else {
        // case2. timezone change to larger
        time_t now;
        (void)time(&now);  // unit is seconds.
        if (static_cast<int64_t>(now) < 0) {
            ANSR_LOGE("Get now time error");
            return false;
        }
        if (newZoneTriggerTime <= GetDurationSinceEpochInMilli(now)) {
            snoozeTimesDynamic_ = 0;
            showImmediately = true;
        } else {
            SetTriggerTimeInMilli(newZoneTriggerTime);
            showImmediately = false;
        }
    }
    return showImmediately;
}

void ReminderRequest::OnSameNotificationIdCovered()
{
    SetState(false, REMINDER_STATUS_ALERTING | REMINDER_STATUS_SHOWING | REMINDER_STATUS_SNOOZE,
        "OnSameNotificationIdCovered");
}

void ReminderRequest::OnShow(bool isPlaySoundOrVibration, bool isSysTimeChanged, bool allowToNotify)
{
    if ((state_ & (REMINDER_STATUS_ACTIVE | REMINDER_STATUS_SNOOZE)) != 0) {
        SetState(false, REMINDER_STATUS_ACTIVE | REMINDER_STATUS_SNOOZE, "onShow()");
    }
    if (isSysTimeChanged) {
        uint64_t nowInstantMilli = GetNowInstantMilli();
        if (nowInstantMilli == 0) {
            ANSR_LOGW("Onshow, get now time error");
        }
        reminderTimeInMilli_ = nowInstantMilli;
    } else {
        reminderTimeInMilli_ = triggerTimeInMilli_;
    }
    UpdateNextReminder(false);
    if (allowToNotify) {
        SetState(true, REMINDER_STATUS_SHOWING, "OnShow");
        if (isPlaySoundOrVibration) {
            SetState(true, REMINDER_STATUS_ALERTING, "OnShow");
        }
        UpdateNotificationStateForAlert();
    }
}

void ReminderRequest::OnShowFail()
{
    SetState(false, REMINDER_STATUS_SHOWING, "OnShowFailed()");
}

bool ReminderRequest::OnSnooze()
{
    if ((state_ & REMINDER_STATUS_SNOOZE) != 0) {
        ANSR_LOGW("onSnooze, the state of reminder is incorrect, state: %{public}s", (GetState(state_)).c_str());
        return false;
    }
    if ((state_ & REMINDER_STATUS_ALERTING) != 0) {
        SetState(false, REMINDER_STATUS_ALERTING, "onSnooze()");
    }
    SetSnoozeTimesDynamic(GetSnoozeTimes());
    if (!UpdateNextReminder(true)) {
        return false;
    }
    UpdateNotificationStateForSnooze();
    if (timeIntervalInMilli_ > 0) {
        SetState(true, REMINDER_STATUS_SNOOZE, "onSnooze()");
    }
    return true;
}

void ReminderRequest::OnStart()
{
    if ((state_ & REMINDER_STATUS_ACTIVE) != 0) {
        ANSR_LOGE(
            "start failed, the state of reminder is incorrect, state: %{public}s", (GetState(state_)).c_str());
        return;
    }
    if (isExpired_) {
        ANSR_LOGE("start failed, the reminder is expired");
        return;
    }
    SetState(true, REMINDER_STATUS_ACTIVE, "OnStart()");
}

void ReminderRequest::OnStop()
{
    ANSR_LOGI("Stop the previous active reminder, %{public}s", this->Dump().c_str());
    if ((state_ & REMINDER_STATUS_ACTIVE) == 0) {
        ANSR_LOGW("onStop, the state of reminder is incorrect, state: %{public}s", (GetState(state_)).c_str());
        return;
    }
    SetState(false, REMINDER_STATUS_ACTIVE, "OnStop");
}

bool ReminderRequest::OnTerminate()
{
    if ((state_ & REMINDER_STATUS_ALERTING) == 0) {
        ANSR_LOGW("onTerminate, the state of reminder is %{public}s", (GetState(state_)).c_str());
        return false;
    }
    SetState(false, REMINDER_STATUS_ALERTING, "onTerminate");
    UpdateNotificationStateForAlert();
    return true;
}

bool ReminderRequest::OnTimeZoneChange()
{
    time_t oldZoneTriggerTime = static_cast<time_t>(triggerTimeInMilli_ / MILLI_SECONDS);
    struct tm *localOriTime = localtime(&oldZoneTriggerTime);
    if (localOriTime == nullptr) {
        ANSR_LOGE("oldZoneTriggerTime is null");
        return false;
    }
    time_t newZoneTriggerTime = mktime(localOriTime);
    uint64_t nextTriggerTime = PreGetNextTriggerTimeIgnoreSnooze(true, false);
    return HandleTimeZoneChange(
        triggerTimeInMilli_, GetDurationSinceEpochInMilli(newZoneTriggerTime), nextTriggerTime);
}

void ReminderRequest::RecoverActionButtonJsonMode(const std::string &jsonString)
{
    if (!nlohmann::json::accept(jsonString)) {
        ANSR_LOGW("not a json string!");
        return;
    }
    nlohmann::json root = nlohmann::json::parse(jsonString, nullptr, false);
    if (root.is_discarded()) {
        ANSR_LOGW("parse json data failed!");
        return;
    }
    std::string type;
    GetJsonValue<std::string>(root, "type", type);
    if (!IsVaildButtonType(type)) {
        ANSR_LOGW("unkown button type!");
        return;
    }
    std::string title;
    GetJsonValue<std::string>(root, "title", title);
    std::string resource;
    GetJsonValue<std::string>(root, "resource", resource);
    auto buttonWantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
    if (root.contains("wantAgent") && !root["wantAgent"].empty()) {
        nlohmann::json wantAgent = root["wantAgent"];
        GetJsonValue<std::string>(wantAgent, "pkgName", buttonWantAgent->pkgName);
        GetJsonValue<std::string>(wantAgent, "abilityName", buttonWantAgent->abilityName);
    }
    auto buttonDataShareUpdate = std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
    if (root.contains("dataShareUpdate") && !root["dataShareUpdate"].empty()) {
        nlohmann::json dataShareUpdate = root["dataShareUpdate"];
        GetJsonValue<std::string>(dataShareUpdate, "uri", buttonDataShareUpdate->uri);
        GetJsonValue<std::string>(dataShareUpdate, "equalTo", buttonDataShareUpdate->equalTo);
        GetJsonValue<std::string>(dataShareUpdate, "valuesBucket", buttonDataShareUpdate->valuesBucket);
    }
    SetActionButton(title, ActionButtonType(std::stoi(type, nullptr)),
        resource, buttonWantAgent, buttonDataShareUpdate);
}

void ReminderRequest::DeserializeButtonInfo(const std::string& buttonInfoStr)
{
    std::vector<std::string> multiButton = StringSplit(buttonInfoStr, SEP_BUTTON_MULTI);
    for (auto button : multiButton) {
        std::vector<std::string> singleButton = StringSplit(button, SEP_BUTTON_SINGLE);
        if (singleButton.size() <= SINGLE_BUTTON_INVALID) {
            ANSR_LOGW("RecoverButton fail");
            return;
        }
        if (singleButton.size() == SINGLE_BUTTON_ONLY_ONE) {
            std::string jsonString = singleButton.at(SINGLE_BUTTON_JSONSTRING);
            RecoverActionButtonJsonMode(jsonString);
            continue;
        }
        // old method Soon to be deleted
        if (singleButton.size() < SINGLE_BUTTON_MIN_LEN) {
            ANSR_LOGW("RecoverButton fail");
            return;
        }
        auto buttonWantAgent = std::make_shared<ReminderRequest::ButtonWantAgent>();
        if (singleButton.size() == SINGLE_BUTTON_MAX_LEN) {
            buttonWantAgent->pkgName = singleButton.at(BUTTON_PKG_INDEX);
            buttonWantAgent->abilityName = singleButton.at(BUTTON_ABILITY_INDEX);
        }
        std::string resource = "";
        auto buttonDataShareUpdate = std::make_shared<ReminderRequest::ButtonDataShareUpdate>();
        SetActionButton(singleButton.at(BUTTON_TITLE_INDEX),
            ActionButtonType(std::atoi(singleButton.at(BUTTON_TYPE_INDEX).c_str())),
            resource, buttonWantAgent, buttonDataShareUpdate);
        ANSR_LOGI("RecoverButton title:%{public}s, pkgName:%{public}s, abilityName:%{public}s",
            singleButton.at(BUTTON_TITLE_INDEX).c_str(), buttonWantAgent->pkgName.c_str(),
            buttonWantAgent->abilityName.c_str());
    }
}

std::vector<std::string> ReminderRequest::StringSplit(std::string source, const std::string &split)
{
    std::vector<std::string> result;
    if (source.empty()) {
        return result;
    }
    size_t pos = 0;
    while ((pos = source.find(split)) != std::string::npos) {
        std::string token = source.substr(0, pos);
        if (!token.empty()) {
            result.push_back(token);
        }
        source.erase(0, pos + split.length());
    }
    if (!source.empty()) {
        result.push_back(source);
    }
    return result;
}

void ReminderRequest::RecoverWantAgentByJson(const std::string& wantAgentInfo, const uint8_t& type)
{
    nlohmann::json root = nlohmann::json::parse(wantAgentInfo, nullptr, false);
    if (root.is_discarded()) {
        ANSR_LOGW("parse json data failed");
        return;
    }
    if (!root.contains("pkgName") || !root["pkgName"].is_string() ||
        !root.contains("abilityName") || !root["abilityName"].is_string() ||
        !root.contains("uri") || !root["uri"].is_string() ||
        !root.contains("parameters") || !root["parameters"].is_string()) {
        return;
    }

    std::string pkgName = root.at("pkgName").get<std::string>();
    std::string abilityName = root.at("abilityName").get<std::string>();
    std::string uri = root.at("uri").get<std::string>();
    std::string parameters = root.at("parameters").get<std::string>();
    switch (type) {
        case WANT_AGENT_FLAG: {
            auto wai = std::make_shared<ReminderRequest::WantAgentInfo>();
            wai->pkgName = pkgName;
            wai->abilityName = abilityName;
            wai->uri = uri;
            wai->parameters = AAFwk::WantParamWrapper::ParseWantParams(parameters);
            SetWantAgentInfo(wai);
            break;
        }
        case MAX_WANT_AGENT_FLAG: {
            auto maxScreenWantAgentInfo = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
            maxScreenWantAgentInfo->pkgName = pkgName;
            maxScreenWantAgentInfo->abilityName = abilityName;
            SetMaxScreenWantAgentInfo(maxScreenWantAgentInfo);
            break;
        }
        default: {
            ANSR_LOGW("RecoverWantAgent type not support");
            break;
        }
    }
}

void ReminderRequest::DeserializeWantAgent(const std::string &wantAgentInfo, const uint8_t type)
{
    if (nlohmann::json::accept(wantAgentInfo)) {
        RecoverWantAgentByJson(wantAgentInfo, type);
        return;
    }
    std::vector<std::string> info = StringSplit(wantAgentInfo, ReminderRequest::SEP_WANT_AGENT);
    uint8_t minLen = 2;
    if (info.size() < minLen) {
        ANSR_LOGW("RecoverWantAgent fail");
        return;
    }
    ANSR_LOGD("pkg=%{public}s, ability=%{public}s", info.at(0).c_str(), info.at(1).c_str());
    switch (type) {
        case 0: {
            auto wai = std::make_shared<ReminderRequest::WantAgentInfo>();
            wai->pkgName = info.at(0);
            wai->abilityName = info.at(1);
            if (info.size() > minLen) {
                wai->uri = info.at(WANT_AGENT_URI_INDEX);
            }
            SetWantAgentInfo(wai);
            break;
        }
        case 1: {
            auto maxScreenWantAgentInfo = std::make_shared<ReminderRequest::MaxScreenAgentInfo>();
            maxScreenWantAgentInfo->pkgName = info.at(0);
            maxScreenWantAgentInfo->abilityName = info.at(1);
            SetMaxScreenWantAgentInfo(maxScreenWantAgentInfo);
            break;
        }
        default: {
            ANSR_LOGW("RecoverWantAgent type not support");
            break;
        }
    }
}

ReminderRequest& ReminderRequest::SetMaxScreenWantAgentInfo(
    const std::shared_ptr<MaxScreenAgentInfo> &maxScreenWantAgentInfo)
{
    maxScreenWantAgentInfo_ = maxScreenWantAgentInfo;
    return *this;
}

ReminderRequest& ReminderRequest::SetNotificationId(int32_t notificationId)
{
    notificationId_ = notificationId;
    return *this;
}

ReminderRequest& ReminderRequest::SetGroupId(const std::string &groupId)
{
    groupId_ = groupId;
    return *this;
}

ReminderRequest& ReminderRequest::SetSlotType(const NotificationConstant::SlotType &slotType)
{
    slotType_ = slotType;
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeSlotType(const NotificationConstant::SlotType &snoozeSlotType)
{
    snoozeSlotType_ = snoozeSlotType;
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeContent(const std::string &snoozeContent)
{
    snoozeContent_ = snoozeContent;
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeTimes(const uint8_t snoozeTimes)
{
    snoozeTimes_ = snoozeTimes;
    SetSnoozeTimesDynamic(snoozeTimes);
    return *this;
}

ReminderRequest& ReminderRequest::SetSnoozeTimesDynamic(const uint8_t snooziTimes)
{
    snoozeTimesDynamic_ = snooziTimes;
    return *this;
}

ReminderRequest& ReminderRequest::SetTimeInterval(const uint64_t timeIntervalInSeconds)
{
    if (timeIntervalInSeconds > (UINT64_MAX / MILLI_SECONDS)) {
        ANSR_LOGW("SetTimeInterval, replace to set (0s), for the given is out of legal range");
        timeIntervalInMilli_ = 0;
    } else {
        uint64_t timeIntervalInMilli = timeIntervalInSeconds * MILLI_SECONDS;
        if (timeIntervalInMilli > 0 && timeIntervalInMilli < MIN_TIME_INTERVAL_IN_MILLI) {
            ANSR_LOGW("SetTimeInterval, replace to set %{public}u, for the given is 0<%{public}" PRIu64 "<%{public}u",
                MIN_TIME_INTERVAL_IN_MILLI / MILLI_SECONDS, timeIntervalInSeconds,
                MIN_TIME_INTERVAL_IN_MILLI / MILLI_SECONDS);
            timeIntervalInMilli_ = MIN_TIME_INTERVAL_IN_MILLI;
        } else {
            timeIntervalInMilli_ = timeIntervalInMilli;
        }
    }
    return *this;
}

ReminderRequest& ReminderRequest::SetTitle(const std::string &title)
{
    title_ = title;
    return *this;
}

void ReminderRequest::SetTriggerTimeInMilli(uint64_t triggerTimeInMilli)
{
    triggerTimeInMilli_ = triggerTimeInMilli;
}

ReminderRequest& ReminderRequest::SetWantAgentInfo(const std::shared_ptr<WantAgentInfo> &wantAgentInfo)
{
    if (wantAgentInfo != nullptr) {
        wantAgentInfo_ = wantAgentInfo;
    }
    return *this;
}

bool ReminderRequest::ShouldShowImmediately() const
{
    uint64_t nowInstantMilli = GetNowInstantMilli();
    if (nowInstantMilli == 0) {
        return false;
    }
    if (triggerTimeInMilli_ > nowInstantMilli) {
        return false;
    }
    return true;
}

std::map<ReminderRequest::ActionButtonType, ReminderRequest::ActionButtonInfo> ReminderRequest::GetActionButtons(
    ) const
{
    return actionButtonMap_;
}

std::string ReminderRequest::GetCreatorBundleName() const
{
    return creatorBundleName_;
}

int32_t ReminderRequest::GetCreatorUid() const
{
    return creatorUid_;
}

std::string ReminderRequest::GetContent() const
{
    return content_;
}

std::string ReminderRequest::GetExpiredContent() const
{
    return expiredContent_;
}

std::shared_ptr<ReminderRequest::MaxScreenAgentInfo> ReminderRequest::GetMaxScreenWantAgentInfo() const
{
    return maxScreenWantAgentInfo_;
}

int32_t ReminderRequest::GetNotificationId() const
{
    return notificationId_;
}

std::string ReminderRequest::GetGroupId() const
{
    return groupId_;
}

sptr<NotificationRequest> ReminderRequest::GetNotificationRequest() const
{
    return notificationRequest_;
}

int32_t ReminderRequest::GetReminderId() const
{
    return reminderId_;
}

uint64_t ReminderRequest::GetReminderTimeInMilli() const
{
    return reminderTimeInMilli_;
}

void ReminderRequest::SetReminderId(int32_t reminderId)
{
    reminderId_ = reminderId;
}

void ReminderRequest::SetReminderTimeInMilli(const uint64_t reminderTimeInMilli)
{
    reminderTimeInMilli_ = reminderTimeInMilli;
}

ReminderRequest& ReminderRequest::SetRingDuration(const uint64_t ringDurationInSeconds)
{
    uint64_t ringDuration = ringDurationInSeconds * MILLI_SECONDS;
    ringDurationInMilli_ = std::min(ringDuration, MAX_RING_DURATION);
    return *this;
}

NotificationConstant::SlotType ReminderRequest::GetSlotType() const
{
    return slotType_;
}

NotificationConstant::SlotType ReminderRequest::GetSnoozeSlotType() const
{
    return snoozeSlotType_;
}

std::string ReminderRequest::GetSnoozeContent() const
{
    return snoozeContent_;
}

uint8_t ReminderRequest::GetSnoozeTimes() const
{
    return snoozeTimes_;
}

uint8_t ReminderRequest::GetSnoozeTimesDynamic() const
{
    return snoozeTimesDynamic_;
}

uint8_t ReminderRequest::GetState() const
{
    return state_;
}

uint64_t ReminderRequest::GetTimeInterval() const
{
    return timeIntervalInMilli_ / MILLI_SECONDS;
}

std::string ReminderRequest::GetTitle() const
{
    return title_;
}

uint64_t ReminderRequest::GetTriggerTimeInMilli() const
{
    return triggerTimeInMilli_;
}

int32_t ReminderRequest::GetUserId() const
{
    return userId_;
}

int32_t ReminderRequest::GetUid() const
{
    return uid_;
}

std::string ReminderRequest::GetBundleName() const
{
    return bundleName_;
}

void ReminderRequest::SetReminderType(const ReminderType type)
{
    reminderType_ = type;
}

void ReminderRequest::SetState(const uint8_t state)
{
    state_ = state;
}

void ReminderRequest::SetRepeatDaysOfWeek(const uint8_t repeatDaysOfWeek)
{
    repeatDaysOfWeek_ = repeatDaysOfWeek;
}

void ReminderRequest::SetSystemApp(bool isSystem)
{
    isSystemApp_ = isSystem;
}

bool ReminderRequest::IsSystemApp() const
{
    return isSystemApp_;
}

void ReminderRequest::SetTapDismissed(bool tapDismissed)
{
    tapDismissed_ = tapDismissed;
}

bool ReminderRequest::IsTapDismissed() const
{
    return tapDismissed_;
}

void ReminderRequest::SetAutoDeletedTime(int64_t autoDeletedTime)
{
    autoDeletedTime_ = autoDeletedTime;
}

int64_t ReminderRequest::GetAutoDeletedTime() const
{
    return autoDeletedTime_;
}

void ReminderRequest::SetCustomButtonUri(const std::string &uri)
{
    customButtonUri_ = uri;
}

std::string ReminderRequest::GetCustomButtonUri() const
{
    return customButtonUri_;
}

void ReminderRequest::SetCustomRingUri(const std::string &uri)
{
    customRingUri_ = uri;
}

std::string ReminderRequest::GetCustomRingUri() const
{
    return customRingUri_;
}

sptr<NotificationBundleOption> ReminderRequest::GetNotificationBundleOption() const
{
    return notificationOption_;
}

void ReminderRequest::SetNotificationBundleOption(const sptr<NotificationBundleOption>& option)
{
    notificationOption_ = option;
}

std::shared_ptr<ReminderRequest::WantAgentInfo> ReminderRequest::GetWantAgentInfo() const
{
    return wantAgentInfo_;
}

ReminderRequest::ReminderType ReminderRequest::GetReminderType() const
{
    return reminderType_;
}

uint16_t ReminderRequest::GetRingDuration() const
{
    return ringDurationInMilli_ / MILLI_SECONDS;
}

bool ReminderRequest::UpdateNextReminder()
{
    return false;
}

bool ReminderRequest::SetNextTriggerTime()
{
    return false;
}

void ReminderRequest::SetWantAgentStr(const std::string& wantStr)
{
    wantAgentStr_ = wantStr;
}

std::string ReminderRequest::GetWantAgentStr()
{
    return wantAgentStr_;
}

void ReminderRequest::SetMaxWantAgentStr(const std::string& maxWantStr)
{
    maxWantAgentStr_ = maxWantStr;
}

std::string ReminderRequest::GetMaxWantAgentStr()
{
    return maxWantAgentStr_;
}

void ReminderRequest::UpdateNotificationRequest(UpdateNotificationType type, std::string extra)
{
    switch (type) {
        case UpdateNotificationType::COMMON: {
            ANSR_LOGI("UpdateNotification common information");
            if (extra == "snooze") {
                UpdateNotificationCommon(true);
            } else {
                UpdateNotificationCommon(false);
            }
            break;
        }
        case UpdateNotificationType::REMOVAL_WANT_AGENT: {
            ANSR_LOGI("UpdateNotification removal_want_agent");
            AddRemovalWantAgent();
            break;
        }
        case UpdateNotificationType::WANT_AGENT: {
            ANSR_LOGI("UpdateNotification want_agent");
            AppExecFwk::ElementName wantAgent("", wantAgentInfo_->pkgName, wantAgentInfo_->abilityName);
            SetWantAgent(wantAgent);
            SetExtraInfo(wantAgentInfo_->parameters);
            break;
        }
        case UpdateNotificationType::MAX_SCREEN_WANT_AGENT: {
            ANSR_LOGI("UpdateNotification max_screen_want_agent");
            AppExecFwk::ElementName maxScreenWantAgent(
                "", maxScreenWantAgentInfo_->pkgName, maxScreenWantAgentInfo_->abilityName);
            SetMaxScreenWantAgent(maxScreenWantAgent);
            break;
        }
        case UpdateNotificationType::BUNDLE_INFO: {
            ANSR_LOGI("UpdateNotification hap information");
            UpdateNotificationBundleInfo();
            break;
        }
        case UpdateNotificationType::CONTENT: {
            break;
        }
        default:
            break;
    }
}

bool ReminderRequest::MarshallingActionButton(Parcel& parcel) const
{
    // write map
    uint64_t actionButtonMapSize = static_cast<uint64_t>(actionButtonMap_.size());
    WRITE_UINT64_RETURN_FALSE_LOG(parcel, actionButtonMapSize, "actionButtonMapSize");
    for (auto button : actionButtonMap_) {
        uint8_t buttonType = static_cast<uint8_t>(button.first);
        WRITE_UINT8_RETURN_FALSE_LOG(parcel, buttonType, "buttonType");
        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.title, "buttonTitle");
        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.resource, "buttonResource");

        if (button.second.wantAgent == nullptr) {
            ANSR_LOGE("button wantAgent is null");
            return false;
        }

        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.wantAgent->pkgName, "wantAgent's pkgName");
        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.wantAgent->abilityName, "wantAgent's abilityName");

        if (button.second.dataShareUpdate == nullptr) {
            ANSR_LOGE("button dataShareUpdate is null");
            return false;
        }
        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.dataShareUpdate->uri,
            "dataShareUpdate's uri");
        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.dataShareUpdate->equalTo,
            "dataShareUpdate's equalTo");
        WRITE_STRING_RETURN_FALSE_LOG(parcel, button.second.dataShareUpdate->valuesBucket,
            "dataShareUpdate's valuesBucket");
    }
    return true;
}

bool ReminderRequest::MarshallingWantParameters(Parcel& parcel, const AAFwk::WantParams& params) const
{
    if (params.Size() == 0) {
        if (!parcel.WriteInt32(VALUE_NULL)) {
            return false;
        }
    } else {
        if (!parcel.WriteInt32(VALUE_OBJECT)) {
            return false;
        }
        if (!parcel.WriteParcelable(&params)) {
            return false;
        }
    }
    return true;
}

bool ReminderRequest::Marshalling(Parcel &parcel) const
{
    // write string
    WRITE_STRING_RETURN_FALSE_LOG(parcel, content_, "content");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, expiredContent_, "expiredContent");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, snoozeContent_, "snoozeContent");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, title_, "title");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, wantAgentInfo_->abilityName, "wantAgentInfo's abilityName");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, wantAgentInfo_->pkgName, "wantAgentInfo's pkgName");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, wantAgentInfo_->uri, "wantAgentInfo's uri");
    if (!MarshallingWantParameters(parcel, wantAgentInfo_->parameters)) {
        ANSR_LOGE("Failed to write wantAgentInfo's parameters");
        return false;
    }
    WRITE_STRING_RETURN_FALSE_LOG(parcel, maxScreenWantAgentInfo_->abilityName, "maxScreenWantAgentInfo's abilityName");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, maxScreenWantAgentInfo_->pkgName, "maxScreenWantAgentInfo's pkgName");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, customButtonUri_, "customButtonUri");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, groupId_, "groupId");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, customRingUri_, "customRingUri");
    WRITE_STRING_RETURN_FALSE_LOG(parcel, creatorBundleName_, "creatorBundleName");

    // write bool
    WRITE_BOOL_RETURN_FALSE_LOG(parcel, isExpired_, "isExpired");
    WRITE_BOOL_RETURN_FALSE_LOG(parcel, tapDismissed_, "tapDismissed");

    // write int
    WRITE_INT64_RETURN_FALSE_LOG(parcel, autoDeletedTime_, "autoDeletedTime");
    WRITE_INT32_RETURN_FALSE_LOG(parcel, reminderId_, "reminderId");
    WRITE_INT32_RETURN_FALSE_LOG(parcel, notificationId_, "notificationId");

    WRITE_UINT64_RETURN_FALSE_LOG(parcel, triggerTimeInMilli_, "triggerTimeInMilli");
    WRITE_UINT64_RETURN_FALSE_LOG(parcel, timeIntervalInMilli_, "timeIntervalInMilli");
    WRITE_UINT64_RETURN_FALSE_LOG(parcel, ringDurationInMilli_, "ringDurationInMilli");
    WRITE_UINT64_RETURN_FALSE_LOG(parcel, reminderTimeInMilli_, "reminderTimeInMilli");
    WRITE_UINT8_RETURN_FALSE_LOG(parcel, snoozeTimes_, "snoozeTimes");
    WRITE_UINT8_RETURN_FALSE_LOG(parcel, snoozeTimesDynamic_, "snoozeTimesDynamic");
    WRITE_UINT8_RETURN_FALSE_LOG(parcel, state_, "state");

    // write enum
    uint8_t reminderType = static_cast<uint8_t>(reminderType_);
    WRITE_UINT8_RETURN_FALSE_LOG(parcel, reminderType, "reminderType");

    int32_t slotType = static_cast<int32_t>(slotType_);
    WRITE_INT32_RETURN_FALSE_LOG(parcel, slotType, "slotType");

    int32_t snoozeSlotType = static_cast<int32_t>(snoozeSlotType_);
    WRITE_INT32_RETURN_FALSE_LOG(parcel, snoozeSlotType, "snoozeSlotType");

    if (!MarshallingActionButton(parcel)) {
        return false;
    }
    return true;
}

ReminderRequest *ReminderRequest::Unmarshalling(Parcel &parcel)
{
    auto objptr = new (std::nothrow) ReminderRequest();
    if (objptr == nullptr) {
        ANSR_LOGE("Failed to create reminder due to no memory.");
        return objptr;
    }
    if (!objptr->ReadFromParcel(parcel)) {
        delete objptr;
        objptr = nullptr;
    }
    return objptr;
}

bool ReminderRequest::ReadActionButtonFromParcel(Parcel& parcel)
{
    uint64_t buttonMapSize = 0;
    READ_UINT64_RETURN_FALSE_LOG(parcel, buttonMapSize, "actionButtonMapSize");
    buttonMapSize = (buttonMapSize < MAX_ACTION_BUTTON_NUM) ? buttonMapSize : MAX_ACTION_BUTTON_NUM;
    for (uint64_t i = 0; i < buttonMapSize; i++) {
        uint8_t buttonType = static_cast<uint8_t>(ActionButtonType::INVALID);
        READ_UINT8_RETURN_FALSE_LOG(parcel, buttonType, "buttonType");
        ActionButtonType type = static_cast<ActionButtonType>(buttonType);
        std::string title = parcel.ReadString();
        std::string resource = parcel.ReadString();
        std::string pkgName = parcel.ReadString();
        std::string abilityName = parcel.ReadString();
        std::string uri = parcel.ReadString();
        std::string equalTo = parcel.ReadString();
        std::string valuesBucket = parcel.ReadString();
        ActionButtonInfo info;
        info.type = type;
        info.title = title;
        info.resource = resource;
        info.wantAgent = std::make_shared<ButtonWantAgent>();
        if (info.wantAgent == nullptr) {
            return false;
        }
        info.wantAgent->pkgName = pkgName;
        info.wantAgent->abilityName = abilityName;
        info.dataShareUpdate = std::make_shared<ButtonDataShareUpdate>();
        if (info.dataShareUpdate == nullptr) {
            return false;
        }
        info.dataShareUpdate->uri = uri;
        info.dataShareUpdate->equalTo = equalTo;
        info.dataShareUpdate->valuesBucket = valuesBucket;
        actionButtonMap_.insert(std::pair<ActionButtonType, ActionButtonInfo>(type, info));
    }
    return true;
}

bool ReminderRequest::ReadWantParametersFromParcel(Parcel& parcel, AAFwk::WantParams& wantParams)
{
    int empty = VALUE_NULL;
    if (!parcel.ReadInt32(empty)) {
        return false;
    }
    if (empty == VALUE_OBJECT) {
        auto params = parcel.ReadParcelable<AAFwk::WantParams>();
        if (params != nullptr) {
            wantParams = *params;
            delete params;
            params = nullptr;
        } else {
            return false;
        }
    }
    return true;
}

bool ReminderRequest::ReadFromParcel(Parcel &parcel)
{
    READ_STRING_RETURN_FALSE_LOG(parcel, content_, "content");
    READ_STRING_RETURN_FALSE_LOG(parcel, expiredContent_, "expiredContent");
    READ_STRING_RETURN_FALSE_LOG(parcel, snoozeContent_, "snoozeContent");
    READ_STRING_RETURN_FALSE_LOG(parcel, title_, "title");
    READ_STRING_RETURN_FALSE_LOG(parcel, wantAgentInfo_->abilityName, "wantAgentInfo's abilityName");
    READ_STRING_RETURN_FALSE_LOG(parcel, wantAgentInfo_->pkgName, "wantAgentInfo's pkgName");
    READ_STRING_RETURN_FALSE_LOG(parcel, wantAgentInfo_->uri, "wantAgentInfo's uri");
    if (!ReadWantParametersFromParcel(parcel, wantAgentInfo_->parameters)) {
        ANSR_LOGE("Failed to write wantAgentInfo's parameters");
        return false;
    }
    READ_STRING_RETURN_FALSE_LOG(parcel, maxScreenWantAgentInfo_->abilityName, "maxScreenWantAgentInfo's abilityName");
    READ_STRING_RETURN_FALSE_LOG(parcel, maxScreenWantAgentInfo_->pkgName, "maxScreenWantAgentInfo's pkgName");
    READ_STRING_RETURN_FALSE_LOG(parcel, customButtonUri_, "customButtonUri");
    READ_STRING_RETURN_FALSE_LOG(parcel, groupId_, "groupId");
    READ_STRING_RETURN_FALSE_LOG(parcel, customRingUri_, "customRingUri");
    READ_STRING_RETURN_FALSE_LOG(parcel, creatorBundleName_, "creatorBundleName");

    READ_BOOL_RETURN_FALSE_LOG(parcel, isExpired_, "isExpired");
    READ_BOOL_RETURN_FALSE_LOG(parcel, tapDismissed_, "tapDismissed");

    READ_INT64_RETURN_FALSE_LOG(parcel, autoDeletedTime_, "autoDeletedTime");

    int32_t tempReminderId = -1;
    READ_INT32_RETURN_FALSE_LOG(parcel, tempReminderId, "reminderId");
    reminderId_ = (tempReminderId == -1) ? reminderId_ : tempReminderId;

    READ_INT32_RETURN_FALSE_LOG(parcel, notificationId_, "notificationId");

    READ_UINT64_RETURN_FALSE_LOG(parcel, triggerTimeInMilli_, "triggerTimeInMilli");
    READ_UINT64_RETURN_FALSE_LOG(parcel, timeIntervalInMilli_, "timeIntervalInMilli");
    READ_UINT64_RETURN_FALSE_LOG(parcel, ringDurationInMilli_, "ringDurationInMilli");
    READ_UINT64_RETURN_FALSE_LOG(parcel, reminderTimeInMilli_, "reminderTimeInMilli");

    READ_UINT8_RETURN_FALSE_LOG(parcel, snoozeTimes_, "snoozeTimes");
    READ_UINT8_RETURN_FALSE_LOG(parcel, snoozeTimesDynamic_, "snoozeTimesDynamic");
    READ_UINT8_RETURN_FALSE_LOG(parcel, state_, "state");

    uint8_t reminderType = static_cast<uint8_t>(ReminderType::INVALID);
    READ_UINT8_RETURN_FALSE_LOG(parcel, reminderType, "reminderType");
    reminderType_ = static_cast<ReminderType>(reminderType);

    int32_t slotType = static_cast<int32_t>(NotificationConstant::SlotType::OTHER);
    READ_INT32_RETURN_FALSE_LOG(parcel, slotType, "slotType");
    slotType_ = static_cast<NotificationConstant::SlotType>(slotType);

    int32_t snoozeSlotType = static_cast<int32_t>(NotificationConstant::SlotType::OTHER);
    READ_INT32_RETURN_FALSE_LOG(parcel, snoozeSlotType, "snoozeSlotType");
    snoozeSlotType_ = static_cast<NotificationConstant::SlotType>(snoozeSlotType);

    if (!ReadActionButtonFromParcel(parcel)) {
        return false;
    }

    if (!InitNotificationRequest()) {
        return false;
    }
    return true;
}

bool ReminderRequest::InitNotificationRequest()
{
    ANSR_LOGI("Init notification");
    notificationRequest_ = new (std::nothrow) NotificationRequest(notificationId_);
    if (notificationRequest_ == nullptr) {
        ANSR_LOGE("Failed to create notification.");
        return false;
    }
    displayContent_ = content_;
    return true;
}

void ReminderRequest::InitServerObj()
{
    wantAgentInfo_ = wantAgentInfo_ == nullptr ? std::make_shared<WantAgentInfo>() : wantAgentInfo_;
    maxScreenWantAgentInfo_ =
        maxScreenWantAgentInfo_ == nullptr ? std::make_shared<MaxScreenAgentInfo>() : maxScreenWantAgentInfo_;
}

bool ReminderRequest::IsAlerting() const
{
    return (state_ & REMINDER_STATUS_ALERTING) != 0;
}

uint64_t ReminderRequest::GetDurationSinceEpochInMilli(const time_t target)
{
    auto tarEndTimePoint = std::chrono::system_clock::from_time_t(target);
    auto tarDuration = std::chrono::duration_cast<std::chrono::milliseconds>(tarEndTimePoint.time_since_epoch());
    int64_t tarDate = tarDuration.count();
    if (tarDate < 0) {
        ANSR_LOGW("tarDuration is less than 0.");
        return INVALID_LONG_LONG_VALUE;
    }
    return static_cast<uint64_t>(tarDate);
}

std::string ReminderRequest::GetDateTimeInfo(const time_t &timeInSecond) const
{
    return GetTimeInfoInner(timeInSecond, TimeFormat::YMDHMS, true);
}

std::string ReminderRequest::SerializeButtonInfo() const
{
    std::string info = "";
    bool isFirst = true;
    for (auto button : actionButtonMap_) {
        if (!isFirst) {
            info += SEP_BUTTON_MULTI;
        }
        ActionButtonInfo buttonInfo = button.second;
        nlohmann::json root;
        root["type"] = std::to_string(static_cast<uint8_t>(button.first));
        root["title"] = buttonInfo.title;
        root["resource"] = buttonInfo.resource;
        if (buttonInfo.wantAgent != nullptr) {
            nlohmann::json wantAgentfriends;
            wantAgentfriends["pkgName"] = buttonInfo.wantAgent->pkgName;
            wantAgentfriends["abilityName"] = buttonInfo.wantAgent->abilityName;
            root["wantAgent"]  = wantAgentfriends;
        }

        if (buttonInfo.dataShareUpdate != nullptr) {
            nlohmann::json dataShareUpdatefriends;
            dataShareUpdatefriends["uri"] = buttonInfo.dataShareUpdate->uri;
            dataShareUpdatefriends["equalTo"] = buttonInfo.dataShareUpdate->equalTo;
            dataShareUpdatefriends["valuesBucket"] = buttonInfo.dataShareUpdate->valuesBucket;
            root["dataShareUpdate"]  = dataShareUpdatefriends;
        }
        std::string str = root.dump(INDENT, ' ', false, nlohmann::json::error_handler_t::replace);
        info += str;
        isFirst = false;
    }
    return info;
}

uint64_t ReminderRequest::GetNowInstantMilli() const
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    if (static_cast<int64_t>(now) < 0) {
        ANSR_LOGE("Get now time error");
        return 0;
    }
    return GetDurationSinceEpochInMilli(now);
}

std::string ReminderRequest::GetShowTime(const uint64_t showTime) const
{
    if (reminderType_ == ReminderType::TIMER) {
        return "";
    }
    return GetTimeInfoInner(static_cast<time_t>(showTime / MILLI_SECONDS), TimeFormat::HM, false);
}

std::string ReminderRequest::GetTimeInfoInner(const time_t &timeInSecond, const TimeFormat &format,
    bool keep24Hour) const
{
    const uint8_t dateTimeLen = 80;
    char dateTimeBuffer[dateTimeLen];
    struct tm timeInfo;
    (void)localtime_r(&timeInSecond, &timeInfo);
    bool is24HourClock = OHOS::Global::I18n::LocaleConfig::Is24HourClock();
    if (!is24HourClock && timeInfo.tm_hour > TIME_HOUR_OFFSET && !keep24Hour) {
        timeInfo.tm_hour -= TIME_HOUR_OFFSET;
    }
    switch (format) {
        case TimeFormat::YMDHMS: {
            (void)strftime(dateTimeBuffer, dateTimeLen, "%Y-%m-%d %H:%M:%S", &timeInfo);
            break;
        }
        case TimeFormat::HM: {
            (void)strftime(dateTimeBuffer, dateTimeLen, "%H:%M", &timeInfo);
            break;
        }
        default: {
            ANSR_LOGW("Time format not support.");
            break;
        }
    }
    std::string dateTimeInfo(dateTimeBuffer);
    return dateTimeInfo;
}

std::string ReminderRequest::GetState(const uint8_t state) const
{
    std::string stateInfo = "'";
    if (state == REMINDER_STATUS_INACTIVE) {
        stateInfo += "Inactive";
    } else {
        bool hasSeparator = false;
        if ((state & REMINDER_STATUS_ACTIVE) != 0) {
            stateInfo += "Active";
            hasSeparator = true;
        }
        if ((state & REMINDER_STATUS_ALERTING) != 0) {
            if (hasSeparator) {
                stateInfo += ",";
            }
            stateInfo += "Alerting";
            hasSeparator = true;
        }
        if ((state & REMINDER_STATUS_SHOWING) != 0) {
            if (hasSeparator) {
                stateInfo += ",";
            }
            stateInfo += "Showing";
            hasSeparator = true;
        }
        if ((state & REMINDER_STATUS_SNOOZE) != 0) {
            if (hasSeparator) {
                stateInfo += ",";
            }
            stateInfo += "Snooze";
        }
    }
    stateInfo += "'";
    return stateInfo;
}

void ReminderRequest::AddActionButtons(const bool includeSnooze)
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    for (auto button : actionButtonMap_) {
        auto want = std::make_shared<OHOS::AAFwk::Want>();
        auto type = button.first;
        switch (type) {
            case ActionButtonType::CLOSE:
                want->SetAction(REMINDER_EVENT_CLOSE_ALERT);
                break;
            case ActionButtonType::SNOOZE:
                if (includeSnooze) {
                    want->SetAction(REMINDER_EVENT_SNOOZE_ALERT);
                } else {
                    ANSR_LOGD("Not add action button, type is snooze, as includeSnooze is false");
                    continue;
                }
                break;
            case ActionButtonType::CUSTOM:
                want->SetAction(REMINDER_EVENT_CUSTOM_ALERT);
                if (button.second.wantAgent == nullptr) {
                    return;
                }
                want->SetParam("PkgName", button.second.wantAgent->pkgName);
                want->SetParam("AbilityName", button.second.wantAgent->abilityName);
                break;
            default:
                break;
        }
        want->SetParam(PARAM_REMINDER_ID, reminderId_);
        std::vector<std::shared_ptr<AAFwk::Want>> wants;
        wants.push_back(want);
        auto title = static_cast<std::string>(button.second.title);
        AbilityRuntime::WantAgent::WantAgentInfo buttonWantAgentInfo(
            requestCode,
            AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
            flags,
            wants,
            nullptr
        );

        std::string identity = IPCSkeleton::ResetCallingIdentity();
        std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> buttonWantAgent =
            AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(buttonWantAgentInfo, userId_);
        IPCSkeleton::SetCallingIdentity(identity);

        std::shared_ptr<NotificationActionButton> actionButton
            = NotificationActionButton::Create(nullptr, title, buttonWantAgent);
        notificationRequest_->AddActionButton(actionButton);
    }
}

void ReminderRequest::AddRemovalWantAgent()
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetAction(REMINDER_EVENT_REMOVE_NOTIFICATION);
    want->SetParam(PARAM_REMINDER_ID, reminderId_);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        flags,
        wants,
        nullptr
    );

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, userId_);
    IPCSkeleton::SetCallingIdentity(identity);

    notificationRequest_->SetRemovalWantAgent(wantAgent);
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> ReminderRequest::CreateWantAgent(
    AppExecFwk::ElementName &element) const
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> wantFlags;
    wantFlags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetAction(REMINDER_EVENT_CLICK_ALERT);
    want->SetParam(PARAM_REMINDER_ID, reminderId_);
    std::vector<std::shared_ptr<AAFwk::Want>> wantes;
    wantes.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        wantFlags,
        wantes,
        nullptr
    );
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    auto wantAgent = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantInfo, userId_);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    return wantAgent;
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> ReminderRequest::CreateMaxWantAgent(
    AppExecFwk::ElementName &element) const
{
    int32_t requestCode = 10;
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetElement(element);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(
        requestCode,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY,
        flags,
        wants,
        nullptr
    );
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto wantAgent = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo, userId_);
    IPCSkeleton::SetCallingIdentity(identity);
    return wantAgent;
}

void ReminderRequest::SetMaxScreenWantAgent(AppExecFwk::ElementName &element)
{
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = CreateMaxWantAgent(element);
    notificationRequest_->SetMaxScreenWantAgent(wantAgent);
}

void ReminderRequest::SetWantAgent(AppExecFwk::ElementName &element)
{
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = CreateWantAgent(element);
    notificationRequest_->SetWantAgent(wantAgent);
}

void ReminderRequest::SetExtraInfo(const AAFwk::WantParams& params)
{
    if (params.HasParam(PARAM_EXTRA_KEY)) {
        std::shared_ptr<AAFwk::WantParams> extras = std::make_shared<AAFwk::WantParams>(
            params.GetWantParams(PARAM_EXTRA_KEY));
        notificationRequest_->SetAdditionalData(extras);
    }
}

void ReminderRequest::SetState(bool deSet, const uint8_t newState, std::string function)
{
    uint8_t oldState = state_;
    if (deSet) {
        state_ |= newState;
    } else {
        state_ &= static_cast<uint8_t>(~newState);
    }
    ANSR_LOGI("Switch the reminder(reminderId=%{public}d) state, from %{public}s to %{public}s, called by %{public}s",
        reminderId_, GetState(oldState).c_str(), GetState(state_).c_str(), function.c_str());
}

void ReminderRequest::SetStateToInActive()
{
    SetState(false, (REMINDER_STATUS_SHOWING | REMINDER_STATUS_ALERTING | REMINDER_STATUS_ACTIVE),
        "SetStateToInActive");
}

void ReminderRequest::UpdateActionButtons(const bool &setSnooze)
{
    if (notificationRequest_ == nullptr) {
        ANSR_LOGE("updateActionButtons failed, the notificationRequest is null");
        return;
    }
    notificationRequest_->ClearActionButtons();
    if (setSnooze) {
        AddActionButtons(false);
    } else {
        AddActionButtons(true);
    }
}

bool ReminderRequest::UpdateNextReminder(const bool &force)
{
    bool result = true;
    if (force) {
        uint64_t nowInstantMilli = GetNowInstantMilli();
        if (nowInstantMilli == 0) {
            result = false;
        } else {
            if (timeIntervalInMilli_ != 0) {
                triggerTimeInMilli_ = nowInstantMilli + timeIntervalInMilli_;
                snoozeTimesDynamic_ = snoozeTimes_;
                isExpired_ = false;
            }
        }
    } else {
        result = UpdateNextReminder();
    }
    std::string info = result ? "success" : "no next";
    ANSR_LOGI("updateNextReminder(id=%{public}d, %{public}s): force=%{public}d, trigger time is: %{public}s",
        reminderId_, info.c_str(), force,
        GetDateTimeInfo(static_cast<time_t>(triggerTimeInMilli_ / MILLI_SECONDS)).c_str());
    return result;
}

void ReminderRequest::UpdateNotificationCommon(bool isSnooze)
{
    time_t now;
    (void)time(&now);  // unit is seconds.
    notificationRequest_->SetDeliveryTime(GetDurationSinceEpochInMilli(now));
    notificationRequest_->SetLabel(NOTIFICATION_LABEL);
    notificationRequest_->SetShowDeliveryTime(true);
    if (isSnooze) {
        if (snoozeSlotType_ == NotificationConstant::SlotType::OTHER) {
            notificationRequest_->SetSlotType(NotificationConstant::SlotType::CONTENT_INFORMATION);
        } else {
            notificationRequest_->SetSlotType(snoozeSlotType_);
        }
    } else {
        notificationRequest_->SetSlotType(slotType_);
    }
    notificationRequest_->SetTapDismissed(tapDismissed_);
    notificationRequest_->SetAutoDeletedTime(autoDeletedTime_);
    auto notificationNormalContent = std::make_shared<NotificationNormalContent>();
    notificationNormalContent->SetText(displayContent_);
    notificationNormalContent->SetTitle(title_);
    auto notificationContent = std::make_shared<NotificationContent>(notificationNormalContent);
    notificationRequest_->SetContent(notificationContent);
    if ((reminderType_ == ReminderRequest::ReminderType::TIMER) ||
        (reminderType_ == ReminderRequest::ReminderType::ALARM)) {
        notificationRequest_->SetUnremovable(true);
    }
}

void ReminderRequest::UpdateNotificationBundleInfo()
{
    std::string ownerBundleName = notificationRequest_->GetOwnerBundleName();
    if (!(ownerBundleName.empty())) {
        return;
    }
    ANSR_LOGD("ownerBundleName=%{public}s, bundleName_=%{public}s",
        ownerBundleName.c_str(), bundleName_.c_str());
    notificationRequest_->SetOwnerBundleName(bundleName_);
    notificationRequest_->SetOwnerUid(uid_);
    notificationRequest_->SetCreatorBundleName(bundleName_);
    notificationRequest_->SetCreatorUid(uid_);
    notificationRequest_->SetCreatorUserId(userId_);
}

void ReminderRequest::UpdateNotificationContent(const bool &setSnooze)
{
    if (notificationRequest_ == nullptr) {
        ANSR_LOGE("updateNotificationContent failed, the notificationRequest is null");
        return;
    }
    std::string extendContent = "";
    if (setSnooze) {
        if (timeIntervalInMilli_ != 0) {
            // snooze the reminder by manual
            extendContent = snoozeContent_;
            notificationRequest_->SetTapDismissed(false);
        } else {
            // the reminder is expired now, when timeInterval is 0
            extendContent = expiredContent_;
        }
    } else if (IsAlerting()) {
        // the reminder is alerting, or ring duration is 0
        extendContent = "";
    } else if (snoozeTimesDynamic_ != snoozeTimes_) {
        // the reminder is snoozing by period artithmetic, when the ring duration is over.
        extendContent = snoozeContent_;
        notificationRequest_->SetTapDismissed(false);
    } else {
        // the reminder has already snoozed by period arithmetic, when the ring duration is over.
        extendContent = expiredContent_;
    }
    if (extendContent == "") {
        displayContent_ = content_;
    } else {
        displayContent_ = extendContent;
    }
    ANSR_LOGD("Display content=%{public}s", displayContent_.c_str());
}

void ReminderRequest::UpdateNotificationStateForAlert()
{
    ANSR_LOGD("UpdateNotification content and buttons");
    UpdateNotificationContent(false);
    UpdateActionButtons(false);
}

void ReminderRequest::UpdateNotificationStateForSnooze()
{
    ANSR_LOGD("UpdateNotification content and buttons");
    UpdateNotificationContent(true);
    UpdateActionButtons(true);
}

int32_t ReminderRequest::GetActualTime(const TimeTransferType &type, int32_t cTime)
{
    switch (type) {
        case (TimeTransferType::YEAR):  // year
            return BASE_YEAR + cTime;
        case (TimeTransferType::MONTH):  // month
            return 1 + cTime;
        case (TimeTransferType::WEEK): {  // week
            return cTime == 0 ? SUNDAY : cTime;
        }
        default:
            return -1;
    }
}

int32_t ReminderRequest::GetCTime(const TimeTransferType &type, int32_t actualTime)
{
    switch (type) {
        case (TimeTransferType::YEAR):  // year
            return actualTime - BASE_YEAR;
        case (TimeTransferType::MONTH):  // month
            return actualTime - 1;
        case (TimeTransferType::WEEK): {  // week
            return actualTime == SUNDAY ? 0 : actualTime;
        }
        default:
            return -1;
    }
}

void ReminderRequest::SerializeWantAgent(std::string& wantInfoStr, std::string& maxWantInfoStr)
{
    std::string pkgName;
    std::string abilityName;
    std::string uri;
    std::string parameters;
    if (wantAgentInfo_ != nullptr) {
        pkgName = wantAgentInfo_->pkgName;
        abilityName = wantAgentInfo_->abilityName;
        uri = wantAgentInfo_->uri;
        AAFwk::WantParamWrapper wrapper(wantAgentInfo_->parameters);
        parameters = wrapper.ToString();
    }
    nlohmann::json wantInfo;
    wantInfo["pkgName"] = pkgName;
    wantInfo["abilityName"] = abilityName;
    wantInfo["uri"] = uri;
    wantInfo["parameters"] = parameters;
    wantInfoStr = wantInfo.dump(INDENT, ' ', false, nlohmann::json::error_handler_t::replace);

    if (maxScreenWantAgentInfo_ != nullptr) {
        pkgName = maxScreenWantAgentInfo_->pkgName;
        abilityName = maxScreenWantAgentInfo_->abilityName;
        uri = "";
        parameters = "";
    }
    nlohmann::json maxWantInfo;
    maxWantInfo["pkgName"] = pkgName;
    maxWantInfo["abilityName"] = abilityName;
    maxWantInfo["uri"] = uri;
    maxWantInfo["parameters"] = parameters;
    maxWantInfoStr = maxWantInfo.dump(INDENT, ' ', false, nlohmann::json::error_handler_t::replace);
}

int64_t ReminderRequest::GetNextDaysOfWeek(const time_t now, const time_t target) const
{
    struct tm nowTime;
    (void)localtime_r(&now, &nowTime);
    int32_t today = GetActualTime(TimeTransferType::WEEK, nowTime.tm_wday);
    int32_t dayCount = now >= target ? 1 : 0;
    for (; dayCount <= DAYS_PER_WEEK; dayCount++) {
        int32_t day = (today + dayCount) % DAYS_PER_WEEK;
        day = (day == 0) ? SUNDAY : day;
        if (IsRepeatDaysOfWeek(day)) {
            break;
        }
    }
    ANSR_LOGI("NextDayInterval is %{public}d", dayCount);
    time_t nextTriggerTime = target + dayCount * HOURS_PER_DAY * SECONDS_PER_HOUR;
    return GetTriggerTime(now, nextTriggerTime);
}

bool ReminderRequest::IsRepeatDaysOfWeek(int32_t day) const
{
    return (repeatDaysOfWeek_ & (1 << (day - 1))) > 0;
}

time_t ReminderRequest::GetTriggerTimeWithDST(const time_t now, const time_t nextTriggerTime) const
{
    time_t triggerTime = nextTriggerTime;
    struct tm nowLocal;
    struct tm nextLocal;
    (void)localtime_r(&now, &nowLocal);
    (void)localtime_r(&nextTriggerTime, &nextLocal);
    if (nowLocal.tm_isdst == 0 && nextLocal.tm_isdst > 0) {
        triggerTime -= SECONDS_PER_HOUR;
    } else if (nowLocal.tm_isdst > 0 && nextLocal.tm_isdst == 0) {
        triggerTime += SECONDS_PER_HOUR;
    }
    return triggerTime;
}

uint8_t ReminderRequest::GetRepeatDaysOfWeek() const
{
    return repeatDaysOfWeek_;
}

void ReminderRequest::SetRepeatDaysOfWeek(bool set, const std::vector<uint8_t> &daysOfWeek)
{
    if (daysOfWeek.size() == 0) {
        return;
    }
    if (daysOfWeek.size() > DAYS_PER_WEEK) {
        ANSR_LOGE("The length of daysOfWeek should not larger than 7");
        return;
    }
    for (auto it = daysOfWeek.begin(); it != daysOfWeek.end(); ++it) {
        if (*it < MONDAY || *it > SUNDAY) {
            continue;
        }
        if (set) {
            repeatDaysOfWeek_ |= 1 << (*it - 1);
        } else {
            repeatDaysOfWeek_ &= ~(1 << (*it - 1));
        }
    }
}

std::vector<int32_t> ReminderRequest::GetDaysOfWeek() const
{
    std::vector<int32_t> repeatDays;
    int32_t days[] = {1, 2, 3, 4, 5, 6, 7};
    int32_t len = sizeof(days) / sizeof(int32_t);
    for (int32_t i = 0; i < len; i++) {
        if (IsRepeatDaysOfWeek(days[i])) {
            repeatDays.push_back(days[i]);
        }
    }
    return repeatDays;
}

uint64_t ReminderRequest::GetTriggerTime(const time_t now, const time_t nextTriggerTime) const
{
    time_t triggerTime = GetTriggerTimeWithDST(now, nextTriggerTime);
    struct tm test;
    (void)localtime_r(&triggerTime, &test);
    ANSR_LOGI("NextTriggerTime: year=%{public}d, mon=%{public}d, day=%{public}d, hour=%{public}d, "
              "min=%{public}d, sec=%{public}d, week=%{public}d, nextTriggerTime=%{public}lld",
        GetActualTime(TimeTransferType::YEAR, test.tm_year),
        GetActualTime(TimeTransferType::MONTH, test.tm_mon),
        test.tm_mday,
        test.tm_hour,
        test.tm_min,
        test.tm_sec,
        GetActualTime(TimeTransferType::WEEK, test.tm_wday),
        (long long)triggerTime);

    if (static_cast<int64_t>(triggerTime) <= 0) {
        return 0;
    }
    return GetDurationSinceEpochInMilli(triggerTime);
}

void ReminderRequest::OnLanguageChange(const std::shared_ptr<Global::Resource::ResourceManager> &resMgr)
{
    if (resMgr == nullptr) {
        return;
    }
    // update title
    for (auto &button : actionButtonMap_) {
        if (button.second.resource.empty()) {
            continue;
        }
        std::string title;
        resMgr->GetStringByName(button.second.resource.c_str(), title);
        if (title.empty()) {
            continue;
        }
        button.second.title = title;
    }
}
}
}
