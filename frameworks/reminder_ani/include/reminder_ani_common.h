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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_REMINDER_ANI_INCLUDE_REMINDER_ANI_COMMON_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_REMINDER_ANI_INCLUDE_REMINDER_ANI_COMMON_H

#include "ohos.reminderAgentManager.manager.proj.hpp"

#include "taihe/callback.hpp"
#include "reminder_request.h"
#include "reminder_state_callback.h"

namespace OHOS::ReminderAgentManagerNapi {
using CallbackType = ::taihe::callback<
    void(::taihe::array_view<::ohos::reminderAgentManager::manager::ReminderState>)>;
class AniReminderStateCallback : public Notification::ReminderStateCallback {
public:
    explicit AniReminderStateCallback(std::shared_ptr<CallbackType> callback)
        : callback_(callback) {}
    ~AniReminderStateCallback() = default;

    void OnReminderState(const std::vector<Notification::ReminderState>& states) override;

private:
    std::shared_ptr<CallbackType> callback_;
};

class Common {
public:
    using CallbackPair = std::pair<CallbackType, sptr<AniReminderStateCallback>>;
    static std::list<CallbackPair> callbackList_;
    static std::mutex callbackMutex_;

public:
    enum ErrorCode : int32_t {
        ERR_REMINDER_PERMISSION_DENIED = 201,
        ERR_REMINDER_INVALID_PARAM = 401,
        ERR_REMINDER_NOTIFICATION_NOT_ENABLE = 1700001,
        ERR_REMINDER_NUMBER_OVERLOAD,
        ERR_REMINDER_NOT_EXIST,
        ERR_REMINDER_PACKAGE_NOT_EXIST,
        ERR_REMINDER_CALLER_TOKEN_INVALID,
        ERR_REMINDER_DATA_SHARE_PERMISSION_DENIED,
        ERR_REMINDER_PARAM_ERROR,
        ERR_REMINDER_NOTIFICATION_NO_SHOWING,
    };
    
    enum AniSlotType {
        UNKNOWN_TYPE = 0,
        SOCIAL_COMMUNICATION = 1,
        SERVICE_INFORMATION = 2,
        CONTENT_INFORMATION = 3,
        LIVE_VIEW = 4,
        CUSTOMER_SERVICE = 5,
        EMERGENCY_INFORMATION = 10,
        OTHER_TYPES = 0xFFFF,
    };

    static std::string GetErrCodeMsg(const int32_t errorCode, const std::string& extraInfo = "");

    bool CreateReminder(const ::ohos::reminderAgentManager::manager::ParamReminder& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

    ::taihe::optional<::ohos::reminderAgentManager::manager::ParamReminder> GenAniReminder(
        const sptr<Notification::ReminderRequest>& reminder);

    void ConvertSlotType(AniSlotType aniSlotType, Notification::NotificationConstant::SlotType& slotType);

    bool UnWarpSlotType(uintptr_t slotType, Notification::NotificationConstant::SlotType& outSlot);

    std::string GetErrorMsg() const
    {
        return lastErrorMsg_;
    }

private:
    bool ParseIntArray(const ::taihe::array<int32_t>& values, std::vector<uint8_t>& result, uint8_t maxLen);

    bool ParseIntParam(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    void ParseStringParam(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    bool ParseBoolParam(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

    bool ParseLocalDateTime(const ::ohos::reminderAgentManager::manager::LocalDateTime& dateTimeReq,
        struct tm& dateTime);
    void ParseWantAgent(const ::ohos::reminderAgentManager::manager::WantAgent& wantAgentReq,
        std::shared_ptr<Notification::ReminderRequest::WantAgentInfo>& wantAgent);
    void ParseMaxScreenWantAgent(const ::ohos::reminderAgentManager::manager::MaxScreenWantAgent& wantAgentReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    void ParseButtonWantAgent(const ::ohos::reminderAgentManager::manager::WantAgent& wantAgentReq,
        std::shared_ptr<Notification::ReminderRequest::ButtonWantAgent>& buttonWantAgent,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    void ParseDataShareUpdateEqualTo(
        const ::taihe::map<::taihe::string, ::ohos::reminderAgentManager::manager::ParamType>& aniEqualTo,
        std::string& equalTo);
    void ParseButtonDataShareUpdate(
        const ::ohos::reminderAgentManager::manager::DataShareUpdate& aniDataShareUpdate,
        std::shared_ptr<Notification::ReminderRequest::ButtonDataShareUpdate>& dataShareUpdate);
    bool ParseActionButton(
        const ::taihe::array<::ohos::reminderAgentManager::manager::ActionButton>& actionButtons,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    void ParseRingChannel(const ::ohos::reminderAgentManager::manager::RingChannel channel,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

    bool ParseCalendarParam(const ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendarReq,
        std::vector<uint8_t>& repeatMonths, std::vector<uint8_t>& repeatDays, std::vector<uint8_t>& daysOfWeek);

    bool CreateReminderBase(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    bool CreateReminderTimer(const ::ohos::reminderAgentManager::manager::ReminderRequestTimer& timerReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    bool CreateReminderAlarm(const ::ohos::reminderAgentManager::manager::ReminderRequestAlarm& alarmReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    bool CreateReminderCalendar(
        const ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendarReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

private:
    void GenAniIntResult(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequest& base);
    void GenAniStringResult(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequest& base);

    void GenAniWantAgent(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::ohos::reminderAgentManager::manager::WantAgent>& aniWantAgent);
    void GenAniMaxScreenWantAgent(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::ohos::reminderAgentManager::manager::MaxScreenWantAgent>& aniWantAgent);
    void GenAniActionButton(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::taihe::array<::ohos::reminderAgentManager::manager::ActionButton>>& aniActionButtons);
    void GenAniRingChannel(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::ohos::reminderAgentManager::manager::RingChannel>& aniRingChannel);

    void GenAniReminderBase(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequest& base);
    void GenAniReminderTimer(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequestTimer& timer);
    void GenAniReminderAlarm(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequestAlarm& alarm);
    void GenAniReminderCalendar(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendar);

private:
    bool IsSelfSystemApp();

private:
    std::string lastErrorMsg_;
};
} // namespace OHOS::ReminderAgentManagerNapi

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_REMINDER_ANI_INCLUDE_REMINDER_ANI_COMMON_H