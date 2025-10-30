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

#include "reminder_request.h"

namespace OHOS::ReminderAgentManagerNapi {
class Common {
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

    static std::string getErrCodeMsg(const int32_t errorCode);

    static bool CreateReminder(const ::ohos::reminderAgentManager::manager::ParamReminder& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

    static ::taihe::optional<::ohos::reminderAgentManager::manager::ParamReminder> GenAniReminder(
        const sptr<Notification::ReminderRequest>& reminder);

    static void ConvertSlotType(AniSlotType aniSlotType, Notification::NotificationConstant::SlotType& slotType);

    static bool UnWarpSlotType(uintptr_t slotType, Notification::NotificationConstant::SlotType& outSlot);

private:
    static bool ParseIntArray(const ::taihe::array<int32_t>& values, std::vector<uint8_t>& result, uint8_t maxLen);

    static bool ParseIntParam(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static void ParseStringParam(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

    static bool ParseLocalDateTime(const ::ohos::reminderAgentManager::manager::LocalDateTime& dateTimeReq,
        struct tm& dateTime);
    static void ParseWantAgent(const ::ohos::reminderAgentManager::manager::WantAgent& wantAgentReq,
        std::shared_ptr<Notification::ReminderRequest::WantAgentInfo>& wantAgent);
    static void ParseMaxScreenWantAgent(const ::ohos::reminderAgentManager::manager::MaxScreenWantAgent& wantAgentReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static void ParseButtonWantAgent(const ::ohos::reminderAgentManager::manager::WantAgent& wantAgentReq,
        std::shared_ptr<Notification::ReminderRequest::ButtonWantAgent>& buttonWantAgent,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static void ParseDataShareUpdateEqualTo(
        const ::taihe::map<::taihe::string, ::ohos::reminderAgentManager::manager::ParamType>& aniEqualTo,
        std::string& equalTo);
    static void ParseButtonDataShareUpdate(
        const ::ohos::reminderAgentManager::manager::DataShareUpdate& aniDataShareUpdate,
        std::shared_ptr<Notification::ReminderRequest::ButtonDataShareUpdate>& dataShareUpdate);
    static bool ParseActionButton(
        const ::taihe::array<::ohos::reminderAgentManager::manager::ActionButton>& actionButtons,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static void ParseRingChannel(const ::ohos::reminderAgentManager::manager::RingChannel channel,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

    static bool ParseCalendarParam(const ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendarReq,
        std::vector<uint8_t>& repeatMonths, std::vector<uint8_t>& repeatDays, std::vector<uint8_t>& daysOfWeek);

    static bool CreateReminderBase(const ::ohos::reminderAgentManager::manager::ReminderRequest& reminderReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static bool CreateReminderTimer(const ::ohos::reminderAgentManager::manager::ReminderRequestTimer& timerReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static bool CreateReminderAlarm(const ::ohos::reminderAgentManager::manager::ReminderRequestAlarm& alarmReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);
    static bool CreateReminderCalendar(
        const ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendarReq,
        std::shared_ptr<Notification::ReminderRequest>& reminder);

private:
    static void GenAniIntResult(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequest& base);
    static void GenAniStringResult(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequest& base);

    static void GenAniWantAgent(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::ohos::reminderAgentManager::manager::WantAgent>& aniWantAgent);
    static void GenAniMaxScreenWantAgent(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::ohos::reminderAgentManager::manager::MaxScreenWantAgent>& aniWantAgent);
    static void GenAniActionButton(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::taihe::array<::ohos::reminderAgentManager::manager::ActionButton>>& aniActionButtons);
    static void GenAniRingChannel(const sptr<Notification::ReminderRequest>& reminder,
        ::taihe::optional<::ohos::reminderAgentManager::manager::RingChannel>& aniRingChannel);

    static void GenAniReminderBase(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequest& base);
    static void GenAniReminderTimer(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequestTimer& timer);
    static void GenAniReminderAlarm(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequestAlarm& alarm);
    static void GenAniReminderCalendar(const sptr<Notification::ReminderRequest>& reminder,
        ::ohos::reminderAgentManager::manager::ReminderRequestCalendar& calendar);

private:
    static bool IsSelfSystemApp();
};
} // namespace OHOS::ReminderAgentManagerNapi

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_REMINDER_ANI_INCLUDE_REMINDER_ANI_COMMON_H