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

#include <unistd.h>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerProxy::PublishReminder(sptr<ReminderRequest> &reminder)
{
    ANSR_LOGI("PublishReminder");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[PublishReminder] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (reminder == nullptr) {
        ANSR_LOGW("[PublishReminder] fail: reminder is null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    if (!data.WriteUint8(static_cast<uint8_t>(reminder->GetReminderType()))) {
        ANSR_LOGE("[PublishReminder] fail: write reminder type failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteParcelable(reminder)) {
        ANSR_LOGE("[Publish] fail: write reminder parcelable failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::PUBLISH_REMINDER, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[PublishReminder] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    int32_t reminderId = -1;
    if (!reply.ReadInt32(reminderId)) {
        ANSR_LOGE("[PublishReminder] fail: read reminder id failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    reminder->SetReminderId(reminderId);
    ANSR_LOGD("ReminderId=%{public}d", reminder->GetReminderId());
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[PublishReminder] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::CancelReminder(const int32_t reminderId)
{
    ANSR_LOGI("[CancelReminder]");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[CancelReminder] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(reminderId)) {
        ANSR_LOGE("[CancelReminder] fail: write reminder id failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_REMINDER, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[CancelReminder] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[CancelReminder] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::CancelAllReminders()
{
    ANSR_LOGI("[CancelAllReminders]");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[CancelAllReminders] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::CANCEL_ALL_REMINDERS, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[CancelAllReminders] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[CancelAllReminders] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::GetValidReminders(std::vector<sptr<ReminderRequest>> &reminders)
{
    ANSR_LOGI("[GetValidReminders]");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[GetValidReminders] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_ALL_VALID_REMINDERS, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[GetValidReminders] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    uint8_t count = 0;
    if (!reply.ReadUint8(count)) {
        ANSR_LOGE("[GetValidReminders] fail: read reminder count failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ANSR_LOGD("[GetValidReminders] count=%{public}hhu", count);
    reminders.clear();
    result = ReadReminders(count, reply, reminders);
    if (result != ERR_OK) {
        ANSR_LOGE("[GetValidReminders] fail: ReadReminders ErrCode=%{public}d", result);
        return result;
    } else {
        ANSR_LOGD("[GetValidReminders], size=%{public}zu", reminders.size());
    }
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[GetValidReminders] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::AddExcludeDate(const int32_t reminderId, const uint64_t date)
{
    ANSR_LOGI("[AddExcludeDate]");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[AddExcludeDate] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(reminderId)) {
        ANSR_LOGE("[AddExcludeDate] fail: write reminder id failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteUint64(date)) {
        ANSR_LOGE("[AddExcludeDate] fail: write exclude date failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ADD_EXCLUDE_DATE_REMINDER, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[AddExcludeDate] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[AddExcludeDate] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::DelExcludeDates(const int32_t reminderId)
{
    ANSR_LOGI("[DelExcludeDates]");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[DelExcludeDates] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(reminderId)) {
        ANSR_LOGE("[DelExcludeDates] fail: write reminder id failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::DEL_EXCLUDE_DATES_REMINDER, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[DelExcludeDates] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[DelExcludeDates] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::GetExcludeDates(const int32_t reminderId, std::vector<uint64_t>& dates)
{
    ANSR_LOGI("[GetExcludeDates]");
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANSR_LOGE("[GetExcludeDates] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(reminderId)) {
        ANSR_LOGE("[GetExcludeDates] fail: write reminder id failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_EXCLUDE_DATES_REMINDER, option, data, reply);
    if (result != ERR_OK) {
        ANSR_LOGE("[GetExcludeDates] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    uint8_t count = 0;
    if (!reply.ReadUint8(count)) {
        ANSR_LOGE("[GetExcludeDates] fail: read exclude date count failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    ANSR_LOGD("[GetExcludeDates] count=%{public}hhu", count);
    dates.clear();
    for (uint8_t i = 0; i < count; i++) {
        uint64_t date = 0;
        if (!reply.ReadUint64(date)) {
            ANSR_LOGE("[GetExcludeDates] fail: read exclude date");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        dates.push_back(date);
    }
    if (!reply.ReadInt32(result)) {
        ANSR_LOGE("[GetExcludeDates] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::ReadReminders(
    uint8_t &count, MessageParcel &reply, std::vector<sptr<ReminderRequest>> &reminders)
{
    for (uint8_t i = 0; i < count; i++) {
        uint8_t typeInfo = static_cast<uint8_t>(ReminderRequest::ReminderType::INVALID);
        if (!reply.ReadUint8(typeInfo)) {
            ANSR_LOGE("Failed to read reminder type");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        auto reminderType = static_cast<ReminderRequest::ReminderType>(typeInfo);
        sptr<ReminderRequest> reminder;
        if (ReminderRequest::ReminderType::ALARM == reminderType) {
            ANSR_LOGD("[GetValidReminders] alarm");
            reminder = reply.ReadParcelable<ReminderRequestAlarm>();
        } else if (ReminderRequest::ReminderType::TIMER == reminderType) {
            ANSR_LOGD("[GetValidReminders] timer");
            reminder = reply.ReadParcelable<ReminderRequestTimer>();
        } else if (ReminderRequest::ReminderType::CALENDAR == reminderType) {
            ANSR_LOGD("[GetValidReminders] calendar");
            reminder = reply.ReadParcelable<ReminderRequestCalendar>();
        } else {
            ANSR_LOGW("[GetValidReminders] type=%{public}hhu", typeInfo);
            return ERR_ANS_INVALID_PARAM;
        }
        if (!reminder) {
            ANSR_LOGE("[GetValidReminders] fail: Reminder ReadParcelable failed");
            return ERR_ANS_PARCELABLE_FAILED;
        }
        reminders.push_back(reminder);
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
