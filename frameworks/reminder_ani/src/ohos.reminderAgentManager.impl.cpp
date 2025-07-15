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

#include "ohos.reminderAgentManager.manager.proj.hpp"
#include "ohos.reminderAgentManager.manager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ans_log_wrapper.h"
#include "reminder_helper.h"
#include "notification_helper.h"
#include "reminder_ani_common.h"

using namespace OHOS;

namespace {
static bool CheckReminderId(int32_t reminderId)
{
    if (reminderId < 0) {
        ANSR_LOGW("Param reminder id is illegal.");
        int32_t ret = ReminderAgentManagerNapi::Common::ERR_REMINDER_INVALID_PARAM;
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return false;
    }
    return true;
}

static bool UnWarpDate(uintptr_t date, ani_double& outValue)
{
    ani_object value = reinterpret_cast<ani_object>(date);
    ani_env* env = ::taihe::get_env();
    if (env == nullptr || value == nullptr) {
        ANSR_LOGE("Env is nullptr.");
        return false;
    }
    static const char* className = "Lescompat/Date;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANSR_LOGE("Failed to find class %{public}s.", className);
        return false;
    }
    ani_method get;
    if (ANI_OK != env->Class_FindMethod(cls, "valueOf", nullptr, &get)) {
        ANSR_LOGE("Failed to find method valueOf.");
        return false;
    }
    if (ANI_OK != env->Object_CallMethod_Double(value, get, &outValue)) {
        ANSR_LOGE("Failed to call method valueOf.");
        return false;
    }
    return true;
}

static bool UnWarpNotificationSlot(uintptr_t slot, OHOS::Notification::NotificationConstant::SlotType& outSlot)
{
    ani_object slotObj = reinterpret_cast<ani_object>(slot);
    ani_env* env = ::taihe::get_env();
    if (env == nullptr || slotObj == nullptr) {
        ANSR_LOGE("Env is nullptr or slot is nullptr.");
        return false;
    }
    static const char* className = "Lnotification/notificationSlot/NotificationSlotInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANSR_LOGE("Failed to find class %{public}s.", className);
        return false;
    }
    ani_ref notificationTypeRef = {};
    if (ANI_OK != env->Object_GetPropertyByName_Ref(slotObj, "notificationType", &notificationTypeRef)) {
        ANSR_LOGE("Failed to get property notificationType.");
        return false;
    }
    if (notificationTypeRef == nullptr) {
        ANSR_LOGE("Failed to get property, notificationTypeRef is nullptr.");
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    ani_status status = env->Reference_IsUndefined(notificationTypeRef, &isUndefined);
    if (status != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGE("Failed to check undefined for 'notificationType', status: %{public}d", status);
        return false;
    }
    ani_int intValue;
    status = env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(notificationTypeRef), &intValue);
    if (status != ANI_OK) {
        ANS_LOGE("EnumItem_GetValue_Int failed, status: %{public}d", status);
        return false;
    }
    outSlot = OHOS::Notification::NotificationConstant::SlotType::OTHER;
    ReminderAgentManagerNapi::Common::ConvertSlotType(
        static_cast<ReminderAgentManagerNapi::Common::AniSlotType>(intValue), outSlot);
    return true;
}

static ani_object WarpDouble(ani_env* env, double value)
{
    ani_class doubleCls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("Lstd/core/Double;", &doubleCls)) != ANI_OK) {
        ANSR_LOGE("Failed to find classLstd/core/Double.");
        return nullptr;
    }
    ani_method doubleCtor;
    if ((status = env->Class_FindMethod(doubleCls, "<ctor>", "D:V", &doubleCtor)) != ANI_OK) {
        ANSR_LOGE("Failed to find method <ctor>.");
        return nullptr;
    }
    ani_object doubleObj;
    if ((status = env->Object_New(doubleCls, doubleCtor, &doubleObj, static_cast<ani_double>(value))) != ANI_OK) {
        ANSR_LOGE("Failed to create double object.");
        return nullptr;
    }
    return doubleObj;
}

static bool WarpDate(int64_t time, ani_object &outObj)
{
    ani_env* env = ::taihe::get_env();
    if (env == nullptr || time < 0) {
        ANSR_LOGE("Env is nullptr or time is invalid value.");
        return false;
    }
    ani_class cls;
    ani_status status;
    if (ANI_OK != (status = env->FindClass("Lescompat/Date;", &cls))) {
        ANSR_LOGE("Failed to find class Lescompat/Date.");
        return false;
    }
    ani_method ctor;
    if (ANI_OK != (status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/Object;:V", &ctor))) {
        ANSR_LOGE("Failed to find method <ctor>. Lstd/core/Object;:V");
        return false;
    }
    ani_object timeObj = WarpDouble(env, static_cast<double>(time));
    if (timeObj == nullptr) {
        return false;
    }
    if (ANI_OK != (status = env->Object_New(cls, ctor, &outObj, timeObj))) {
        ANSR_LOGE("Failed to create date object.");
        return false;
    }
    return true;
}

double PublishReminderSync(::ohos::reminderAgentManager::manager::ParamReminder const& reminderReq)
{
    std::shared_ptr<OHOS::Notification::ReminderRequest> reminder;
    if (!ReminderAgentManagerNapi::Common::CreateReminder(reminderReq, reminder)) {
        int32_t ret = ReminderAgentManagerNapi::Common::ERR_REMINDER_INVALID_PARAM;
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return -1;
    }
    int32_t reminderId = -1;
    int32_t ret = OHOS::Notification::ReminderHelper::PublishReminder(*reminder, reminderId);
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return -1;
    }
    return static_cast<double>(reminderId);
}

void CancelReminderSync(double reminderId)
{
    int32_t id = static_cast<int32_t>(reminderId);
    if (!CheckReminderId(id)) {
        return;
    }
    int32_t ret = OHOS::Notification::ReminderHelper::CancelReminder(id);
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
    }
}

::taihe::array<::ohos::reminderAgentManager::manager::ParamReminder> GetValidRemindersSync()
{
    std::vector<OHOS::Notification::ReminderRequestAdaptation> reminders;
    int32_t ret = OHOS::Notification::ReminderHelper::GetValidReminders(reminders);
    std::vector<::ohos::reminderAgentManager::manager::ParamReminder> aniReminders;
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return ::taihe::array<::ohos::reminderAgentManager::manager::ParamReminder>(aniReminders);
    }
    for (const auto& reminder : reminders) {
        if (reminder.reminderRequest_ == nullptr) {
            continue;
        }
        auto result = ReminderAgentManagerNapi::Common::GenAniReminder(reminder.reminderRequest_);
        if (result.has_value()) {
            aniReminders.push_back(result.value());
        }
    }
    return ::taihe::array<::ohos::reminderAgentManager::manager::ParamReminder>(aniReminders);
}

void CancelAllRemindersSync()
{
    int32_t ret = OHOS::Notification::ReminderHelper::CancelAllReminders();
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
    }
}

void AddNotificationSlotSync(uintptr_t slot)
{
    OHOS::Notification::NotificationConstant::SlotType notificationSlot;
    int32_t ret = ReminderAgentManagerNapi::Common::ERR_REMINDER_INVALID_PARAM;
    if (!UnWarpNotificationSlot(slot, notificationSlot)) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return;
    }
    ret = OHOS::Notification::NotificationHelper::AddSlotByType(notificationSlot);
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
    }
}

void RemoveNotificationSlotSync(uintptr_t slotType)
{
    int32_t ret = ReminderAgentManagerNapi::Common::ERR_REMINDER_INVALID_PARAM;
    OHOS::Notification::NotificationConstant::SlotType slot;
    if (!ReminderAgentManagerNapi::Common::UnWarpSlotType(slotType, slot)) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return;
    }
    ret = OHOS::Notification::ReminderHelper::RemoveNotificationSlot(slot);
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
    }
}

void AddExcludeDateSync(double reminderId, uintptr_t date)
{
    int32_t id = static_cast<int32_t>(reminderId);
    if (!CheckReminderId(id)) {
        return;
    }
    ani_double dateValue;
    int32_t ret = ERR_OK;
    if (!UnWarpDate(date, dateValue)) {
        ret = ReminderAgentManagerNapi::Common::ERR_REMINDER_INVALID_PARAM;
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return;
    }
    if (dateValue <= 0) {
        ANSR_LOGW("Param exclude date is illegal.");
        ret = ReminderAgentManagerNapi::Common::ERR_REMINDER_INVALID_PARAM;
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return;
    }
    ret = OHOS::Notification::ReminderHelper::AddExcludeDate(id, static_cast<int64_t>(dateValue));
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
    }
}

void DeleteExcludeDatesSync(double reminderId)
{
    int32_t id = static_cast<int32_t>(reminderId);
    if (!CheckReminderId(id)) {
        return;
    }
    int32_t ret = OHOS::Notification::ReminderHelper::DelExcludeDates(id);
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
    }
}

::taihe::array<uintptr_t> GetExcludeDatesSync(double reminderId)
{
    int32_t id = static_cast<int32_t>(reminderId);
    std::vector<uintptr_t> results;
    if (!CheckReminderId(id)) {
        return ::taihe::array<uintptr_t>(results);
    }
    std::vector<int64_t> dates;
    int32_t ret = OHOS::Notification::ReminderHelper::GetExcludeDates(id, dates);
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return ::taihe::array<uintptr_t>(results);
    }
    for (const auto date : dates) {
        ani_object dateObj;
        if (!WarpDate(date, dateObj)) {
            continue;
        }
        results.push_back(reinterpret_cast<uintptr_t>(dateObj));
    }
    return ::taihe::array<uintptr_t>(results);
}

::taihe::array<::ohos::reminderAgentManager::manager::ReminderInfo> GetAllValidRemindersSync()
{
    std::vector<OHOS::Notification::ReminderRequestAdaptation> reminders;
    int32_t ret = OHOS::Notification::ReminderHelper::GetValidReminders(reminders);
    std::vector<::ohos::reminderAgentManager::manager::ReminderInfo> aniReminders;
    if (ret != ERR_OK) {
        ::taihe::set_business_error(ret, ReminderAgentManagerNapi::Common::getErrCodeMsg(ret));
        return ::taihe::array<::ohos::reminderAgentManager::manager::ReminderInfo>(aniReminders);
    }
    for (const auto& reminder : reminders) {
        if (reminder.reminderRequest_ == nullptr) {
            continue;
        }
        auto result = ReminderAgentManagerNapi::Common::GenAniReminder(reminder.reminderRequest_);
        if (!result.has_value()) {
            continue;
        }
        ::ohos::reminderAgentManager::manager::ReminderInfo reminderInfo {
            .reminderId = static_cast<double>(reminder.reminderRequest_->GetReminderId()),
            .reminderReq = result.value()
        };
        aniReminders.push_back(reminderInfo);
    }
    return ::taihe::array<::ohos::reminderAgentManager::manager::ReminderInfo>(aniReminders);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_PublishReminderSync(PublishReminderSync);
TH_EXPORT_CPP_API_CancelReminderSync(CancelReminderSync);
TH_EXPORT_CPP_API_GetValidRemindersSync(GetValidRemindersSync);
TH_EXPORT_CPP_API_CancelAllRemindersSync(CancelAllRemindersSync);
TH_EXPORT_CPP_API_AddNotificationSlotSync(AddNotificationSlotSync);
TH_EXPORT_CPP_API_RemoveNotificationSlotSync(RemoveNotificationSlotSync);
TH_EXPORT_CPP_API_AddExcludeDateSync(AddExcludeDateSync);
TH_EXPORT_CPP_API_DeleteExcludeDatesSync(DeleteExcludeDatesSync);
TH_EXPORT_CPP_API_GetExcludeDatesSync(GetExcludeDatesSync);
TH_EXPORT_CPP_API_GetAllValidRemindersSync(GetAllValidRemindersSync);
// NOLINTEND