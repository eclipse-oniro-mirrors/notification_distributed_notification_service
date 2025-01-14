/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "disturb_manager.h"

#include <functional>
#include <iomanip>
#include <sstream>

#include "advanced_notification_service.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"

#include "../advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {
constexpr int32_t HOURS_IN_ONE_DAY = 24;

ErrCode DisturbManager::HandleSetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDoNotDisturbDate> date = data.ReadParcelable<NotificationDoNotDisturbDate>();
    if (date == nullptr) {
        ANS_LOGE("[HandleSetDoNotDisturbDate] fail: read date failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetDoNotDisturbDate(date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDoNotDisturbDate] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}
ErrCode DisturbManager::HandleSetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleSetDoNotDisturbDateByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationDoNotDisturbDate> date = data.ReadParcelable<NotificationDoNotDisturbDate>();
    if (date == nullptr) {
        ANS_LOGE("[HandleSetDoNotDisturbDateByUser] fail: read date failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    ErrCode result = SetDoNotDisturbDateByUserSyncQueue(userId, date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDoNotDisturbDateByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}

ErrCode DisturbManager::SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGW("No active user found!");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    return SetDoNotDisturbDateByUserSyncQueue(userId, date);
}

ErrCode DisturbManager::SetDoNotDisturbDateByUserSyncQueue(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s enter, userId = %{public}d", __FUNCTION__, userId);
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (date == nullptr) {
        ANS_LOGE("Invalid date param");
        return ERR_ANS_INVALID_PARAM;
    }
    int64_t beginDate = ResetSeconds(date->GetBeginDate());
    int64_t endDate = ResetSeconds(date->GetEndDate());
    switch (date->GetDoNotDisturbType()) {
        case NotificationConstant::DoNotDisturbType::NONE:
            beginDate = 0;
            endDate = 0;
            break;
        case NotificationConstant::DoNotDisturbType::ONCE:
            AdjustDateForDndTypeOnce(beginDate, endDate);
            break;
        case NotificationConstant::DoNotDisturbType::CLEARLY:
            if (beginDate >= endDate) {
                return ERR_ANS_INVALID_PARAM;
            }
            break;
        default:
            break;
    }
    ANS_LOGD("Before set SetDoNotDisturbDate beginDate = %{public}" PRId64 ", endDate = %{public}" PRId64,
             beginDate, endDate);
    const sptr<NotificationDoNotDisturbDate> newConfig = new (std::nothrow) NotificationDoNotDisturbDate(
        date->GetDoNotDisturbType(), beginDate, endDate);
    if (newConfig == nullptr) {
        ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
        return ERR_NO_MEMORY;
    }

    sptr<NotificationBundleOption> bundleOption = AdvancedNotificationService::GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Generate invalid bundle option!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    AdvancedNotificationService::GetInstance()->SubmitSyncTask(std::bind([&]() {
        SetDoNotDisturbDateByUserInner(userId, newConfig);
    }));
    return ERR_OK;
}

ErrCode DisturbManager::SetDoNotDisturbDateByUserInner(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("ffrt enter!");
    ErrCode result = NotificationPreferences::GetInstance()->SetDoNotDisturbDate(userId, date);
    if (result == ERR_OK) {
        NotificationSubscriberManager::GetInstance()->NotifyDoNotDisturbDateChanged(userId, date);
    }
    return result;
}

void DisturbManager::AdjustDateForDndTypeOnce(int64_t &beginDate, int64_t &endDate)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    time_t nowT = std::chrono::system_clock::to_time_t(now);
    tm nowTm = GetLocalTime(nowT);

    auto beginDateMilliseconds = std::chrono::milliseconds(beginDate);
    auto beginDateTimePoint =
        std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(beginDateMilliseconds);
    time_t beginDateT = std::chrono::system_clock::to_time_t(beginDateTimePoint);
    tm beginDateTm = GetLocalTime(beginDateT);

    auto endDateMilliseconds = std::chrono::milliseconds(endDate);
    auto endDateTimePoint =
        std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(endDateMilliseconds);
    time_t endDateT = std::chrono::system_clock::to_time_t(endDateTimePoint);
    tm endDateTm = GetLocalTime(endDateT);

    tm todayBeginTm = nowTm;
    todayBeginTm.tm_sec = 0;
    todayBeginTm.tm_min = beginDateTm.tm_min;
    todayBeginTm.tm_hour = beginDateTm.tm_hour;

    tm todayEndTm = nowTm;
    todayEndTm.tm_sec = 0;
    todayEndTm.tm_min = endDateTm.tm_min;
    todayEndTm.tm_hour = endDateTm.tm_hour;

    time_t todayBeginT = mktime(&todayBeginTm);
    if (todayBeginT == -1) {
        return;
    }
    time_t todayEndT = mktime(&todayEndTm);
    if (todayEndT == -1) {
        return;
    }

    auto newBeginTimePoint = std::chrono::system_clock::from_time_t(todayBeginT);
    auto newEndTimePoint = std::chrono::system_clock::from_time_t(todayEndT);
    if (newBeginTimePoint >= newEndTimePoint) {
        newEndTimePoint += std::chrono::hours(HOURS_IN_ONE_DAY);
    }

    if (newEndTimePoint < now) {
        newBeginTimePoint += std::chrono::hours(HOURS_IN_ONE_DAY);
        newEndTimePoint += std::chrono::hours(HOURS_IN_ONE_DAY);
    }

    auto newBeginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(newBeginTimePoint.time_since_epoch());
    beginDate = newBeginDuration.count();

    auto newEndDuration = std::chrono::duration_cast<std::chrono::milliseconds>(newEndTimePoint.time_since_epoch());
    endDate = newEndDuration.count();
}

}  // namespace Notification
}  // namespace OHOS
