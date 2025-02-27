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
ErrCode DisturbManager::HandleGetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDoNotDisturbDate> date = nullptr;

    ErrCode result = GetDoNotDisturbDateSyncQueue(date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleSetDoNotDisturbDate] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        if (!reply.WriteParcelable(date)) {
            ANS_LOGE("[HandleSetDoNotDisturbDate] fail: write date failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return ERR_OK;
}

ErrCode DisturbManager::HandleGetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!data.ReadInt32(userId)) {
        ANS_LOGE("[HandleGetDoNotDisturbDateByUser] fail: read userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    sptr<NotificationDoNotDisturbDate> date = nullptr;
    ErrCode result = GetDoNotDisturbDateByUserSyncQueue(userId, date);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("[HandleGetDoNotDisturbDateByUser] fail: write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        if (!reply.WriteParcelable(date)) {
            ANS_LOGE("[HandleGetDoNotDisturbDateByUser] fail: write date failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return ERR_OK;
}

ErrCode DisturbManager::GetDoNotDisturbDateSyncQueue(sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    ErrCode result = ERR_OK;
    AdvancedNotificationService::GetInstance()->SubmitSyncTask(std::bind([&]() {
        result = GetDoNotDisturbDateByUserInner(userId, date);
    }));
    return result;
}

ErrCode DisturbManager::GetDoNotDisturbDateByUserSyncQueue(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    AdvancedNotificationService::GetInstance()->SubmitSyncTask(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = GetDoNotDisturbDateByUserInner(userId, date);
    }));
    return result;
}

ErrCode DisturbManager::GetDoNotDisturbDateByUserInner(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date)
{
    sptr<NotificationDoNotDisturbDate> currentConfig = nullptr;
    ErrCode result = NotificationPreferences::GetInstance()->GetDoNotDisturbDate(userId, currentConfig);
    if (result != ERR_OK) {
        return result;
    }
    int64_t now = GetCurrentTime();
    switch (currentConfig->GetDoNotDisturbType()) {
        case NotificationConstant::DoNotDisturbType::CLEARLY:
        case NotificationConstant::DoNotDisturbType::ONCE:
            if (now >= currentConfig->GetEndDate()) {
                date = new (std::nothrow) NotificationDoNotDisturbDate(
                    NotificationConstant::DoNotDisturbType::NONE, 0, 0);
                if (date == nullptr) {
                    ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
                    return result;
                }
                NotificationPreferences::GetInstance()->SetDoNotDisturbDate(userId, date);
            } else {
                date = currentConfig;
            }
            break;
        default:
            date = currentConfig;
            break;
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
