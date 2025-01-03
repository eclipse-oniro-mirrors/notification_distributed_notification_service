/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
ErrCode DisturbManager::GetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply)
{
    sptr<NotificationDoNotDisturbDate> date = nullptr;

    ErrCode result = GetDoNotDisturbDateInner(date);
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

ErrCode DisturbManager::GetDoNotDisturbDateInner(sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    return GetDoNotDisturbDateByUser(userId, date);
}

ErrCode DisturbManager::GetDoNotDisturbDateByUser(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date)
{
    ErrCode result = ERR_OK;
    auto excuteQueue = AdvancedNotificationService::GetInstance()->GetNotificationSvrQueue();
    if (excuteQueue == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = excuteQueue->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationDoNotDisturbDate> currentConfig = nullptr;
        result = NotificationPreferences::GetInstance()->GetDoNotDisturbDate(userId, currentConfig);
        if (result == ERR_OK) {
            int64_t now = GetCurrentTime();
            switch (currentConfig->GetDoNotDisturbType()) {
                case NotificationConstant::DoNotDisturbType::CLEARLY:
                case NotificationConstant::DoNotDisturbType::ONCE:
                    if (now >= currentConfig->GetEndDate()) {
                        date = new (std::nothrow) NotificationDoNotDisturbDate(
                            NotificationConstant::DoNotDisturbType::NONE, 0, 0);
                        if (date == nullptr) {
                            ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
                            return;
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
        }
    }));
    excuteQueue->wait(handler);

    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
