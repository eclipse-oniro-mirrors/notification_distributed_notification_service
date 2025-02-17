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
ErrCode DisturbManager::HandleGetDoNotDisturbProfile(MessageParcel &data, MessageParcel &reply)
{
    int32_t profileId = data.ReadInt32();
    sptr<NotificationDoNotDisturbProfile> profile = nullptr;
    ErrCode result = GetDoNotDisturbProfileInner(profileId, profile);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("HandleGetDoNotDisturbProfile write result failed, ErrCode=%{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        if (!reply.WriteParcelable(profile)) {
            ANS_LOGE("HandleGetDoNotDisturbProfile write slot failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode DisturbManager::GetDoNotDisturbProfileInner(int32_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGW("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    ErrCode result = NotificationPreferences::GetInstance()->GetDoNotDisturbProfile(id, userId, profile);
    if (result != ERR_OK) {
        ANS_LOGE("profile failed id: %{public}d, userid: %{public}d", id, userId);
    }
    return result;
}

}  // namespace Notification
}  // namespace OHOS
