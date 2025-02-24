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

namespace OHOS {
namespace Notification {
ErrCode DisturbManager::HandleRemoveDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply)
{
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    if (!ReadParcelableVector(profiles, data)) {
        ANS_LOGE("Read profiles failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = RemoveDoNotDisturbProfilesSyncQueue(profiles);
    if (!reply.WriteInt32(result)) {
        ANS_LOGE("Write result failed, ErrCode is %{public}d", result);
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return ERR_OK;
}

ErrCode DisturbManager::RemoveDoNotDisturbProfilesSyncQueue(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("Called.");
    
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGW("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    AdvancedNotificationService::GetInstance()->SubmitSyncTask(
        std::bind([copyUserId = userId, copyProfiles = profiles]() {
            ANS_LOGD("The ffrt enter.");
            NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfiles(copyUserId, copyProfiles);
        }));
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
