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

#include "ani_geofence_enabled.h"

#include "ans_log_wrapper.h"
#include "notification_helper.h"
#include "sts_common.h"
#include "sts_notification_manager.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetGeofenceEnabled(ani_env* env, ani_boolean enabled)
{
    ANS_LOGD("AniSetGeofenceEnabled call, enable: %{public}d", enabled);
    int returncode = Notification::NotificationHelper::SetGeofenceEnabled(NotificationSts::AniBooleanToBool(enabled));
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetGeofenceEnabled error, errorCode: %{public}d", externalCode);
        return;
    }
    ANS_LOGD("AniSetGeofenceEnabled end");
}

ani_boolean AniIsGeofenceEnabled(ani_env* env)
{
    ANS_LOGD("AniIsGeofenceEnabled call");
    bool enabled = false;
    int returncode = Notification::NotificationHelper::IsGeofenceEnabled(enabled);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("AniIsGeofenceEnabled error, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return NotificationSts::BoolToAniBoolean(false);
    }
    ANS_LOGD("AniIsGeofenceEnabled end");
    return NotificationSts::BoolToAniBoolean(enabled);
}
} // namespace NotificationManagerSts
} // namespace OHOS