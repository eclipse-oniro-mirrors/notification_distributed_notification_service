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
#include "ani_reminder_info.h"

#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "sts_bundle_option.h"
#include "sts_reminder_info.h"
#include "sts_notification_manager.h"
#include "notification_helper.h"
#include "notification_reminder_info.h"

namespace OHOS {
namespace NotificationManagerSts {
ani_object AniGetReminderInfoByBundles(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniGetReminderInfoByBundles call");
    int returncode = 0;
    std::vector<BundleOption> bundles;
    std::vector<ReminderInfo> reminders;
    if (NotificationSts::UnwrapArrayBundleOption(env, obj, bundles)) {
        returncode = Notification::NotificationHelper::GetReminderInfoByBundles(bundles, reminders);
    } else {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniGetReminderInfoByBundles failed : ERROR_INTERNAL_ERROR");
        return nullptr;
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniGetReminderInfoByBundles error, errorCode: %{public}d", externalCode);
    }

    ani_object aniReminders = NotificationSts::GetAniArrayReminderInfo(env, reminders);
    if (aniReminders == nullptr) {
        ANS_LOGE("GetAniArrayReminderInfo failed, arrayBundles is nullptr");
        NotificationSts::ThrowErrorWithMsg(env, "GetAniArrayReminderInfo ERROR_INTERNAL_ERROR");
        return nullptr;
    }

    ANS_LOGD("AniGetReminderInfoByBundles end");
    return aniReminders;
}

void AniSetReminderInfoByBundles(ani_env *env, ani_object obj)
{
    ANS_LOGD("AniSetReminderInfoByBundles call");
    int returncode = 0;
    std::vector<ReminderInfo> reminders;
    if (NotificationSts::UnwrapArrayReminderInfo(env, obj, reminders)) {
        returncode = Notification::NotificationHelper::SetReminderInfoByBundles(reminders);
    } else {
        OHOS::NotificationSts::ThrowError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniSetReminderInfoByBundles failed : ERROR_INTERNAL_ERROR");
        return;
    }

    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSetReminderInfoByBundles error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniSetReminderInfoByBundles end");
    return;
}
}
}
