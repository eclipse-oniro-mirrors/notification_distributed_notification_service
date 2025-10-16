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
#include "ani_silent_reminder_enable.h"

#include "ans_log_wrapper.h"
#include "notification_helper.h"
#include "sts_bundle_option.h"
#include "sts_common.h"
#include "sts_notification_manager.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetSilentReminderEnabled(ani_env *env, ani_object bundleOption, ani_boolean enable)
{
    ANS_LOGD("AniSetSilentReminderEnabled call");
    int returncode = ERR_OK;
    BundleOption option;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        ANS_LOGE("UnwrapBundleOption fail");
        OHOS::NotificationSts::ThrowErrorWithCode(env, OHOS::Notification::ERROR_INTERNAL_ERROR);
        return;
    }
    returncode = Notification::NotificationHelper::SetSilentReminderEnabled(option, enable);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetExternalCode failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
    ANS_LOGD("AniSetSilentReminderEnabled end");
}

ani_object AniIsSilentReminderEnabled(ani_env *env, ani_object bundleOption)
{
    ANS_LOGD("AniIsSilentReminderEnabled call");
    int returncode = ERR_OK;
    BundleOption option;
    int32_t enableStatus = 0;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOption, option)) {
        ANS_LOGE("UnwrapBundleOption fail");
        OHOS::NotificationSts::ThrowErrorWithCode(env, OHOS::Notification::ERROR_INTERNAL_ERROR);
        return nullptr;
    }
    returncode = Notification::NotificationHelper::IsSilentReminderEnabled(option, enableStatus);
    if (returncode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(returncode);
        ANS_LOGE("GetExternalCode failed, errorCode: %{public}d", externalCode);
        OHOS::NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        return nullptr;
    }
    ani_enum_item switchStateItem {};
    Notification::NotificationConstant::SWITCH_STATE switchState =
        static_cast<Notification::NotificationConstant::SWITCH_STATE>(enableStatus);
    if (!NotificationSts::SwitchStateCToEts(env, switchState, switchStateItem)) {
        ANS_LOGE("SwitchStateCToEts failed");
        OHOS::NotificationSts::ThrowErrorWithCode(env, OHOS::Notification::ERROR_INTERNAL_ERROR);
        return nullptr;
    }
    ANS_LOGD("AniIsSilentReminderEnabled end");
    return switchStateItem;
}
} // namespace NotificationManagerSts
} // namespace OHOS