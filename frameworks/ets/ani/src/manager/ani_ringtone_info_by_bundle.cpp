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

#include "ani_ringtone_info_by_bundle.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_ringtone_info.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetRingtoneInfoByBundle(ani_env* env, ani_object bundleObj, ani_object ringtoneInfoObj)
{
    ANS_LOGD("AniSetRingtoneInfoByBundle call");
    Notification::NotificationBundleOption bundle;
    if (!NotificationSts::UnwrapBundleOption(env, bundleObj, bundle)) {
        NotificationSts::ThrowErrorWithMsg(env, "AniSetRingtoneInfoByBundle : erro bundle.");
    }
    Notification::NotificationRingtoneInfo ringtoneInfo;
    if (!NotificationSts::UnwrapRingtoneInfo(env, ringtoneInfoObj, ringtoneInfo)) {
        NotificationSts::ThrowErrorWithMsg(env, "AniSetRingtoneInfoByBundle : erro ringtoneInfo.");
    }

    auto errCode = Notification::NotificationHelper::SetRingtoneInfoByBundle(bundle, ringtoneInfo);
    if (errCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(errCode);
        ANS_LOGE("AniSetRingtoneInfoByBundle error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }
}

ani_object AniGetRingtoneInfoByBundle(ani_env *env, ani_object bundleObj)
{
    ANS_LOGD("AniGetRingtoneInfoByBundle call");
    Notification::NotificationBundleOption bundle;
    if (!NotificationSts::UnwrapBundleOption(env, bundleObj, bundle)) {
        NotificationSts::ThrowErrorWithMsg(env, "AniSetRingtoneInfoByBundle : erro bundle.");
    }

    Notification::NotificationRingtoneInfo ringtoneInfo;
    auto errCode = Notification::NotificationHelper::GetRingtoneInfoByBundle(bundle, ringtoneInfo);
    if (errCode != ERR_OK) {
        int externalCode = NotificationSts::GetExternalCode(errCode);
        ANS_LOGE("AniSetRingtoneInfoByBundle error, errorCode: %{public}d", externalCode);
        NotificationSts::ThrowError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
    }

    ani_object ringtoneInfoObj;
    if (!NotificationSts::WrapRingtoneInfo(env, ringtoneInfo, ringtoneInfoObj) || ringtoneInfoObj == nullptr) {
        ANS_LOGE("WrapRingtoneInfo failed");
        NotificationSts::ThrowErrorWithMsg(env, "WrapRingtoneInfo failed");
        return nullptr;
    }
    return ringtoneInfoObj;
}
} // namespace NotificationManagerSts
} // namespace OHOS