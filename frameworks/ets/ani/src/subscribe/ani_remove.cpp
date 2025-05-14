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
#include "ani_remove.h"

#include "inner_errors.h"
#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "notification_request.h"
#include "sts_bundle_option.h"
#include "sts_subscribe.h"

namespace OHOS {
namespace NotificationSubScribeSts {
void AniRemoveForBundle(ani_env *env, ani_object bundle, ani_object notificationKey, ani_object reasonEnum)
{
    ANS_LOGD("AniRemoveForBundle enter");
    BundleOption option;
    Notification::NotificationKey key;
    int32_t reasonType = -1;
    if (!NotificationSts::UnwrapBundleOption(env, bundle, option)) {
        ANS_LOGD("bundle is valid");
        return;
    }
    if (!NotificationSts::UnWarpNotificationKey(env, notificationKey, key)) {
        ANS_LOGD("notificationKey is valid");
        return;
    }
    if (!NotificationSts::UnWarpReasonEnum(env, reasonEnum, reasonType)) {
        ANS_LOGD("enum convert failed");
        return;
    }
    if (!NotificationSts::IsValidRemoveReason(reasonType)) {
        ANS_LOGD("reasonType is valid");
        return;
    }
    int ret = Notification::NotificationHelper::RemoveNotification(option, key.id, key.label, reasonType);
    ANS_LOGD("StsRemoveForBundle ret %{public}d. ErrorToExternal %{public}d",
        ret, CJSystemapi::Notification::ErrorToExternal(ret));
}

void AniRemoveForHashCode(ani_env *env, ani_string hashCode, ani_object reasonEnum)
{
    ANS_LOGD("AniRemoveForHashCode enter");
    int32_t reasonType = -1;
    std::string hashCodeStd;
    if (ANI_OK != NotificationSts::GetStringByAniString(env, hashCode, hashCodeStd)) {
        ANS_LOGD("hashCode is valid");
        return;
    }
    if (!NotificationSts::UnWarpReasonEnum(env, reasonEnum, reasonType)) {
        ANS_LOGD("enum convert failed");
        return;
    }
    if (!NotificationSts::IsValidRemoveReason(reasonType)) {
        ANS_LOGD("reasonType is valid");
        return;
    }
    ANS_LOGD("hashCode: %{public}s, reasonType: %{public}d", hashCodeStd.c_str(), reasonType);
    int ret = Notification::NotificationHelper::RemoveNotification(hashCodeStd, reasonType);
    ANS_LOGD("StsRemoveForHashCode ret %{public}d. ErrorToExternal %{public}d",
        ret, CJSystemapi::Notification::ErrorToExternal(ret));
}

void AniRemoveForHashCodes(ani_env *env, ani_object hashCodes, ani_object reasonEnum)
{
    ANS_LOGD("StsRemoveForHashCodes enter");
    std::vector<std::string> hashCodesStd;
    int32_t reasonType;
    if (ANI_OK != NotificationSts::GetStringArrayByAniObj(env, hashCodes, hashCodesStd)) {
        ANS_LOGD("hashCodes is valid");
        return;
    }
    if (!NotificationSts::UnWarpReasonEnum(env, reasonEnum, reasonType)) {
        ANS_LOGD("enum convert failed");
        return;
    }
    if (!NotificationSts::IsValidRemoveReason(reasonType)) {
        ANS_LOGD("reasonType is valid");
        return;
    }
    int ret = Notification::NotificationHelper::RemoveNotifications(hashCodesStd, reasonType);
    ANS_LOGD("StsRemoveForHashCodes ret %{public}d. ErrorToExternal %{public}d",
        ret, CJSystemapi::Notification::ErrorToExternal(ret));
}
}
}
