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
#include "ani_local_live_view.h"

#include "inner_errors.h"
#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniTriggerSystemLiveView(
    ani_env *env, ani_object bundleOptionObj, ani_double notificationId, ani_object buttonOptionsObj)
{
    ANS_LOGD("AniTriggerSystemLiveView call");
    BundleOption bundleOption;
    if (!NotificationSts::UnwrapBundleOption(env, bundleOptionObj, bundleOption)) {
        OHOS::AbilityRuntime::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniTriggerSystemLiveView bundleOption ERROR_INTERNAL_ERROR");
        return;
    }
    NotificationSts::ButtonOption buttonOption;
    if (NotificationSts::UnWarpNotificationButtonOption(env, buttonOptionsObj, buttonOption) != ANI_OK) {
        OHOS::AbilityRuntime::ThrowStsError(env, OHOS::Notification::ERROR_INTERNAL_ERROR,
            NotificationSts::FindAnsErrMsg(OHOS::Notification::ERROR_INTERNAL_ERROR));
        ANS_LOGE("AniTriggerSystemLiveView buttonOption ERROR_INTERNAL_ERROR");
        return;
    }
    int returncode = OHOS::Notification::NotificationHelper::TriggerLocalLiveView(bundleOption,
        static_cast<int32_t>(notificationId), buttonOption);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniTriggerSystemLiveView error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniTriggerSystemLiveView end");
}

void AniSubscribeSystemLiveView(ani_env *env, ani_object subscriberObj)
{
    ANS_LOGD("AniSubscribeSystemLiveView call");
    NotificationSts::StsNotificationLocalLiveViewSubscriber *localLiveViewSubscriber
        = new (std::nothrow)NotificationSts::StsNotificationLocalLiveViewSubscriber();
    localLiveViewSubscriber->SetStsNotificationLocalLiveViewSubscriber(env, subscriberObj);
    int returncode
        = OHOS::Notification::NotificationHelper::SubscribeLocalLiveViewNotification(*localLiveViewSubscriber, false);
    int externalCode = CJSystemapi::Notification::ErrorToExternal(returncode);
    if (externalCode != 0) {
        OHOS::AbilityRuntime::ThrowStsError(env, externalCode, NotificationSts::FindAnsErrMsg(externalCode));
        ANS_LOGE("AniSubscribeSystemLiveView error, errorCode: %{public}d", externalCode);
    }
    ANS_LOGD("AniSubscribeSystemLiveView end");
}
} // namespace NotificationManagerSts
} // namespace OHOS