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

#include "ani_on.h"
#include "ans_log_wrapper.h"
#include "sts_common.h"
#include "sts_throw_erro.h"
#include "sts_request.h"
#include "ani_push_callback.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "notification_helper.h"

constexpr const char* TYPE_STRING = "checkNotification";
namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;

bool CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        ANS_LOGE("current app is not system app, not allow.");
        return false;
    }
    return true;
}

ani_int AniOn(ani_env *env, ani_string type, ani_fn_object fn, ani_object checkRequestObj)
{
    ANS_LOGD("enter");
#ifdef ANS_FEATURE_LIVEVIEW_LOCAL_LIVEVIEW
    std::string typeStr = "";
    ani_status status = OHOS::NotificationSts::GetStringByAniString(env, type, typeStr);
    if (status != ANI_OK || typeStr.compare(TYPE_STRING)) {
        ANS_LOGE("InvalidParam 'type'");
        int32_t errCode = OHOS::Notification::ERROR_PARAM_INVALID;
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return errCode;
    }
    if (OHOS::NotificationSts::IsUndefine(env, checkRequestObj)) {
        ANS_LOGI("Old function param, don't need register.");
        return ERR_OK;
    }
    sptr<NotificationCheckRequest> checkRequest = new NotificationCheckRequest();
    if (!OHOS::NotificationSts::UnWarpNotificationCheckRequest(env, checkRequestObj, checkRequest)) {
        ANS_LOGE("InvalidParam 'checkRequest'");
        int32_t errCode = OHOS::Notification::ERROR_PARAM_INVALID;
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return errCode;
    }
    if (!CheckCallerIsSystemApp()) {
        OHOS::NotificationSts::ThrowErrorWithCode(env, ERROR_NOT_SYSTEM_APP);
        return ERROR_NOT_SYSTEM_APP;
    }

    sptr<StsPushCallBack> stsPushCallBack_ = new (std::nothrow) StsPushCallBack(env);
    if (stsPushCallBack_ == nullptr) {
        ANS_LOGE("new stsPushCallBack_ failed");
        OHOS::NotificationSts::ThrowErrorWithCode(env, ERROR_INTERNAL_ERROR);
        return ERROR_INTERNAL_ERROR;
    }
    NotificationConstant::SlotType outSlotType = checkRequest->GetSlotType();
    stsPushCallBack_->SetJsPushCallBackObject(env, outSlotType, fn);
    auto result = NotificationHelper::RegisterPushCallback(stsPushCallBack_->AsObject(), checkRequest);
    if (result != ERR_OK) {
        int32_t externalCode = ERR_OK ? ERR_OK : NotificationSts::GetExternalCode(result);
        ANS_LOGE("Register failed, result is %{public}d", externalCode);
        OHOS::NotificationSts::ThrowErrorWithCode(env, externalCode);
        return externalCode;
    }
    ANS_LOGD("done");
    return result;
#else
    int32_t errCode = OHOS::Notification::ERROR_SYSTEM_CAP_ERROR;
    OHOS::NotificationSts::ThrowErrorWithCode(env, errCode);
    return errCode;
#endif
}

ani_int AniOff(ani_env *env, ani_string type, ani_fn_object fn)
{
    ANS_LOGD("enter");
#ifdef ANS_FEATURE_LIVEVIEW_LOCAL_LIVEVIEW
    std::string typeStr = "";
    ani_status status = OHOS::NotificationSts::GetStringByAniString(env, type, typeStr);
    if (status != ANI_OK || typeStr.compare(TYPE_STRING)) {
        ANS_LOGE("InvalidParam 'type'");
        int32_t errCode = OHOS::Notification::ERROR_PARAM_INVALID;
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return errCode;
    }
    if (!CheckCallerIsSystemApp()) {
        OHOS::NotificationSts::ThrowErrorWithCode(env, ERROR_NOT_SYSTEM_APP);
        return ERROR_NOT_SYSTEM_APP;
    }
    if (!OHOS::NotificationSts::IsUndefine(env, fn)) {
        int32_t errCode = OHOS::Notification::ERROR_PARAM_INVALID;
        OHOS::NotificationSts::ThrowErrorWithInvalidParam(env);
        return errCode;
    }
    int32_t ret = NotificationHelper::UnregisterPushCallback();
    ANS_LOGD("done. ret %{public}d", ret);
    return ERR_OK;
#else
    int32_t errCode = OHOS::Notification::ERROR_SYSTEM_CAP_ERROR;
    OHOS::NotificationSts::ThrowErrorWithCode(env, errCode);
    return errCode;
#endif
}
}
}