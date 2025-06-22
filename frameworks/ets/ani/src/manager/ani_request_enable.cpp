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
#include "ani_request_enable.h"

#include "ani_ans_dialog_callback.h"
#include "ans_log_wrapper.h"
#include "sts_error_utils.h"
#include "notification_helper.h"
#include "ani_common_util.h"
#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace OHOS::Notification;
bool GetEnableNotificationInfo(ani_env *env, ani_object content, std::shared_ptr<EnableNotificationInfo> &info)
{
    ANS_LOGD("enter");
    if (content == nullptr) {
        ANS_LOGD("content is null");
        return true;
    }
    ani_status status = ANI_OK;
    ani_boolean stageMode = ANI_FALSE;
    status = OHOS::AbilityRuntime::IsStageContext(env, content, stageMode);
    ANS_LOGD("status %{public}d, stageMode %{public}d", status, stageMode);
    if (ANI_OK != status || stageMode != ANI_TRUE) {
        ANS_LOGE("Only support stage mode");
        std::string msg = "Incorrect parameter types.Only support stage mode.";
        OHOS::AbilityRuntime::ThrowStsError(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    info->stageMode = true;
    info->context = OHOS::AbilityRuntime::GetStageModeContext(env, content);
    if (info->context != nullptr) {
        info->callerToken = info->context->GetToken();
    }
    return true;
}

void RequestEnableExecute(std::shared_ptr<EnableNotificationInfo> &info)
{
    ANS_LOGD("enter");
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    if (client == nullptr) {
        ANS_LOGD("create client fail");
        info->errorCode = ERROR_INTERNAL_ERROR;
        return;
    }
    if (info->context != nullptr) {
        ANS_LOGD("stage mode");
        bool canPop = false;
        std::string bundleName = "";
        ErrCode errCode = NotificationHelper::CanPopEnableNotificationDialog(client, canPop, bundleName);
        ANS_LOGI("CanPopEnableNotificationDialog  result , errCode = %{public}d , canPop = %{public}d",
            errCode, canPop);
        if (canPop == false) {
            info->errorCode = errCode;
            return;
        }
        info->bundleName = bundleName;
    } else {
        ANS_LOGD("un stage mode");
        std::string deviceId {""};
        info->errorCode = NotificationHelper::RequestEnableNotification(deviceId, client, info->callerToken);
    }
    ANS_LOGI("ipcCall done, code is %{public}d.", info->errorCode);
}

void StsAsyncCompleteCallbackRequestEnableNotification(ani_env *env, std::shared_ptr<EnableNotificationInfo> info)
{
    ANS_LOGD("enter");
    if (env == nullptr || info == nullptr) return;
    ani_status status;
    int32_t errorCode = info->errorCode ==
        ERR_OK ? ERR_OK : NotificationSts::GetExternalCode(info->errorCode);
    if (errorCode == ERR_OK) {
        ANS_LOGD("Resolve. errorCode %{public}d", errorCode);
        ani_object ret = OHOS::AppExecFwk::createInt(env, errorCode);
        if (ret == nullptr) {
            ANS_LOGD("createInt faild");
            return;
        }
        if (ANI_OK != (status = env->PromiseResolver_Resolve(info->resolver, static_cast<ani_ref>(ret)))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", status);
        }
    } else {
        std::string errMsg = OHOS::NotificationSts::FindAnsErrMsg(errorCode);
        ANS_LOGD("reject. errorCode %{public}d errMsg %{public}s", errorCode, errMsg.c_str());
        ani_error rejection = static_cast<ani_error>(OHOS::AbilityRuntime::CreateStsError(env, errorCode, errMsg));
        if (ANI_OK != (status = env->PromiseResolver_Reject(info->resolver, rejection))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", status);
        }
    }
}

bool CreateUIExtension(std::shared_ptr<EnableNotificationInfo> &info)
{
    ANS_LOGD("enter");
    if (info->context == nullptr) {
        ANS_LOGE("Get context failed");
        return false;
    }
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(info->context);
    if (abilityContext == nullptr) {
        ANS_LOGE("abilityContext is null");
        return false;
    }
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        ANS_LOGE("uiContent is null");
        return false;
    }
    AAFwk::Want want;
    std::string targetBundleName = "com.ohos.notificationdialog";
    std::string targetAbilityName = "EnableNotificationDialog";
    want.SetElementName(targetBundleName, targetAbilityName);
    std::string typeKey = "ability.want.params.uiExtensionType";
    std::string typeValue = "sysDialog/common";
    want.SetParam(typeKey, typeValue);
    auto uiExtCallback = std::make_shared<ModalExtensionCallback>();
    uiExtCallback->SetAbilityContext(abilityContext);
    uiExtCallback->SetBundleName(info->bundleName);
    OHOS::Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        .onRelease = std::bind(&ModalExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        .onResult = std::bind(&ModalExtensionCallback::OnResult, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2),
        .onReceive = std::bind(&ModalExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        .onError = std::bind(&ModalExtensionCallback::OnError, uiExtCallback,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
        .onRemoteReady = std::bind(&ModalExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
        .onDestroy = std::bind(&ModalExtensionCallback::OnDestroy, uiExtCallback),
    };
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ANS_LOGI("Create end, sessionId: %{public}d", sessionId);
    if (sessionId == 0) {
        ANS_LOGE("Create component failed, sessionId is 0");
        return false;
    }
    uiExtCallback->SetSessionId(sessionId);
    return true;
}

void RequestEnableComplete(ani_env *env, std::shared_ptr<EnableNotificationInfo> &info)
{
    ANS_LOGD("enter");
    if (!info->bundleName.empty()) {
        bool success = CreateUIExtension(info);
        if (success) {
            info->errorCode = ERR_ANS_DIALOG_POP_SUCCEEDED;
        } else {
            info->errorCode = ERROR_INTERNAL_ERROR;
            NotificationHelper::RemoveEnableNotificationDialog();
        }
    }
    if (info->errorCode != ERR_ANS_DIALOG_POP_SUCCEEDED) {
        ANS_LOGE("error, code is %{public}d.", info->errorCode);
        StsAsyncCompleteCallbackRequestEnableNotification(env, info);
        return;
    }
    // Dialog is popped
    auto StsCallback = std::make_unique<StsAnsDialogCallback>();
    if (!StsCallback->Init(env, info, StsAsyncCompleteCallbackRequestEnableNotification) ||
        !AnsDialogHostClient::SetDialogCallbackInterface(std::move(StsCallback))
    ) {
        ANS_LOGE("error");
        info->errorCode = ERROR_INTERNAL_ERROR;
        StsAsyncCompleteCallbackRequestEnableNotification(env, info);
        return;
    }
}

ani_object AniRequestEnableNotification(ani_env *env, ani_object content)
{
    ANS_LOGD("enter");
    std::shared_ptr<EnableNotificationInfo> info = std::make_shared<EnableNotificationInfo>();
    if (!GetEnableNotificationInfo(env, content, info)) {
        ANS_LOGD("GetEnableNotificationInfo");
        return nullptr;
    }
    ani_object aniPromise {};
    ani_resolver aniResolver {};
    if (ANI_OK != env->Promise_New(&aniResolver, &aniPromise)) {
        ANS_LOGD("Promise_New faild");
        return nullptr;
    }
    info->resolver = aniResolver;
    RequestEnableExecute(info);
    RequestEnableComplete(env, info);
    ANS_LOGD("RequestEnableNotification done");
    return aniPromise;
}
}
}