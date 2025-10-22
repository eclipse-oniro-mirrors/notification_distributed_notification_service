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
#include "sts_notification_subscriber_extension.h"

#include "ability_manager_client.h"
#include "ans_log_wrapper.h"
#include "notification_subscriber_stub_impl.h"
#include "sts_common.h"
#include "sts_notification_info.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

StsNotificationSubscriberExtension* StsNotificationSubscriberExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new StsNotificationSubscriberExtension(static_cast<ETSRuntime&>(*runtime));
}
StsNotificationSubscriberExtension::StsNotificationSubscriberExtension(ETSRuntime &stsRuntime)
    : stsRuntime_(stsRuntime) {}
StsNotificationSubscriberExtension::~StsNotificationSubscriberExtension()
{
    ANS_LOGD("~StsNotificationSubscriberExtension called");
}

void StsNotificationSubscriberExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    if (record == nullptr) {
        ANS_LOGE("record null");
        return;
    }
    NotificationSubscriberExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_ == nullptr || Extension::abilityInfo_->srcEntrance.empty()) {
        ANS_LOGE("NotificationSubscriberExtension Init abilityInfo error");
        return;
    }
    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    auto pos = srcPath.rfind(".");
    if (pos != std::string::npos) {
        srcPath.erase(pos);
        srcPath.append(".abc");
    }
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    stsObj_ = stsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, abilityInfo_->srcEntrance);
    if (stsObj_ == nullptr) {
        ANS_LOGE("stsObj_ null");
        return;
    }

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        ANS_LOGE("null env");
        return;
    }
    BindContext(env, application);
    return;
}

void StsNotificationSubscriberExtension::BindContext(ani_env* env, const std::shared_ptr<OHOSApplication> &application)
{
    ANS_LOGD("StsNotificationSubscriberExtension BindContext Call");
    auto context = GetContext();
    if (context == nullptr) {
        ANS_LOGE("Failed to get context");
        return;
    }

    ani_object contextObj = CreateSTSContext(env, context, application);
    if (contextObj == nullptr) {
        ANS_LOGE("null contextObj");
        return;
    }

    ani_field contextField;
    auto status = env->Class_FindField(stsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        ANS_LOGE("Class_GetField context failed");
        ResetEnv(env);
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        ANS_LOGE("GlobalReference_Create contextObj failed");
        return;
    }
    if (env->Object_SetField_Ref(stsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        ANS_LOGE("Object_SetField_Ref contextObj failed");
        ResetEnv(env);
    }
}

ani_object StsNotificationSubscriberExtension::CreateSTSContext(ani_env* env,
    std::shared_ptr<NotificationSubscriberExtensionContext> context,
    const std::shared_ptr<OHOSApplication> &application)
{
    ani_object STSContext = CreateNotificationSubscriberExtensionContext(env, context, application);
    return STSContext;
}

std::weak_ptr<StsNotificationSubscriberExtension> StsNotificationSubscriberExtension::GetWeakPtr()
{
    return std::static_pointer_cast<StsNotificationSubscriberExtension>(shared_from_this());
}

void StsNotificationSubscriberExtension::OnDestroy()
{
    ANS_LOGD("OnDestroy called");

    ani_env* env = stsRuntime_.GetAniEnv();
    if (!env) {
        ANS_LOGE("task env not found env");
        return;
    }

    ani_object ani_data {};
    const char* signature  = "V:V";
    CallObjectMethod(false, "onDestroy", signature, ani_data);
}

void StsNotificationSubscriberExtension::OnReceiveMessage(const std::shared_ptr<NotificationInfo> info)
{
    ANS_LOGD("OnReceiveMessage called");
    if (info == nullptr) {
        ANS_LOGE("info is invalid");
        return;
    }
    if (handler_ == nullptr) {
        ANS_LOGE("handler is invalid");
        return;
    }
    std::weak_ptr<StsNotificationSubscriberExtension> wThis = GetWeakPtr();
    auto task = [wThis, info, this]() {
        std::shared_ptr<StsNotificationSubscriberExtension> sThis = wThis.lock();
        if (sThis == nullptr) {
            return;
        }
        ani_env* env = sThis->stsRuntime_.GetAniEnv();
        if (!env) {
            ANS_LOGE("task env not found env");
            return;
        }

        ani_object ani_info = WrapNotificationInfo(env, info);
        if (ani_info == nullptr) {
            ANS_LOGW("WrapNotificationInfo failed");
        }
        const char* signature  = "Lnotification/notificationInfo/NotificationInfoInner;:V";
        CallObjectMethod(false, "onReceiveMessage", signature, ani_info);
    };
    handler_->PostTask(task, "OnReceiveMessage");
}


void StsNotificationSubscriberExtension::OnCancelMessages(const std::shared_ptr<std::vector<std::string>> hashCodes)
{
    ANS_LOGD("OnCancelMessages called");
    if (hashCodes == nullptr) {
        ANS_LOGE("info is invalid");
        return;
    }
    if (handler_ == nullptr) {
        ANS_LOGE("handler is invalid");
        return;
    }
    std::weak_ptr<StsNotificationSubscriberExtension> wThis = GetWeakPtr();
    auto task = [wThis, hashCodes, this]() {
        std::shared_ptr<StsNotificationSubscriberExtension> sThis = wThis.lock();
        if (sThis == nullptr) {
            return;
        }
        ani_env* env = sThis->stsRuntime_.GetAniEnv();
        if (!env) {
            ANS_LOGE("task env not found env");
            return;
        }

        ani_object aniObject {};
        ani_object aniArray = GetAniStringArrayByVectorString(env, *hashCodes);
        if (aniArray == nullptr) {
            ANS_LOGE("aniArray is nullptr");
            return;
        }
        if (!SetPropertyByRef(env, aniObject, "hashCodes", aniArray)) {
            ANS_LOGE("Set names failed");
            return;
        }
        const char* signature  = "Lstd/core/Object;:V";
        CallObjectMethod(false, "onCancelMessages", signature, aniObject);
    };
    handler_->PostTask(task, "OnCancelMessages");
}

void StsNotificationSubscriberExtension::ResetEnv(ani_env* env)
{
    env->DescribeError();
    env->ResetError();
}

void StsNotificationSubscriberExtension::OnStart(const AAFwk::Want& want)
{
    ANS_LOGD("%{public}s called.", __func__);
    Extension::OnStart(want);
}

void StsNotificationSubscriberExtension::OnStop()
{
    ANS_LOGD("%{public}s called.", __func__);
    OnDestroy();
    Extension::OnStop();
}

void StsNotificationSubscriberExtension::OnDisconnect(const AAFwk::Want& want)
{
    ANS_LOGD("%{public}s called.", __func__);
    Extension::OnDisconnect(want);
}

sptr<IRemoteObject> StsNotificationSubscriberExtension::OnConnect(const AAFwk::Want& want)
{
    ANS_LOGD("%{public}s called.", __func__);
    Extension::OnConnect(want);
    sptr<NotificationSubscriberStubImpl> remoteObject = new (std::nothrow) NotificationSubscriberStubImpl(
        std::static_pointer_cast<StsNotificationSubscriberExtension>(shared_from_this()));
    if (remoteObject == nullptr) {
        ANS_LOGE("failed to create NotificationSubscriberStubImpl");
        return nullptr;
    }
    return remoteObject->AsObject();
}

void StsNotificationSubscriberExtension::CallObjectMethod(
    bool withResult, const char *name, const char *signature, ...)
{
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        ANS_LOGE("env not found StsNotificationSubscriberExtensions");
        return;
    }
    if (stsObj_ == nullptr) {
        ANS_LOGE("stsObj_ nullptr");
        return;
    }
    if ((status = env->Class_FindMethod(stsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        ANS_LOGE("Class_FindMethod nullptr:%{public}d", status);
        return;
    }
    if (method == nullptr) {
        return;
    }

    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(stsObj_->aniObj, method, &res, args)) != ANI_OK) {
            ANS_LOGE("status : %{public}d", status);
        }
        va_end(args);
        return;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(stsObj_->aniObj, method, args)) != ANI_OK) {
        ANS_LOGE("status : %{public}d", status);
    }
    va_end(args);
    return;
}
}
}