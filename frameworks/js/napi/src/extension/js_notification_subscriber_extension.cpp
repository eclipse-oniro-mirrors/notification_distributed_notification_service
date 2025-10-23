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

#include "js_notification_subscriber_extension.h"
#include <memory>

#include "ability_info.h"
#include "ability_handler.h"
#include "ans_log_wrapper.h"
#include "common_convert_notification_info.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_notification_subscriber_extension_context.h"
#include "napi_common_want.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_remote_object.h"
#include "notification_subscriber_stub_impl.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
}

using namespace OHOS::AppExecFwk;

napi_value AttachNotificationSubscriberExtensionContext(napi_env env, void* value, void*)
{
    ANS_LOGD("AttachNotificationSubscriberExtensionContext");
    if (value == nullptr) {
        ANS_LOGE("invalid parameter.");
        return nullptr;
    }

    auto ptr = reinterpret_cast<std::weak_ptr<NotificationSubscriberExtensionContext>*>(value)->lock();
    if (ptr == nullptr) {
        ANS_LOGE("invalid context.");
        return nullptr;
    }

    napi_value object = CreateJsNotificationSubscriberExtensionContext(env, ptr);
    auto napiContextObj = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(env,
        "application.NotificationSubscriberExtensionContext", &object, 1)->GetNapiValue();
    if (napiContextObj == nullptr) {
        ANS_LOGE("load context failed.");
        return nullptr;
    }
    napi_coerce_to_native_binding_object(env, napiContextObj, AbilityRuntime::DetachCallbackFunc,
        AttachNotificationSubscriberExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<NotificationSubscriberExtensionContext>(ptr);
    if (workContext == nullptr) {
        ANS_LOGE("invalid NotificationSubscriberExtensionContext.");
        return nullptr;
    }
    napi_wrap(env, napiContextObj, workContext,
        [](napi_env, void* data, void*) {
            ANS_LOGI("Finalizer for weak_ptr notification subscriber extension context is called");
            delete static_cast<std::weak_ptr<NotificationSubscriberExtensionContext>*>(data);
        }, nullptr, nullptr);
    return napiContextObj;
}

JsNotificationSubscriberExtension* JsNotificationSubscriberExtension::Create(
    const std::unique_ptr<AbilityRuntime::Runtime>& runtime)
{
    return new (std::nothrow) JsNotificationSubscriberExtension(static_cast<AbilityRuntime::JsRuntime&>(*runtime));
}

JsNotificationSubscriberExtension::JsNotificationSubscriberExtension(AbilityRuntime::JsRuntime& jsRuntime)
    : jsRuntime_(jsRuntime) {}
JsNotificationSubscriberExtension::~JsNotificationSubscriberExtension()
{
    ANS_LOGD("Js notification subscriber extension destructor.");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }

    jsRuntime_.FreeNativeReference(std::move(jsObj_));
}

void JsNotificationSubscriberExtension::Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
    const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
    std::shared_ptr<AppExecFwk::AbilityHandler>& handler,
    const sptr<IRemoteObject>& token)
{
    NotificationSubscriberExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_->srcEntrance.empty()) {
        ANS_LOGE("srcEntrance of abilityInfo is empty");
        return;
    }

    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    srcPath.erase(srcPath.rfind('.'));
    srcPath.append(".abc");

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    ANS_LOGD("moduleName: %{public}s, srcPath: %{public}s.", moduleName.c_str(), srcPath.c_str());
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        ANS_LOGE("Failed to load module");
        return;
    }
    napi_value obj = jsObj_->GetNapiValue();
    if (obj == nullptr) {
        ANS_LOGE("Failed to get notification subscriber extension object");
        return;
    }
    ExecNapiWrap(env, obj);
}

void JsNotificationSubscriberExtension::ExecNapiWrap(napi_env env, napi_value obj)
{
    auto context = GetContext();
    if (context == nullptr) {
        ANS_LOGE("Failed to get context");
        return;
    }

    napi_value contextObj = CreateJsNotificationSubscriberExtensionContext(env, context);
    auto shellContextRef = AbilityRuntime::JsRuntime::LoadSystemModuleByEngine(
        env, "application.NotificationSubscriberExtensionContext", &contextObj, ARGC_ONE);
    if (shellContextRef == nullptr) {
        ANS_LOGE("Failed to get shell context reference");
        return;
    }
    napi_value nativeObj = shellContextRef->GetNapiValue();
    if (nativeObj == nullptr) {
        ANS_LOGE("Failed to get context native object");
        return;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<NotificationSubscriberExtensionContext>(context);
    if (workContext == nullptr) {
        ANS_LOGE("invalid NotificationSubscriberExtensionContext.");
        return;
    }
    napi_coerce_to_native_binding_object(env, nativeObj, AbilityRuntime::DetachCallbackFunc,
        AttachNotificationSubscriberExtensionContext, workContext, nullptr);
    context->Bind(jsRuntime_, shellContextRef.release());
    napi_set_named_property(env, obj, "context", nativeObj);

    ANS_LOGD("Set notification subscriber extension context");
    napi_wrap(env, nativeObj, workContext,
        [](napi_env, void* data, void*) {
        ANS_LOGI("Finalizer for weak_ptr notification subscriber extension context is called");
        delete static_cast<std::weak_ptr<NotificationSubscriberExtensionContext>*>(data);
        }, nullptr, nullptr);

    ANS_LOGI("Init end.");
}

void JsNotificationSubscriberExtension::OnStart(const AAFwk::Want& want)
{
    ANS_LOGD("called");
    Extension::OnStart(want);
}

void JsNotificationSubscriberExtension::OnStop()
{
    ANS_LOGD("called");
    OnDestroy();
    Extension::OnStop();
}

sptr<IRemoteObject> JsNotificationSubscriberExtension::OnConnect(const AAFwk::Want& want)
{
    ANS_LOGD("called");
    Extension::OnConnect(want);
    sptr<NotificationSubscriberStubImpl> remoteObject = new (std::nothrow) NotificationSubscriberStubImpl(
        std::static_pointer_cast<JsNotificationSubscriberExtension>(shared_from_this()));
    if (remoteObject == nullptr) {
        ANS_LOGE("failed to create NotificationSubscriberStubImpl!");
        return nullptr;
    }
    return remoteObject->AsObject();
}

void JsNotificationSubscriberExtension::OnDisconnect(const AAFwk::Want& want)
{
    ANS_LOGD("called");
    Extension::OnDisconnect(want);
}

std::weak_ptr<JsNotificationSubscriberExtension> JsNotificationSubscriberExtension::GetWeakPtr()
{
    return std::static_pointer_cast<JsNotificationSubscriberExtension>(shared_from_this());
}

void JsNotificationSubscriberExtension::OnDestroy()
{
    ANS_LOGD("OnDestroy");

    if (!jsObj_) {
        ANS_LOGE("Not found NotificationSubscriberExtension.js");
        return;
    }

    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();

    napi_value argv[] = {};
    napi_value obj = jsObj_->GetNapiValue();
    if (obj == nullptr) {
        ANS_LOGE("Failed to get NotificationSubscriberExtension object");
        return;
    }

    napi_value method = nullptr;
    napi_get_named_property(env, obj, "onDestroy", &method);
    if (method == nullptr) {
        ANS_LOGE("Failed to get onDestroy from NotificationSubscriberExtension object");
        return;
    }
    napi_call_function(env, obj, method, ARGC_ZERO, argv, nullptr);
    ANS_LOGD("JsNotificationSubscriberExtension js receive event called.");
}

void JsNotificationSubscriberExtension::OnReceiveMessage(const std::shared_ptr<NotificationInfo> info)
{
    ANS_LOGD("called");
    if (info == nullptr) {
        ANS_LOGE("handler is invalid");
        return;
    }
    if (handler_ == nullptr) {
        ANS_LOGE("handler is invalid");
        return;
    }
    std::weak_ptr<JsNotificationSubscriberExtension> wThis = GetWeakPtr();

    auto task = [wThis, info]() {
        std::shared_ptr<JsNotificationSubscriberExtension> sThis = wThis.lock();
        if (sThis == nullptr) {
            return;
        }
        if (!sThis->jsObj_) {
            ANS_LOGE("Not found NotificationSubscriberExtension.js");
            return;
        }

        AbilityRuntime::HandleScope handleScope(sThis->jsRuntime_);
        napi_env env = sThis->jsRuntime_.GetNapiEnv();
        napi_value napiInfo = nullptr;
        napi_create_object(env, &napiInfo);

        if (!SetNotificationInfo(env, info, napiInfo)) {
            ANS_LOGE("Set NotificationInfo object failed.");
            return;
        }

        napi_value argv[] = {napiInfo};
        napi_value obj = sThis->jsObj_->GetNapiValue();
        if (obj == nullptr) {
            ANS_LOGE("Failed to get NotificationSubscriberExtension object");
            return;
        }

        napi_value method = nullptr;
        napi_get_named_property(env, obj, "onReceiveMessage", &method);
        if (method == nullptr) {
            ANS_LOGE("Failed to get onReceiveMessage from NotificationSubscriberExtension object");
            return;
        }
        napi_call_function(env, obj, method, ARGC_ONE, argv, nullptr);
        ANS_LOGD("JsNotificationSubscriberExtension js receive event called.");
    };
    handler_->PostTask(task, "OnReceiveMessage");
}

void JsNotificationSubscriberExtension::OnCancelMessages(const std::shared_ptr<std::vector<std::string>> hashCodes)
{
    ANS_LOGD("called");
    if (hashCodes == nullptr) {
        ANS_LOGE("hashCodes is invalid");
        return;
    }
    if (handler_ == nullptr) {
        ANS_LOGE("handler is invalid");
        return;
    }
    std::weak_ptr<JsNotificationSubscriberExtension> wThis = GetWeakPtr();

    auto task = [wThis, hashCodes]() {
        std::shared_ptr<JsNotificationSubscriberExtension> sThis = wThis.lock();
        if (sThis == nullptr) {
            return;
        }
        if (!sThis->jsObj_) {
            ANS_LOGE("Not found NotificationSubscriberExtension.js");
            return;
        }

        AbilityRuntime::HandleScope handleScope(sThis->jsRuntime_);
        napi_env env = sThis->jsRuntime_.GetNapiEnv();
        napi_value result = sThis->CreateOnCancelMessagesResult(env, hashCodes);
        napi_value argv[] = {result};
        napi_value obj = sThis->jsObj_->GetNapiValue();
        if (obj == nullptr) {
            ANS_LOGE("Failed to get NotificationSubscriberExtension object");
            return;
        }

        napi_value method = nullptr;
        napi_get_named_property(env, obj, "onCancelMessages", &method);
        if (method == nullptr) {
            ANS_LOGE("Failed to get onCancelMessages from NotificationSubscriberExtension object");
            return;
        }
        napi_call_function(env, obj, method, ARGC_ONE, argv, nullptr);
        ANS_LOGD("JsNotificationSubscriberExtension js receive event called.");
    };
    handler_->PostTask(task, "OnCancelMessages");
}

napi_value JsNotificationSubscriberExtension::CreateOnCancelMessagesResult(
    napi_env env, const std::shared_ptr<std::vector<std::string>> hashCodes)
{
    napi_value result = nullptr;
    napi_create_array(env, &result);
    uint32_t count = 0;
    for (auto vec : *hashCodes) {
        napi_value vecValue = nullptr;
        ANS_LOGD("hashCodes = %{public}s", vec.c_str());
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &vecValue);
        napi_set_element(env, result, count, vecValue);
        count++;
    }
    return result;
}
}  // namespace NotificationNapi
}  // namespace OHOS