/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "napi_push_callback.h"
#include "common.h"

#include "ans_log_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "nlohmann/json.hpp"
#include "notification_check_info.h"
#include "napi_common_want.h"
#include "napi_common_util.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t ARGC_ONE = 1;
} // namespace

int32_t JSPushCallBack::checkResult_;

JSPushCallBack::JSPushCallBack(napi_env env) : env_(env) {}

JSPushCallBack::~JSPushCallBack() {}

void JSPushCallBack::SetJsPushCallBackObject(napi_value pushCallBackObject)
{
    napi_create_reference(env_, pushCallBackObject, 1, &pushCallBackObject_);
}

bool JSPushCallBack::IsEqualPushCallBackObject(napi_value pushCallBackObject)
{
    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return false;
    }
    napi_value value = nullptr;
    napi_get_reference_value(env_, pushCallBackObject_, &value);
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return false;
    }

    bool isEquals = false;
    napi_strict_equals(env_, value, pushCallBackObject, &isEquals);
    return isEquals;
}

void JSPushCallBack::SetJsPropertyString(std::string key, std::string value, napi_value& jsResult)
{
    napi_value keyNapiValue = nullptr;
    napi_value valueNapiValue = nullptr;
    napi_create_string_utf8(env_, key.c_str(), key.length(), &keyNapiValue);
    napi_create_string_utf8(env_, value.c_str(), value.length(), &valueNapiValue);
    napi_set_property(env_, jsResult, keyNapiValue, valueNapiValue);
}

void JSPushCallBack::SetJsPropertyInt32(std::string key, int32_t value, napi_value& jsResult)
{
    napi_value keyNapiValue = nullptr;
    napi_value valueNapiValue = nullptr;
    napi_create_string_utf8(env_, key.c_str(), key.length(), &keyNapiValue);
    napi_create_int32(env_, value, &valueNapiValue);
    napi_set_property(env_, jsResult, keyNapiValue, valueNapiValue);
}

void JSPushCallBack::SetJsPropertyWantParams(
    std::string key, std::shared_ptr<AAFwk::WantParams> wantParams, napi_value& jsResult)
{
    napi_value keyNapiValue = nullptr;
    napi_create_string_utf8(env_, key.c_str(), key.length(), &keyNapiValue);
    if (wantParams) {
        napi_value extraInfo = nullptr;
        extraInfo = OHOS::AppExecFwk::WrapWantParams(env_, *wantParams);
        napi_set_property(env_, jsResult, keyNapiValue, extraInfo);
    }
}

int32_t JSPushCallBack::OnCheckNotification(const std::string &notificationData)
{
    AbilityRuntime::HandleEscape handleEscape(env_);
    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return checkResult_;
    }

    napi_value value = nullptr;
    napi_get_reference_value(env_, pushCallBackObject_, &value);
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return checkResult_;
    }

    std::string pkgName;
    auto checkInfo = new (std::nothrow) NotificationCheckInfo {};
    checkInfo->ConvertJsonStringToValue(notificationData);

    napi_value jsResult = nullptr;
    napi_create_object(env_, &jsResult);

    NotificationNapi::SlotType slotType;
    NotificationNapi::ContentType contentType;
    NotificationNapi::Common::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(checkInfo->GetContentType()), contentType);
    NotificationNapi::Common::SlotTypeCToJS(
        static_cast<NotificationConstant::SlotType>(checkInfo->GetSlotType()), slotType);
    SetJsPropertyString("bundleName", checkInfo->GetPkgName(), jsResult);
    SetJsPropertyInt32("notificationKey", checkInfo->GetNotifyId(), jsResult);
    SetJsPropertyInt32("contentType", static_cast<int32_t>(contentType), jsResult);
    SetJsPropertyInt32("creatorUserId", checkInfo->GetCreatorUserId(), jsResult);
    SetJsPropertyInt32("slotType", static_cast<int32_t>(slotType), jsResult);
    SetJsPropertyString("label", checkInfo->GetLabel(), jsResult);
    SetJsPropertyWantParams("extraInfos", checkInfo->GetExtraInfo(), jsResult);

    napi_value funcResult;
    napi_value argv[] = { jsResult };

    napi_value resultOut = nullptr;
    napi_call_function(env_, value, value, ARGC_ONE, &argv[0], &resultOut);
    funcResult = handleEscape.Escape(resultOut);

    bool isPromise = false;
    napi_is_promise(env_, funcResult, &isPromise);
    if (!isPromise) {
        ANS_LOGE("Notificaiton check function is not promise.");
        return checkResult_;
    }

    return HandleCheckPromise(funcResult);
}

int32_t JSPushCallBack::HandleCheckPromise(napi_value funcResult)
{
    napi_value promiseThen = nullptr;
    napi_get_named_property(env_, funcResult, "then", &promiseThen);

    bool isCallable = false;
    napi_is_callable(env_, promiseThen, &isCallable);
    if (!isCallable) {
        ANS_LOGE("HandleCheckPromise property then is not callable.");
        return checkResult_;
    }

    napi_value checkPromiseCallback;
    napi_create_function(env_, "checkPromiseCallback", strlen("checkPromiseCallback"), CheckPromiseCallback,
        nullptr, &checkPromiseCallback);

    napi_call_function(env_, funcResult, promiseThen, ARGC_ONE, &checkPromiseCallback, nullptr);
    return checkResult_;
}

napi_value JSPushCallBack::CheckPromiseCallback(napi_env env, napi_callback_info info)
{
    if (info == nullptr) {
        ANS_LOGE("CheckPromiseCallback, invalid input info.");
        return nullptr;
    }
    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    napi_get_cb_info(env, info, &argc, &argv[0], nullptr, nullptr);
    if (!ConvertFunctionResult(env, argv[0])) {
        ANS_LOGE("ConvertFunctionResult failed.");
    };
    return nullptr;
}

bool JSPushCallBack::ConvertFunctionResult(napi_env env, napi_value funcResult)
{
    if (funcResult == nullptr) {
        ANS_LOGE("The funcResult is error.");
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, funcResult, &valueType), false);
    if (valueType != napi_object) {
        ANS_LOGE("The funcResult is not napi_object.");
        return false;
    }
    if (AppExecFwk::IsExistsByPropertyName(env, funcResult, "code") == false) {
        ANS_LOGE("GetProperty code failed.");
        return false;
    }

    napi_value codeValue = nullptr;
    napi_valuetype codeType = napi_undefined;
    napi_get_named_property(env, funcResult, "code", &codeValue);
    NAPI_CALL_BASE(env, napi_typeof(env, codeValue, &codeType), false);

    if (codeType != napi_number) {
        ANS_LOGE("GetProperty code failed. Number expected.");
        return false;
    }
    int32_t code = -1;
    if (!AbilityRuntime::ConvertFromJsValue(env, codeValue, code)) {
        ANS_LOGE("Parse code failed.");
        return false;
    }

    bool hasMessageProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, funcResult, "message", &hasMessageProperty), false);
    if (!hasMessageProperty) {
        ANS_LOGE("Property message expected.");
        return false;
    }

    napi_value messageValue = nullptr;
    napi_valuetype messageType = napi_undefined;
    napi_get_named_property(env, funcResult, "message", &messageValue);
    NAPI_CALL_BASE(env, napi_typeof(env, messageValue, &messageType), false);

    if (messageType != napi_string) {
        ANS_LOGE("GetProperty message failed. String expected.");
        return false;
    }

    std::string message;
    if (!AbilityRuntime::ConvertFromJsValue(env, messageValue, message)) {
        ANS_LOGE("Parse message failed.");
        return false;
    }

    ANS_LOGI("code : %{public}d ,message : %{public}s", code, message.c_str());
    checkResult_ = code;
    return true;
}
} // namespace Notification
} // namespace OHOS
