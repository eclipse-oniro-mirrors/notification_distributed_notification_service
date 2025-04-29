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
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr uint32_t ERR_INVOKE_PUSHCHECK_PROMISE = 1;
} // namespace

JSPushCallBack::JSPushCallBack(napi_env env) : env_(env) {}

JSPushCallBack::~JSPushCallBack() {}

void JSPushCallBack::SetJsPushCallBackObject(NotificationConstant::SlotType slotType, napi_value pushCallBackObject)
{
    napi_ref pushCheckObject;
    napi_create_reference(env_, pushCallBackObject, 1, &pushCheckObject);
    pushCallBackObjects_.insert_or_assign(slotType, pushCheckObject);
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

void CallBackReturn(const int32_t ret, const std::weak_ptr<PushCallBackParam> pushCallBackParam)
{
    auto callBackParam = pushCallBackParam.lock();
    if (callBackParam == nullptr) {
        ANS_LOGI("Push callback param has been released");
        return;
    }

    std::unique_lock<std::mutex> uniqueLock(callBackParam->callBackMutex);
    callBackParam->result = ret;
    callBackParam->ready = true;
    callBackParam->callBackCondition.notify_all();
}

napi_value JSPushCallBack::CheckPromiseCallback(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    if (info == nullptr) {
        ANS_LOGE("CheckPromiseCallback, invalid input info");
        return nullptr;
    }

    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    void *data;

    napi_get_cb_info(env, info, &argc, &argv[0], nullptr, &data);
    int32_t ret = ConvertFunctionResult(env, argv[0]);

    auto *callbackInfo = static_cast<PromiseCallbackInfo *>(data);
    CallBackReturn(ret, callbackInfo->GetJsCallBackParam());

    PromiseCallbackInfo::Destroy(callbackInfo);
    callbackInfo = nullptr;
    return nullptr;
}

int32_t JSPushCallBack::OnCheckNotification(
    const std::string &notificationData, const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    AbilityRuntime::HandleEscape handleEscape(env_);

    std::string pkgName;
    auto checkInfo = std::make_shared<NotificationCheckInfo>();
    checkInfo->ConvertJsonStringToValue(notificationData);

    NotificationConstant::SlotType outSlotType = static_cast<NotificationConstant::SlotType>(checkInfo->GetSlotType());
    if (pushCallBackObjects_.find(outSlotType) == pushCallBackObjects_.end()) {
        ANS_LOGE("pushCallBackObjects is nullptr");
        return ERR_INVALID_STATE;
    }

    napi_value checkFunc = nullptr;
    napi_get_reference_value(env_, pushCallBackObjects_[outSlotType], &checkFunc);
    if (checkFunc == nullptr) {
        ANS_LOGE("Failed to get checkFunc value");
        return ERR_INVALID_STATE;
    }
    napi_value jsResult = nullptr;
    napi_create_object(env_, &jsResult);

    NotificationNapi::SlotType slotType;
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(checkInfo->GetContentType()), contentType);
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(
        static_cast<NotificationConstant::SlotType>(checkInfo->GetSlotType()), slotType);
    SetJsPropertyString("bundleName", checkInfo->GetPkgName(), jsResult);
    SetJsPropertyInt32("notificationId", checkInfo->GetNotifyId(), jsResult);
    SetJsPropertyInt32("contentType", static_cast<int32_t>(contentType), jsResult);
    SetJsPropertyInt32("creatorUserId", checkInfo->GetCreatorUserId(), jsResult);
    SetJsPropertyInt32("slotType", static_cast<int32_t>(slotType), jsResult);
    SetJsPropertyString("label", checkInfo->GetLabel(), jsResult);
    SetJsPropertyWantParams("extraInfos", checkInfo->GetExtraInfo(), jsResult);

    napi_value funcResult;
    napi_value argv[] = { jsResult };

    napi_value resultOut = nullptr;
    napi_call_function(env_, nullptr, checkFunc, ARGC_ONE, &argv[0], &resultOut);
    funcResult = handleEscape.Escape(resultOut);

    bool isPromise = false;
    napi_is_promise(env_, funcResult, &isPromise);
    if (!isPromise) {
        ANS_LOGE("Notificaiton check function is not promise.");
        return ERR_INVALID_STATE;
    }

    HandleCheckPromise(funcResult, pushCallBackParam);
    return ERR_OK;
}

void JSPushCallBack::HandleCheckPromise(
    napi_value funcResult, const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    napi_value promiseThen = nullptr;
    napi_value promiseCatch = nullptr;
    napi_get_named_property(env_, funcResult, "then", &promiseThen);
    napi_get_named_property(env_, funcResult, "catch", &promiseCatch);

    bool isCallable = false;
    napi_is_callable(env_, promiseThen, &isCallable);
    if (!isCallable) {
        ANS_LOGE("HandleCheckPromise property then is not callable.");
        return;
    }
    napi_is_callable(env_, promiseCatch, &isCallable);
    if (!isCallable) {
        ANS_LOGE("HandleCheckPromise property catch is not callable.");
        return;
    }

    napi_value checkPromiseCallback;
    auto *callbackInfo = PromiseCallbackInfo::Create(pushCallBackParam);
    napi_create_function(env_, "checkPromiseCallback", strlen("checkPromiseCallback"), CheckPromiseCallback,
        callbackInfo, &checkPromiseCallback);

    napi_status status;
    napi_value argvPromise[ARGC_ONE] = { checkPromiseCallback };

    status = napi_call_function(env_, funcResult, promiseThen, ARGC_ONE, argvPromise, nullptr);
    if (status != napi_ok) {
        ANS_LOGE("Invoke pushCheck promise then error.");
        PromiseCallbackInfo::Destroy(callbackInfo);
        return CallBackReturn(ERR_INVOKE_PUSHCHECK_PROMISE, pushCallBackParam);
    }

    status = napi_call_function(env_, funcResult, promiseCatch, ARGC_ONE, argvPromise, nullptr);
    if (status != napi_ok) {
        ANS_LOGE("Invoke pushCheck promise catch error.");
        PromiseCallbackInfo::Destroy(callbackInfo);
        return CallBackReturn(ERR_INVOKE_PUSHCHECK_PROMISE, pushCallBackParam);
    }

    return;
}

int32_t JSPushCallBack::ConvertFunctionResult(napi_env env, napi_value funcResult)
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

    ANS_LOGI("code:%{public}d, message:%{public}s", code, message.c_str());
    return code;
}
} // namespace Notification
} // namespace OHOS
