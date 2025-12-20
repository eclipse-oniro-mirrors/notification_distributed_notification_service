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

#include "reminder/reminder_state_listener.h"
#include "reminder/reminder_common.h"

#include "common.h"
#include "napi_common.h"
#include "reminder_helper.h"

namespace OHOS::ReminderAgentNapi {
using namespace Notification;

static constexpr const char* REMINDER_STATE_REMINDER_ID = "reminderId";
static constexpr const char* REMINDER_STATE_BUTTON_TYPE = "buttonType";
static constexpr const char* REMINDER_STATE_IS_RESEND = "isMessageResend";
static constexpr size_t ARG_COUNT_ONE = 1;
struct CallBackContext {
    napi_env env {nullptr};
    std::shared_ptr<NativeReference> callbackRef {nullptr};
    OnReminderStateCb onReminderStateCb {nullptr};
    std::vector<ReminderState> states;
};

JsReminderStateCallback::JsReminderStateCallback(napi_env env, napi_value callbackObj, OnReminderStateCb callback)
    : napiEnv_(env), reminderStateCb_(callback)
{
    if (napiEnv_ == nullptr || callbackObj == nullptr) {
        return;
    }
    napi_ref tmpRef = nullptr;
    napi_create_reference(napiEnv_, callbackObj, 1, &tmpRef);
    callbackRef_.reset(reinterpret_cast<NativeReference*>(tmpRef));
    napi_value callbackWorkName  = nullptr;
    napi_create_string_utf8(env, "ThreadSafeFunction in JsReminderStateCallback", NAPI_AUTO_LENGTH, &callbackWorkName);
    napi_create_threadsafe_function(env, nullptr, nullptr, callbackWorkName, 0, 1, nullptr, nullptr, nullptr,
        ThreadSafeCallBack, &threadSafeFunction_);
}

void JsReminderStateCallback::OnReminderState(const std::vector<ReminderState>& states)
{
    if (napiEnv_ == nullptr || callbackRef_ == nullptr || reminderStateCb_ == nullptr) {
        return;
    }
    CallBackContext* callBackContext = new CallBackContext();
    callBackContext->env = napiEnv_;
    callBackContext->callbackRef = callbackRef_;
    callBackContext->states = states;
    callBackContext->onReminderStateCb = reminderStateCb_;
    napi_acquire_threadsafe_function(threadSafeFunction_);
    napi_status status = napi_call_threadsafe_function(threadSafeFunction_, callBackContext, napi_tsfn_blocking);
    if (status != napi_ok) {
        ANSR_LOGE("napi_call failed %{public}d", status);
        delete callBackContext;
        napi_release_threadsafe_function(threadSafeFunction_, napi_threadsafe_function_release_mode::napi_tsfn_release);
    }
}

void JsReminderStateCallback::ThreadSafeCallBack(napi_env env, napi_value jsCb, void* context, void* data)
{
    ANSR_LOGI("ThreadSafeCallBack start");
    CallBackContext* callBackContext = reinterpret_cast<CallBackContext*>(data);
    callBackContext->onReminderStateCb(callBackContext->env,
        callBackContext->callbackRef->GetNapiValue(), callBackContext->states);
    delete callBackContext;
}

JsReminderStateListener::~JsReminderStateListener()
{
    std::lock_guard<std::mutex> locker(jsCallBackListMutex_);
    jsCallBackList_.clear();
}

JsReminderStateListener& JsReminderStateListener::GetInstance()
{
    static JsReminderStateListener instance;
    return instance;
}

napi_value JsReminderStateListener::RegisterReminderStateCallback(napi_env env, napi_callback_info info)
{
    napi_value jsCallback = nullptr;
    if (!CheckCallbackParam(env, info, &jsCallback, true)) {
        ANSR_LOGE("Register reminder state callback parameter error.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
        return nullptr;
    }

    napi_ref tempRef = nullptr;
    napi_create_reference(env, jsCallback, 1, &tempRef);
    std::unique_ptr<NativeReference> callbackRef;
    callbackRef.reset(reinterpret_cast<NativeReference*>(tempRef));
    std::lock_guard<std::mutex> locker(jsCallBackListMutex_);
    for (auto iter = jsCallBackList_.begin(); iter != jsCallBackList_.end(); iter++) {
        bool isEqual = false;
        napi_strict_equals(env, jsCallback, iter->first->GetNapiValue(), &isEqual);
        if (isEqual) {
            ANSR_LOGI("Register a exist callback.");
            return NotificationNapi::Common::NapiGetNull(env);
        }
    }
    auto reminderStateCb = [](napi_env env, napi_value callbackObj, std::vector<ReminderState> states) {
        JsReminderStateListener::GetInstance().OnReminderState(env, callbackObj, states);
    };
    sptr<JsReminderStateCallback> callback =
        new (std::nothrow) JsReminderStateCallback(env, jsCallback, reminderStateCb);
    if (callback == nullptr) {
        ANSR_LOGW("Register callback is nullptr.");
        return NotificationNapi::Common::NapiGetNull(env);
    }
    int32_t ret = ReminderHelper::RegisterReminderState(callback);
    if (ret != ERR_OK) {
        ReminderCommon::HandleErrCode(env, ret);
    } else {
        jsCallBackList_.emplace_back(std::move(callbackRef), callback);
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

napi_value JsReminderStateListener::UnRegisterReminderStateCallback(napi_env env, napi_callback_info info)
{
    napi_value jsCallback = nullptr;
    if (!CheckCallbackParam(env, info, &jsCallback, false)) {
        ANSR_LOGE("UnRegister reminder state callback parameter error.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
        return nullptr;
    }

    std::lock_guard<std::mutex> locker(jsCallBackListMutex_);
    if (jsCallback == nullptr) {
        for (auto iter = jsCallBackList_.begin(); iter != jsCallBackList_.end(); iter++) {
            ReminderHelper::UnRegisterReminderState(iter->second);
        }
        jsCallBackList_.clear();
        return NotificationNapi::Common::NapiGetNull(env);
    }
    bool isEqual = false;
    for (auto iter = jsCallBackList_.begin(); iter != jsCallBackList_.end(); iter++) {
        isEqual = false;
        napi_strict_equals(env, jsCallback, iter->first->GetNapiValue(), &isEqual);
        if (isEqual) {
            ReminderHelper::UnRegisterReminderState(iter->second);
            jsCallBackList_.erase(iter);
            break;
        }
    }
    if (!isEqual) {
        ANSR_LOGE("UnRegister reminder state callback error.");
        ReminderCommon::HandleErrCode(env, ERR_REMINDER_PARAM_ERROR);
    }
    return NotificationNapi::Common::NapiGetNull(env);
}

void JsReminderStateListener::OnReminderState(napi_env env, napi_value callbackObj,
    const std::vector<ReminderState>& states)
{
    ANSR_LOGI("OnReminderState asyncCallback.");
    std::lock_guard<std::mutex> locker(jsCallBackListMutex_);
    bool isEqual = false;
    auto iter = jsCallBackList_.begin();
    for (; iter != jsCallBackList_.end(); iter++) {
        NAPI_CALL_RETURN_VOID(env, napi_strict_equals(env, callbackObj, iter->first->GetNapiValue(), &isEqual));
        if (isEqual) {
            break;
        }
    }
    if (!isEqual) {
        ANSR_LOGE("Callback not found in registered array.");
        return;
    }
    std::unique_ptr<ReminderStateCbInfo> cbInfo = std::make_unique<ReminderStateCbInfo>(env);
    cbInfo->states = states;
    napi_value resourceName = nullptr;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_latin1(env, "OnReminderState", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL_RETURN_VOID(env,
        napi_create_reference(env, iter->first->GetNapiValue(), 1, &cbInfo->callback));

    ReminderStateCbInfo* ctx = cbInfo.get();
    auto task = [env, ctx]() {
        JsReminderStateListener::CompleteCb(env, ctx);
    };
    if (napi_status::napi_ok != napi_send_event(env, task, napi_eprio_high, "reminderStateChange")) {
        ANSR_LOGE("failed to napi_send_event.");
        return;
    }
    cbInfo.release();
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result));
    ANSR_LOGI("OnReminderState asyncCallback end.");
}

bool JsReminderStateListener::CheckCallbackParam(napi_env env, napi_callback_info info,
    napi_value* jsCallback, const bool isRegister)
{
    if (jsCallback == nullptr) {
        return false;
    }
    size_t argc = ARG_COUNT_ONE;
    napi_value argv[ARG_COUNT_ONE] = { 0 };
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), false);
    if (isRegister && argc != ARG_COUNT_ONE) {
        return false;
    }
    if (argc != ARG_COUNT_ONE) {
        return true;
    }
    *jsCallback = argv[0];
    if (*jsCallback == nullptr) {
        return false;
    }
    bool isCallable = false;
    napi_is_callable(env, *jsCallback, &isCallable);
    if (!isCallable) {
        return false;
    }
    return true;
}

void JsReminderStateListener::CompleteCb(napi_env env, ReminderStateCbInfo* info)
{
    ANSR_LOGI("CompleteCb, main event thread complete callback.");
    if (info == nullptr) {
        ANSR_LOGW("Complete cb info is nullptr.");
        return;
    }
    std::unique_ptr<ReminderStateCbInfo> cbInfo(info);
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value array = nullptr;
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, cbInfo->callback, &callback));
    
    int32_t count = 0;
    napi_create_array(env, &array);
    for (const auto& state : cbInfo->states) {
        napi_value result = nullptr;
        napi_create_object(env, &result);
        napi_value reminderId = nullptr;
        napi_create_int32(env, state.reminderId_, &reminderId);
        napi_set_named_property(env, result, REMINDER_STATE_REMINDER_ID, reminderId);
        napi_value actionButtonType = nullptr;
        napi_create_uint32(env, static_cast<uint32_t>(state.buttonType_), &actionButtonType);
        napi_set_named_property(env, result, REMINDER_STATE_BUTTON_TYPE, actionButtonType);
        napi_value isResend = nullptr;
        napi_get_boolean(env, state.isResend_, &isResend);
        napi_set_named_property(env, result, REMINDER_STATE_IS_RESEND, isResend);
        napi_set_element(env, array, count, result);
        count++;
    }
    ANSR_LOGI("count = %{public}d", count);

    // call js callback
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, 1, &array, &callResult));
    if (cbInfo->callback != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_delete_reference(env, cbInfo->callback));
        cbInfo->callback = nullptr;
    }
    ANSR_LOGI("CompleteCb, main event thread complete end.");
}
}  // namespace OHOS::ReminderAgentNapi
