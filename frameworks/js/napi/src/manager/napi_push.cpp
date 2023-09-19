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
#include "napi_push.h"

#include "ans_inner_errors.h"
#include "ipc_skeleton.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
} // namespace
using namespace OHOS::AbilityRuntime;

void NapiPush::Finalizer(napi_env env, void *data, void *hint)
{
    ANS_LOGD("called");
    delete static_cast<NapiPush *>(data);
}

napi_value NapiPush::RegisterPushCallback(napi_env env, napi_callback_info info)
{
    NapiPush *me = CheckParamsAndGetThis<NapiPush>(env, info);
    return (me != nullptr) ? me->OnRegisterPushCallback(env, info) : nullptr;
}

napi_value NapiPush::UnregisterPushCallback(napi_env env, napi_callback_info info)
{
    NapiPush *me = CheckParamsAndGetThis<NapiPush>(env, info);
    return (me != nullptr) ? me->OnUnregisterPushCallback(env, info) : nullptr;
}

napi_value NapiPush::OnRegisterPushCallback(napi_env env, const napi_callback_info info)
{
    ANS_LOGD("called");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ARGC_TWO) {
        ANS_LOGE("The param is invalid.");
        ThrowTooFewParametersError(env);
        return undefined;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[INDEX_ZERO], &valueType));
    if (valueType != napi_string) {
        ANS_LOGE("Parse type failed");
        ThrowError(env, ERROR_PARAM_INVALID);
        return undefined;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[INDEX_ZERO], str, STR_MAX_SIZE - 1, &strLen));
    std::string type = str;
    if (type != "checkNotification") {
        ANS_LOGE("The type is not checkNotification");
        ThrowError(env, ERROR_PARAM_INVALID);
        return undefined;
    }

    if (!CheckCallerIsSystemApp()) {
        ThrowError(env, ERROR_NOT_SYSTEM_APP);
        return undefined;
    }

    if (jsPushCallBack_ == nullptr) {
        jsPushCallBack_ = new (std::nothrow) OHOS::Notification::JSPushCallBack(env);
        if (jsPushCallBack_ == nullptr) {
            ANS_LOGE("new JSPushCallBack failed");
            ThrowError(env, ERROR_INTERNAL_ERROR);
            return undefined;
        }
    }

    jsPushCallBack_->SetJsPushCallBackObject(argv[INDEX_ONE]);
    NotificationHelper::RegisterPushCallback(jsPushCallBack_->AsObject());
    return undefined;
}

napi_value NapiPush::OnUnregisterPushCallback(napi_env env, const napi_callback_info info)
{
    ANS_LOGD("called");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    size_t argc = ARGC_TWO;
    napi_value argv[ARGC_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < ARGC_ONE) {
        ANS_LOGE("The param is invalid.");
        ThrowTooFewParametersError(env);
        return undefined;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[INDEX_ZERO], &valueType));
    if (valueType != napi_string) {
        ANS_LOGE("Failed to parse type.");
        ThrowError(env, ERROR_PARAM_INVALID);
        return undefined;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[INDEX_ZERO], str, STR_MAX_SIZE - 1, &strLen));
    std::string type = str;
    if (type != "checkNotification") {
        ANS_LOGE("The type is not checkNotification");
        ThrowError(env, ERROR_PARAM_INVALID);
        return undefined;
    }

    if (!CheckCallerIsSystemApp()) {
        ThrowError(env, ERROR_NOT_SYSTEM_APP);
        return undefined;
    }

    if (jsPushCallBack_ == nullptr) {
        ThrowError(env, ERROR_INTERNAL_ERROR);
        ANS_LOGE("Never registered.");
        return undefined;
    }

    if (argc == ARGC_TWO) {
        if (!jsPushCallBack_->IsEqualPushCallBackObject(argv[INDEX_ONE])) {
            ANS_LOGE("inconsistent with existing callback");
            ThrowError(env, ERROR_PARAM_INVALID);
            return undefined;
        }
    }

    NotificationHelper::UnregisterPushCallback();
    delete jsPushCallBack_;
    jsPushCallBack_ = nullptr;
    return undefined;
}

bool NapiPush::CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        ANS_LOGE("current app is not system app, not allow.");
        return false;
    }
    return true;
}
} // namespace NotificationNapi
} // namespace OHOS