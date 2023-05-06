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
#include "js_error_utils.h"
#include "js_runtime_utils.h"
namespace OHOS {
namespace NotificationNapi {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;

void NapiPush::Finalizer(NativeEngine *engine, void *data, void *hint)
{
    ANS_LOGI("NapiPush::Finalizer is called");
    std::unique_ptr<NapiPush>(static_cast<NapiPush *>(data));
}

NativeValue *NapiPush::RegisterPushCallback(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiPush *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiPush>(engine, info);
    return (me != nullptr) ? me->OnRegisterPushCallback(*engine, *info) : nullptr;
}

NativeValue *NapiPush::UnregisterPushCallback(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiPush *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiPush>(engine, info);
    return (me != nullptr) ? me->OnUnregisterPushCallback(*engine, *info) : nullptr;
}

NativeValue *NapiPush::OnRegisterPushCallback(NativeEngine &engine, const NativeCallbackInfo &info)
{
    ANS_LOGI("%{public}s is called", __FUNCTION__);

    if (info.argc != ARGC_TWO) {
        ANS_LOGE("The param is invalid.");
        OHOS::AbilityRuntime::ThrowTooFewParametersError(engine);
        return engine.CreateUndefined();
    }

    std::string type;
    if (!OHOS::AbilityRuntime::ConvertFromJsValue(engine, info.argv[INDEX_ZERO], type) || type != "checkNotification") {
        ANS_LOGE("Parse type failed");
        OHOS::AbilityRuntime::ThrowError(engine, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return engine.CreateUndefined();
    }

    if (!jsPushCallBack_) {
        jsPushCallBack_ = new OHOS::Notification::JSPushCallBack(engine);
    }

    jsPushCallBack_->SetJsPushCallBackObject(info.argv[INDEX_ONE]);
    NotificationHelper::RegisterPushCallback(jsPushCallBack_->AsObject());

    return engine.CreateUndefined();
}

NativeValue *NapiPush::OnUnregisterPushCallback(NativeEngine &engine, const NativeCallbackInfo &info)
{
    ANS_LOGI("%{public}s is called", __FUNCTION__);

    if (info.argc < ARGC_ONE || info.argc > ARGC_TWO) {
        ANS_LOGE("The param is invalid.");
        OHOS::AbilityRuntime::ThrowTooFewParametersError(engine);
        return engine.CreateUndefined();
    }

    std::string type;
    if (!OHOS::AbilityRuntime::ConvertFromJsValue(engine, info.argv[INDEX_ZERO], type) || type != "checkNotification") {
        ANS_LOGE("Parse type failed");
        OHOS::AbilityRuntime::ThrowError(engine, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return engine.CreateUndefined();
    }

    if (!jsPushCallBack_) {
        OHOS::AbilityRuntime::ThrowError(engine, ERROR_INTERNAL_ERROR);
        ANS_LOGE("Never registered.");
        return engine.CreateUndefined();
    }

    if (info.argc == ARGC_TWO) {
        if (!jsPushCallBack_->IsEqualPushCallBackObject(info.argv[INDEX_ONE])) {
            ANS_LOGW("OnUnregisterPushCallback inconsistent with existing callback");
            OHOS::AbilityRuntime::ThrowError(engine, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
            return engine.CreateUndefined();
        }
    }
    NotificationHelper::UnregisterPushCallback();
    delete jsPushCallBack_;
    jsPushCallBack_ = nullptr;

    return engine.CreateUndefined();
}
} // namespace NotificationNapi
} // namespace OHOS