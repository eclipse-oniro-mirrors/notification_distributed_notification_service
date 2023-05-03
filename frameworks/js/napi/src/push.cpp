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
#include "push.h"

#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "push_callback.h"

namespace OHOS {
namespace NotificationNapi {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THR = 3;
constexpr int32_t ERR_OK = 0;
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;

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

    if (info.argc < ARGC_TWO || info.argc > ARGC_THR) {
        ANS_LOGE("The param is invalid.");
        OHOS::AbilityRuntime::ThrowTooFewParametersError(engine);
        return engine.CreateUndefined();
    }

    std::string type;
    if (!OHOS::AbilityRuntime::ConvertFromJsValue(engine, info.argv[INDEX_ZERO], type) || type != "pushCheck") {
        ANS_LOGE("Parse type failed");
        OHOS::AbilityRuntime::ThrowError(engine, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return engine.CreateUndefined();
    }

    sptr<OHOS::Notification::JSPushCallBack> jsPushCallBack = new OHOS::Notification::JSPushCallBack(engine);
    jsPushCallBack->SetJsPushCallBackObject(info.argv[INDEX_ONE]);

    auto complete = [jsPushCallBack](NativeEngine &engine, AbilityRuntime::AsyncTask &task, int32_t status) {
        auto ret = NotificationHelper::RegisterPushCallback(jsPushCallBack->AsObject());
        if (ret == ERR_OK) {
            task.Resolve(engine, engine.CreateUndefined());
        } else {
            task.Reject(engine, AbilityRuntime::CreateJsError(engine, ret, "Register push callback failed."));
        }
    };

    auto callback = (info.argc == ARGC_TWO) ? nullptr : info.argv[INDEX_TWO];

    NativeValue *result = nullptr;
    AbilityRuntime::AsyncTask::Schedule("NapiPush::OnRegisterPushCallback", engine,
        AbilityRuntime::CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
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
    if (!OHOS::AbilityRuntime::ConvertFromJsValue(engine, info.argv[INDEX_ZERO], type) || type != "pushCheck") {
        ANS_LOGE("Parse type failed");
        OHOS::AbilityRuntime::ThrowError(engine, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return engine.CreateUndefined();
    }

    auto complete = [](NativeEngine &engine, AbilityRuntime::AsyncTask &task, int32_t status) {
        auto ret = NotificationHelper::UnregisterPushCallback();
        if (ret == ERR_OK) {
            task.Resolve(engine, engine.CreateUndefined());
        } else {
            task.Reject(engine, AbilityRuntime::CreateJsError(engine, ret, "Unregister push callback failed."));
        }
    };

    auto callback = (info.argc == ARGC_ONE) ? nullptr : info.argv[INDEX_ONE];

    NativeValue *result = nullptr;
    AbilityRuntime::AsyncTask::Schedule("NapiPush::OnUnregisterPushCallback", engine,
        AbilityRuntime::CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
}
} // namespace NotificationNapi
} // namespace OHOS