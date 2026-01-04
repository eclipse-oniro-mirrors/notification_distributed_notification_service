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

#include "sts_callback_promise.h"

#include "sts_throw_erro.h"

namespace OHOS {
namespace NotificationSts {
void PaddingCallbackPromiseInfo(ani_env *env, ani_ref &callback, CallbackPromiseInfo &info, ani_object &promise)
{
    if (callback) {
        ANS_LOGD("null callback");
        info.callback = callback;
        info.isCallback = true;
    } else {
        ani_resolver resolve = nullptr;
        env->Promise_New(&resolve, &promise);
        info.resolve = resolve;
        info.isCallback = false;
    }
}

void CreateReturnData(ani_env *env, const CallbackPromiseInfo &info)
{
    ANS_LOGD("start, errorCode=%{public}d", info.returnCode);
    int32_t errorCode = info.returnCode == ERR_OK ? ERR_OK : GetExternalCode(info.returnCode);
    
    if (info.isCallback) {
        SetCallback(env, info.callback, errorCode, info.result);
    } else {
        SetPromise(env, info.resolve, errorCode, info.result);
    }
    ANS_LOGD("end");
}

std::vector<ani_ref> GetCallBackData(
    ani_env *env, const ani_ref &callback, const int32_t &errorCode, const ani_object &result)
{
    ani_object data = (result == nullptr) ? GetNullObject(env) : result;
    std::vector<ani_ref> args;
    if (errorCode != ERR_OK) {
        ani_object errorObj = CreateError(env, errorCode, FindAnsErrMsg(errorCode));
        ani_ref undefRef;
        env->GetUndefined(&undefRef);
        args.push_back(errorObj);
        args.push_back(undefRef);
    } else {
        ani_object nullObj = GetNullObject(env);
        args.push_back(nullObj);
        args.push_back(data);
    }
    return args;
}

void SetCallback(ani_env *env, const ani_ref &callback, const int32_t &errorCode, const ani_object &result)
{
    ANS_LOGD("start");
    std::vector<ani_ref> args = GetCallBackData(env, callback, errorCode, result);
    ani_status status = ANI_OK;
    ani_ref funcResult;
    if (ANI_OK != (status = env->FunctionalObject_Call(static_cast<ani_fn_object>(callback),
        args.size(), args.data(), &funcResult))) {
        ANS_LOGE("FunctionalObject_Call faild. status %{public}d", status);
        return;
    }
    ANS_LOGD("end");
}

void SetPromise(ani_env *env, const ani_resolver &resolver, const int32_t &errorCode, const ani_object &result)
{
    ANS_LOGD("start");
    ani_object data = (result == nullptr) ? GetNullObject(env) : result;
    ani_status status = ANI_OK;
    if (errorCode == ERR_OK) {
        status = env->PromiseResolver_Resolve(resolver, data);
    } else {
        ani_object errorObj = CreateError(env, errorCode, FindAnsErrMsg(errorCode));
        status = env->PromiseResolver_Reject(resolver, static_cast<ani_error>(errorObj));
    }
    if (ANI_OK != status) {
        ANS_LOGE("SetPromise failed,status = %{public}d", status);
    }
    ANS_LOGD("end");
}
} // namespace NotificationSts
} // OHOS
