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
#include <optional>

#include "ans_inner_errors.h"
#include "napi_remove_group.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
    const int REMOVE_GROUP_BY_BUNDLE_MIN_PARA = 2;
    const int REMOVE_GROUP_BY_BUNDLE_MAX_PARA = 3;
}

napi_value ParseParameters(
    const napi_env &env, const napi_callback_info &info, RemoveParamsGroupByBundle &params)
{
    ANS_LOGD("enter");

    size_t argc = REMOVE_GROUP_BY_BUNDLE_MAX_PARA;
    napi_value argv[REMOVE_GROUP_BY_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < REMOVE_GROUP_BY_BUNDLE_MIN_PARA) {
        ANS_LOGW("Wrong number of arguments.");
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGW("Wrong argument type. Object expected.");
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        return nullptr;
    }

    // argv[1]: groupName: string
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_string) {
        ANS_LOGW("Wrong argument type. String expected.");
        return nullptr;
    }
    char str[STR_MAX_SIZE] = {0};
    size_t strLen = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM1], str, STR_MAX_SIZE - 1, &strLen));
    params.groupName = str;
    // argv[2]:callback
    if (argc >= REMOVE_GROUP_BY_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Wrong argument type. Function expected.");
            return nullptr;
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }
    return Common::NapiGetNull(env);
}

void AsyncCompleteCallbackNapiRemoveGroupByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoRemoveGroupByBundle *asynccallbackinfo = static_cast<AsyncCallbackInfoRemoveGroupByBundle *>(data);
    if (asynccallbackinfo) {
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiRemoveGroupByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");
    RemoveParamsGroupByBundle params {};
    if (ParseParameters(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoRemoveGroupByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoRemoveGroupByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeGroupByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("RemoveGroupByBundle napi_create_async_work start");
            AsyncCallbackInfoRemoveGroupByBundle *asynccallbackinfo =
                static_cast<AsyncCallbackInfoRemoveGroupByBundle *>(data);
            if (asynccallbackinfo) {
                ANS_LOGI("option.bundle = %{public}s, option.uid = %{public}d, groupName = %{public}s",
                    asynccallbackinfo->params.option.GetBundleName().c_str(),
                    asynccallbackinfo->params.option.GetUid(),
                    asynccallbackinfo->params.groupName.c_str());
                asynccallbackinfo->info.errorCode = NotificationHelper::RemoveGroupByBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.groupName);
            }
        },
        AsyncCompleteCallbackNapiRemoveGroupByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_status status = napi_queue_async_work(env, asynccallbackinfo->asyncWork);
    if (status != napi_ok) {
        ANS_LOGE("napi_queue_async_work failed return: %{public}d", status);
        asynccallbackinfo->info.errorCode = ERROR_INTERNAL_ERROR;
        Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
        if (asynccallbackinfo->info.callback != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }

    if (isCallback) {
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS