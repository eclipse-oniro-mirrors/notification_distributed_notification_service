/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "napi_slot.h"

#include "ans_inner_errors.h"
#include "slot.h"

namespace OHOS {
namespace NotificationNapi {
napi_value NapiAddSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoAddSlot paras;
    if (ParseParametersByAddSlot(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoAddSlot *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoAddSlot {
        .env = env,
        .asyncWork = nullptr,
        .slot = paras.slot,
        .inType = paras.inType,
        .isAddSlotByType = paras.isAddSlotByType
    };
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "addSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiAddSlot work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlot *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->isAddSlotByType) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::AddSlotByType(asynccallbackinfo->inType);
                } else {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::AddNotificationSlot(asynccallbackinfo->slot);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiAddSlot work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlot *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiAddSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiAddSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiAddSlots(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoAddSlots paras;
    if (ParseParametersByAddSlots(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoAddSlots *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoAddSlots {.env = env, .asyncWork = nullptr, .slots = paras.slots};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "addSlots", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiAddSlots work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlots *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::AddNotificationSlots(asynccallbackinfo->slots);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiAddSlots work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlots *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiAddSlots callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiAddSlots work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSetSlotByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoSetSlotByBundle params {};
    if (ParseParametersSetSlotByBundle(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSetSlotByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSetSlotByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setSlotByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetSlotByBundle work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::UpdateNotificationSlots(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.slots);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSetSlotByBundle work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotByBundle *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSetSlotByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSetSlotByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}


void AsyncCompleteCallbackNapiGetSlot(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("null data");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlot *>(data);
    if (asynccallbackinfo) {
        napi_value result = Common::NapiGetNull(env);
        if (asynccallbackinfo->info.errorCode == ERR_OK) {
            if (asynccallbackinfo->slot != nullptr) {
                napi_create_object(env, &result);
                if (!Common::SetNotificationSlot(env, *asynccallbackinfo->slot, result)) {
                    asynccallbackinfo->info.errorCode = ERROR;
                    result = Common::NapiGetNull(env);
                }
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("null callback");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoGetSlot paras;
    if (ParseParametersByGetSlot(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlot {.env = env, .asyncWork = nullptr, .outType = paras.outType};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSlot work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetNotificationSlot(asynccallbackinfo->outType, asynccallbackinfo->slot);
            }
        },
        AsyncCompleteCallbackNapiGetSlot,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiGetSlotNumByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoGetSlotNumByBundle params {};
    if (ParseParametersGetSlotNumByBundle(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotNumByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotNumByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotNumByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSlotNumByBundle work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotNumByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotNumAsBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->num);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiGetSlotNumByBundle work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlotNumByBundle *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_create_uint32(env, asynccallbackinfo->num, &result);
                Common::CreateReturnValue(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiGetSlotNumByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiGetSlotNumByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetSlots(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("null data");
        return;
    }
    napi_value result = nullptr;
    auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlots *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo conversion is success.");
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            napi_create_array(env, &arr);
            size_t count = 0;
            for (auto vec : asynccallbackinfo->slots) {
                if (!vec) {
                    ANS_LOGW("Invalidated NotificationSlot object ptr.");
                    continue;
                }
                napi_value nSlot = nullptr;
                napi_create_object(env, &nSlot);
                if (!Common::SetNotificationSlot(env, *vec, nSlot)) {
                    ANS_LOGD("null SetNotificationSlot");
                    continue;
                }
                napi_set_element(env, arr, count, nSlot);
                count++;
            }
            ANS_LOGD("count : %{public}zu", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->slots.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiGetSlots callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetSlots(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoGetSlots {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlots", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSlots word excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlots *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlots(asynccallbackinfo->slots);
            }
        },
        AsyncCompleteCallbackNapiGetSlots,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetSlotsByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("null data");
        return;
    }
    napi_value result = nullptr;
    auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotsByBundle *>(data);
    if (asynccallbackinfo) {
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            napi_create_array(env, &arr);
            size_t count = 0;
            for (auto vec : asynccallbackinfo->slots) {
                if (!vec) {
                    ANS_LOGW("Invalid NotificationSlot object ptr.");
                    continue;
                }
                napi_value nSlot = nullptr;
                napi_create_object(env, &nSlot);
                if (!Common::SetNotificationSlot(env, *vec, nSlot)) {
                    continue;
                }
                napi_set_element(env, arr, count, nSlot);
                count++;
            }
            ANS_LOGD("count = %{public}zu", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->slots.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("null callback");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetSlotsByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoGetSlotsByBundle params {};
    if (ParseParametersGetSlotsByBundle(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotsByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotsByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotsByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSlotsByBundle work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotsByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotsForBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->slots);
            }
        },
        AsyncCompleteCallbackNapiGetSlotsByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetSlotByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("null data");
        return;
    }
    napi_value result = nullptr;
    auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotByBundle *>(data);
    if (asynccallbackinfo) {
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            if (asynccallbackinfo->slot != nullptr) {
                napi_create_object(env, &result);
                if (!Common::SetNotificationSlot(env, *asynccallbackinfo->slot, result)) {
                    asynccallbackinfo->info.errorCode = ERROR;
                    result = Common::NapiGetNull(env);
                }
            }
        }
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete napiGetSlotByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value NapiGetSlotByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoGetSlotByBundle params {};
    if (ParseParametersGetSlotByBundle(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSlotByBundle work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotForBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.outType, asynccallbackinfo->slot);
            }
        },
        AsyncCompleteCallbackNapiGetSlotByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiRemoveSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoRemoveSlot paras;
    if (ParseParametersByRemoveSlot(env, info, paras) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoRemoveSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoRemoveSlot {.env = env, .asyncWork = nullptr, .outType = paras.outType};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiRemoveSlot work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::RemoveNotificationSlot(asynccallbackinfo->outType);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiRemoveSlot work complete.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveSlot *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiRemoveSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiRemoveSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiRemoveAllSlots(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    auto *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoRemoveAllSlots {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeAll", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiRemoveAllSlots work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveAllSlots *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::RemoveAllSlots();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiRemoveAllSlots work complete.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveAllSlots *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiRemoveAllSlots callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiRemoveAllSlots work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiEnableNotificationSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoEnableSlot params {};
    if (ParseParametersEnableSlot(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoInfoEnableSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoInfoEnableSlot {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "EnableNotificationSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiEnableNotificationSlot work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoEnableSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetEnabledForBundleSlot(
                    asynccallbackinfo->params.option,
                    asynccallbackinfo->params.outType,
                    asynccallbackinfo->params.enable,
                    asynccallbackinfo->params.isForceControl);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiEnableNotificationSlot work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoEnableSlot *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiEnableNotificationSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiEnableNotificationSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiIsEnableNotificationSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoIsEnableSlot params {};
    if (ParseParametersIsEnableSlot(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoInfoIsEnableSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoInfoIsEnableSlot {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsEnableNotificationSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiIsEnableNotificationSlot work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoIsEnableSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetEnabledForBundleSlot(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.outType, asynccallbackinfo->isEnable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiIsEnableNotificationSlot work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoIsEnableSlot *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asynccallbackinfo->isEnable, &result);
                Common::CreateReturnValue(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiIsEnableNotificationSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiIsEnableNotificationSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiSetSlotFlagsByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoSetSlotFlagsByBundle params {};
    if (ParseParametersSetSlotFlagsByBundle(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSetSlotFlagsByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSetSlotFlagsByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setSlotFlagsByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiSetSlotFlagsByBundle work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetNotificationSlotFlagsAsBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.slotFlags);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiSetSlotFlagsByBundle work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiSetSlotFlagsByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiSetSlotFlagsByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value NapiGetSlotFlagsByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    ParametersInfoGetSlotFlagsByBundle params {};
    if (ParseParametersGetSlotFlagsByBundle(env, info, params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotFlagsByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotFlagsByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotFlagsByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiGetSlotFlagsByBundle work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotFlagsAsBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->slotFlags);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("NapiGetSlotFlagsByBundle work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_create_uint32(env, asynccallbackinfo->slotFlags, &result);
                Common::CreateReturnValue(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete napiGetSlotFlagsByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("NapiGetSlotFlagsByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    bool isCallback = asynccallbackinfo->info.isCallback;
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackNapiGetNotificationSettings(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("called");
    if (!data) {
        ANS_LOGE("null data");
        return;
    }
    auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetNotificationSettings *>(data);
    if (asynccallbackinfo) {
        napi_value result = Common::NapiGetNull(env);
        napi_create_object(env, &result);
        bool soundEnabled = asynccallbackinfo->slotFlags & NotificationConstant::ReminderFlag::SOUND_FLAG;
        bool vibrationEnabled = asynccallbackinfo->slotFlags & NotificationConstant::ReminderFlag::VIBRATION_FLAG;
        napi_value vibrationValue;
        napi_value soundValue;
        napi_get_boolean(env, vibrationEnabled, &vibrationValue);
        napi_get_boolean(env, soundEnabled, &soundValue);

        napi_set_named_property(env, result, "vibrationEnabled", vibrationValue);
        napi_set_named_property(env, result, "soundEnabled", soundValue);
        Common::CreateReturnValue(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete NapiGetNotificationSettings callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
    ANS_LOGD("NapiGetNotificationSettings work complete end.");
}

napi_value NapiGetNotificationSettings(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    AsyncCallbackInfoGetNotificationSettings *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetNotificationSettings {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getNotificationSetting", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("getNotificationSettings work excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetNotificationSettings *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSettings(
                    asynccallbackinfo->slotFlags);
            }
        },
        AsyncCompleteCallbackNapiGetNotificationSettings,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    return asynccallbackinfo->info.isCallback ? Common::NapiGetNull(env) : promise;
}

}  // namespace NotificationNapi
}  // namespace OHOS
