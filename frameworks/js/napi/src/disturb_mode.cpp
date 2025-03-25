/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "disturb_mode.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int SET_DISTURB_MAX_PARA = 3;
const int SET_DISTURB_MIN_PARA = 1;
const int GET_DISTURB_MAX_PARA = 2;
const int DISTURB_PROFILES_PARA = 1;
const int DO_NOT_DISTURB_PROFILE_MIN_ID = 1;
const int DO_NOT_DISTURB_PROFILE_MAX_ID = 10;

napi_value GetDoNotDisturbDate(const napi_env &env, const napi_value &argv, SetDoNotDisturbDateParams &params)
{
    ANS_LOGD("enter");
    napi_value value = nullptr;
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    // argv[0]: date:type
    NAPI_CALL(env, napi_has_named_property(env, argv, "type", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    napi_get_named_property(env, argv, "type", &value);
    NAPI_CALL(env, napi_typeof(env, value, &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int type = 0;
    NotificationConstant::DoNotDisturbType outType = NotificationConstant::DoNotDisturbType::NONE;
    napi_get_value_int32(env, value, &type);
    ANS_LOGI("type is: %{public}d", type);
    if (!AnsEnumUtil::DoNotDisturbTypeJSToC(DoNotDisturbType(type), outType)) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }
    params.date.SetDoNotDisturbType(outType);

    // argv[0]: date:begin
    NAPI_CALL(env, napi_has_named_property(env, argv, "begin", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    double begin = 0;
    napi_get_named_property(env, argv, "begin", &value);
    bool isDate = false;
    napi_is_date(env, value, &isDate);
    if (!isDate) {
        ANS_LOGE("Wrong argument type. Date expected.");
        std::string msg = "Incorrect parameter types.The type of param must be date.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_date_value(env, value, &begin);
    params.date.SetBeginDate(int64_t(begin));

    // argv[0]: date:end
    NAPI_CALL(env, napi_has_named_property(env, argv, "end", &hasProperty));
    if (!hasProperty) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    double end = 0;
    napi_get_named_property(env, argv, "end", &value);
    isDate = false;
    napi_is_date(env, value, &isDate);
    if (!isDate) {
        ANS_LOGE("Wrong argument type. Date expected.");
        std::string msg = "Incorrect parameter types.The type of param must be date.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_date_value(env, value, &end);
    params.date.SetEndDate(int64_t(end));

    return Common::NapiGetNull(env);
}

bool GetDoNotDisturbProfile(
    const napi_env &env, const napi_value &value, sptr<NotificationDoNotDisturbProfile> &profile)
{
    ANS_LOGD("Called.");
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, value, "id", &hasProperty), false);
    if (!hasProperty) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        return false;
    }
    int64_t profileId = 0;
    napi_value obj = nullptr;
    napi_get_named_property(env, value, "id", &obj);
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valuetype), false);
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        return false;
    }
    napi_get_value_int64(env, obj, &profileId);
    profile->SetProfileId(profileId);

    NAPI_CALL_BASE(env, napi_has_named_property(env, value, "name", &hasProperty), false);
    if (!hasProperty) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        return false;
    }
    char name[STR_MAX_SIZE] = {0};
    napi_get_named_property(env, value, "name", &obj);
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valuetype), false);
    if (valuetype != napi_string) {
        ANS_LOGE("Wrong argument type. String expected.");
        return false;
    }
    size_t strLen = 0;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, name, STR_MAX_SIZE - 1, &strLen), false);
    profile->SetProfileName(name);

    return AnalyseTrustlist(env, value, profile);
}

bool AnalyseTrustlist(const napi_env &env, const napi_value &value, sptr<NotificationDoNotDisturbProfile> &profile)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, value, "trustlist", &hasProperty), false);
    if (!hasProperty) {
        return true;
    }
    napi_value obj = nullptr;
    napi_get_named_property(env, value, "trustlist", &obj);
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, obj, &isArray), false);
    if (!isArray) {
        ANS_LOGE("Value is not an array.");
        return false;
    }
    uint32_t length = 0;
    napi_get_array_length(env, obj, &length);
    if (length == 0) {
        ANS_LOGD("The array is empty.");
        return true;
    }
    std::vector<NotificationBundleOption> options;
    for (size_t index = 0; index < length; index++) {
        napi_value nOption = nullptr;
        napi_get_element(env, obj, index, &nOption);
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, nOption, &valuetype), false);
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            return false;
        }
        NotificationBundleOption option;
        if (!Common::GetBundleOption(env, nOption, option)) {
            return false;
        }
        options.emplace_back(option);
    }
    profile->SetProfileTrustList(options);
    return true;
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, SetDoNotDisturbDateParams &params)
{
    ANS_LOGD("enter");

    size_t argc = SET_DISTURB_MAX_PARA;
    napi_value argv[SET_DISTURB_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_DISTURB_MIN_PARA) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: date
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Property type expected.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }
    if (GetDoNotDisturbDate(env, argv[PARAM0], params) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[1] : userId / callback
    if (argc >= SET_DISTURB_MAX_PARA - 1) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if ((valuetype != napi_number) && (valuetype != napi_function)) {
            ANS_LOGE("Wrong argument type. Function or object expected. Excute promise.");
            return Common::NapiGetNull(env);
        }

        if (valuetype == napi_number) {
            params.hasUserId = true;
            NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM1], &params.userId));
        } else {
            napi_create_reference(env, argv[PARAM1], 1, &params.callback);
        }
    }

    // argv[2]:callback
    if (argc >= SET_DISTURB_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

bool ParseProfilesParameters(
    const napi_env &env, const napi_callback_info &info, std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("Called.");
    size_t argc = DISTURB_PROFILES_PARA;
    napi_value argv[DISTURB_PROFILES_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL), false);
    if (argc != DISTURB_PROFILES_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return false;
    }
    napi_valuetype valuetype = napi_undefined;
    bool isArray = false;
    napi_is_array(env, argv[PARAM0], &isArray);
    if (!isArray) {
        ANS_LOGE("Wrong argument type. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    uint32_t length = 0;
    napi_get_array_length(env, argv[PARAM0], &length);
    if (length == 0) {
        ANS_LOGD("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        napi_value nProfile = nullptr;
        napi_get_element(env, argv[PARAM0], index, &nProfile);
        NAPI_CALL_BASE(env, napi_typeof(env, nProfile, &valuetype), false);
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return false;
        }
        sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
        if (profile == nullptr) {
            ANS_LOGE("Failed to create NotificationDoNotDisturbProfile.");
            return false;
        }
        if (!GetDoNotDisturbProfile(env, nProfile, profile)) {
            return false;
        }
        profiles.emplace_back(profile);
    }
    return true;
}

napi_value SetDoNotDisturbDate(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    SetDoNotDisturbDateParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSetDoNotDisturb *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSetDoNotDisturb {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo is failed.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setDoNotDisturbDate", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr, resourceName, [](napi_env env, void *data) {
            ANS_LOGD("SetDoNotDisturbDate work excute.");
            AsyncCallbackInfoSetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoSetDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasUserId) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::SetDoNotDisturbDate(
                        asynccallbackinfo->params.userId, asynccallbackinfo->params.date);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::SetDoNotDisturbDate(
                        asynccallbackinfo->params.date);
                }

                ANS_LOGI("SetDoNotDisturbDate date=%{public}s errorCode=%{public}d, hasUserId=%{public}d",
                    asynccallbackinfo->params.date.Dump().c_str(), asynccallbackinfo->info.errorCode,
                    asynccallbackinfo->params.hasUserId);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("SetDoNotDisturbDate work complete.");
            AsyncCallbackInfoSetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoSetDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete SetDoNotDisturbDate callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo, &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("SetDoNotDisturbDate callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackGetDoNotDisturbDate(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackInfoGetDoNotDisturb *asynccallbackinfo = static_cast<AsyncCallbackInfoGetDoNotDisturb *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("asynccallbackinfo is not nullptr.");
        napi_value result = Common::NapiGetNull(env);
        if (asynccallbackinfo->info.errorCode == ERR_OK) {
            napi_create_object(env, &result);
            if (!Common::SetDoNotDisturbDate(env, asynccallbackinfo->date, result)) {
                asynccallbackinfo->info.errorCode = ERROR;
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete GetDoNotDisturbDate callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, GetDoNotDisturbDateParams &params)
{
    ANS_LOGD("enter");

    size_t argc = GET_DISTURB_MAX_PARA;
    napi_value argv[GET_DISTURB_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: userId / callback
    if (argc >= GET_DISTURB_MAX_PARA - 1) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        if ((valuetype != napi_number) && (valuetype != napi_function)) {
            ANS_LOGW("Wrong argument type. Function or object expected. Excute promise.");
            return Common::NapiGetNull(env);
        }
        if (valuetype == napi_number) {
            params.hasUserId = true;
            NAPI_CALL(env, napi_get_value_int32(env, argv[PARAM0], &params.userId));
        } else {
            napi_create_reference(env, argv[PARAM0], 1, &params.callback);
        }
    }

    // argv[1]:callback
    if (argc >= GET_DISTURB_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value GetDoNotDisturbDate(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    GetDoNotDisturbDateParams params {};
    if (ParseParameters(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetDoNotDisturb *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetDoNotDisturb {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo is failed.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getDoNotDisturbDate string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getDoNotDisturbDate", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("GetDoNotDisturbDate work excute.");
            AsyncCallbackInfoGetDoNotDisturb *asynccallbackinfo =
                static_cast<AsyncCallbackInfoGetDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->params.hasUserId) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetDoNotDisturbDate(
                        asynccallbackinfo->params.userId, asynccallbackinfo->date);
                } else {
                    asynccallbackinfo->info.errorCode = NotificationHelper::GetDoNotDisturbDate(
                        asynccallbackinfo->date);
                }

                ANS_LOGI("GetDoNotDisturbDate errorCode=%{public}d date=%{public}s, hasUserId=%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->date.Dump().c_str(),
                    asynccallbackinfo->params.hasUserId);
            }
        },
        AsyncCompleteCallbackGetDoNotDisturbDate,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getDoNotDisturbDate callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SupportDoNotDisturbMode(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSupportDoNotDisturb *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSupportDoNotDisturb {
        .env = env, .asyncWork = nullptr, .callback = callback};

    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo is failed.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create supportDoNotDisturbMode string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "supportDoNotDisturbMode", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("SupportDoNotDisturbMode work excute.");
            AsyncCallbackInfoSupportDoNotDisturb *asynccallbackinfo =
                static_cast<AsyncCallbackInfoSupportDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::DoesSupportDoNotDisturbMode(asynccallbackinfo->isSupported);
                ANS_LOGI("errorCode:%{public}d isSupported:%{public}d",
                    asynccallbackinfo->info.errorCode, asynccallbackinfo->isSupported);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("SupportDoNotDisturbMode work complete.");
            AsyncCallbackInfoSupportDoNotDisturb *asynccallbackinfo =
                static_cast<AsyncCallbackInfoSupportDoNotDisturb *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asynccallbackinfo->isSupported, &result);
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete supportDoNotDisturbMode callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("SupportDoNotDisturbMode work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("supportDoNotDisturbMode callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, GetDoNotDisturbProfileParams &params)
{
    ANS_LOGD("ParseParameters");

    size_t argc = DISTURB_PROFILES_PARA;
    napi_value argv[DISTURB_PROFILES_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    // argv[0]: profileId
    napi_valuetype valuetype = napi_undefined;
    if (argc >= DISTURB_PROFILES_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        if (valuetype != napi_number) {
            ANS_LOGW("Wrong argument type Excute promise.");
            return Common::NapiGetNull(env);
        }
        NAPI_CALL(env, napi_get_value_int64(env, argv[PARAM0], &params.profileId));
    }

    return Common::NapiGetNull(env);
}
}  // namespace NotificationNapi
}  // namespace OHOS
