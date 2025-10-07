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

#include "napi_reminder_info.h"

#include "ans_inner_errors.h"
#include "js_native_api.h"
#include "js_native_api_types.h"

namespace OHOS {
namespace NotificationNapi {

const int GET_REMINDER_INFO_MAX_PARA = 1;
const int SET_REMINDER_INFO_MAX_PARA = 1;

napi_value ParseBundlesParameters(const napi_env &env, const napi_callback_info &info,
    std::vector<NotificationBundleOption> &bundles)
{
    ANS_LOGD("ParseParameters bundles");
    size_t argc = GET_REMINDER_INFO_MAX_PARA;
    napi_value argv[GET_REMINDER_INFO_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc != GET_REMINDER_INFO_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: Array<BundleOption>
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, argv[PARAM0], &isArray));
    if (!isArray) {
        ANS_LOGE("Parameter type error. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    uint32_t len = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[PARAM0], &len));
    if (len == 0) {
        ANS_LOGD("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    for (uint32_t index = 0; index < len; ++index) {
        napi_value nBundle = nullptr;
        NAPI_CALL(env, napi_get_element(env, argv[PARAM0], index, &nBundle));
        NAPI_CALL(env, napi_typeof(env, nBundle, &valueType));
        if (valueType != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NotificationBundleOption bundle;
        if (!Common::GetBundleOption(env, nBundle, bundle)) {
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        bundles.emplace_back(bundle);
    }
    return Common::NapiGetNull(env);
}

napi_value ParseReminderInfoParameters(const napi_env &env, const napi_callback_info &info,
    std::vector<NotificationReminderInfo> &reminderInfo)
{
    ANS_LOGD("ParseParameters reminder info");
    size_t argc = SET_REMINDER_INFO_MAX_PARA;
    napi_value argv[SET_REMINDER_INFO_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc != SET_REMINDER_INFO_MAX_PARA) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: Array<NotificationReminderInfo>
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, argv[PARAM0], &isArray));
    if (!isArray) {
        ANS_LOGE("Parameter type error. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    uint32_t len = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[PARAM0], &len));
    if (len == 0) {
        ANS_LOGD("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    for (uint32_t index = 0; index < len; ++index) {
        napi_value nInfo = nullptr;
        NAPI_CALL(env, napi_get_element(env, argv[PARAM0], index, &nInfo));
        NAPI_CALL(env, napi_typeof(env, nInfo, &valueType));
        if (valueType != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NotificationReminderInfo info;
        if (!Common::GetReminderInfo(env, nInfo, info)) {
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }
        reminderInfo.emplace_back(info);
    }
    return Common::NapiGetNull(env);
}

void SetNotificationReminderInfo(
    const napi_env &env, const NotificationReminderInfo &reminderInfo, napi_value &obj)
{
    ANS_LOGD("SetNotificationReminderInfo");

    napi_value bundleNapi = nullptr;
    napi_create_object(env, &bundleNapi);
    // bundleName: string
    napi_value bundleNameNapi = nullptr;
    napi_create_string_utf8(env, reminderInfo.GetBundleOption().GetBundleName().c_str(),
        NAPI_AUTO_LENGTH, &bundleNameNapi);
    napi_set_named_property(env, bundleNapi, "bundle", bundleNameNapi);
    // uid: int32_t
    napi_value uidNapi = nullptr;
    napi_create_int32(env, reminderInfo.GetBundleOption().GetUid(), &uidNapi);
    napi_set_named_property(env, bundleNapi, "uid", uidNapi);

    // reminderFlags: int32_t
    napi_value reminderFlagsNapi = nullptr;
    napi_create_int32(env, reminderInfo.GetReminderFlags(), &reminderFlagsNapi);

    // silentReminderEnabled： bool
    napi_value silentReminderEnabledNapi = nullptr;
    napi_get_boolean(env, reminderInfo.GetSilentReminderEnabled(), &silentReminderEnabledNapi);

    napi_set_named_property(env, obj, "bundle", bundleNapi);
    napi_set_named_property(env, obj, "reminderFlags", reminderFlagsNapi);
    napi_set_named_property(env, obj, "silentReminderEnabled", silentReminderEnabledNapi);
    return;
}

void AsyncCompleteCallbackNapiGetReminderInfoByBundles(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackNapiGetReminderInfoByBundles");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    napi_value result = nullptr;
    AsyncCallbackInfoReminderInfo *asynccallbackinfo = static_cast<AsyncCallbackInfoReminderInfo*>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        return;
    }
    if (asynccallbackinfo->info.errorCode != ERR_OK) {
        result = Common::NapiGetNull(env);
    }
    napi_value arr = nullptr;
    napi_create_array(env, &arr);
    uint32_t cnt = 0;
    for (auto vec : asynccallbackinfo->reminderInfo) {
        napi_value obj;
        napi_create_object(env, &obj);
        SetNotificationReminderInfo(env, vec, obj);
        napi_set_element(env, arr, cnt, obj);
        ++cnt;
    }
    result = arr;
    Common::CreateReturnValue(env, asynccallbackinfo->info, result);
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
    return;
}

void AsyncCompleteCallbackNapiSetReminderInfoByBundles(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackNapiSetReminderInfoByBundles");
    AsyncCallbackInfoReminderInfo *asynccallbackinfo = static_cast<AsyncCallbackInfoReminderInfo*>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        return;
    }
    Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
    return;
}

napi_value NapiGetReminderInfoByBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiGetReminderInfoByBundles");
    std::vector<NotificationBundleOption> bundles;
    if (ParseBundlesParameters(env, info, bundles) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoReminderInfo *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoReminderInfo {.env = env, .asyncWork = nullptr, .bundles = bundles};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getReminderInfoByBundles", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Napi get reminder info by bundles work excute.");
            AsyncCallbackInfoReminderInfo *asynccallbackinfo =
                static_cast<AsyncCallbackInfoReminderInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetReminderInfoByBundles(
                    asynccallbackinfo->bundles, asynccallbackinfo->reminderInfo);
            }
        },
        AsyncCompleteCallbackNapiGetReminderInfoByBundles,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

napi_value NapiSetReminderInfoByBundles(napi_env env, napi_callback_info info)
{
    ANS_LOGD("NapiSetReminderInfoByBundles");
    std::vector<NotificationReminderInfo> reminderInfo;
    if (ParseReminderInfoParameters(env, info, reminderInfo) == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoReminderInfo *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoReminderInfo {
            .env = env, .asyncWork = nullptr, .reminderInfo = reminderInfo};
    if (!asynccallbackinfo) {
        Common::NapiThrow(env, ERROR_INTERNAL_ERROR);
        return Common::JSParaError(env, nullptr);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setReminderInfoByBundles", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Napi set reminder info by bundles work excute.");
            AsyncCallbackInfoReminderInfo *asynccallbackinfo =
                static_cast<AsyncCallbackInfoReminderInfo *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetReminderInfoByBundles(
                    asynccallbackinfo->reminderInfo);
            }
        },
        AsyncCompleteCallbackNapiSetReminderInfoByBundles,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

}
}
