/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "slot.h"
#include "common.h"
#include "napi_common_util.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace NotificationNapi {
const int32_t ADD_SLOT_MAX_PARA = 2;
const int32_t ADD_SLOTS_MAX_PARA = 2;
const int32_t SET_SLOT_AS_BUNDLE_MAX_PARA = 3;
const int32_t GET_SLOT_MAX_PARA = 2;
const int32_t GET_SLOT_NUM_AS_BUNDLE_MAX_PARA = 2;
const int32_t GET_SLOTS_AS_BUNDLE_MAX_PARA = 2;
const int32_t GET_SLOT_AS_BUNDLE_MAX_PARA = 3;
const int32_t REMOVE_SLOT_MAX_PARA = 2;
const int32_t GET_ENABLE_SLOT_MAX_PARA = 3;
const int32_t SET_ENABLE_SLOT_MIN_PARA = 3;
const int32_t SET_ENABLE_SLOT_MAX_PARA = 5;

struct ParametersInfoAddSlot {
    NotificationSlot slot;
    NotificationConstant::SlotType inType = NotificationConstant::SlotType::OTHER;
    bool isAddSlotByType = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoAddSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationSlot slot;
    NotificationConstant::SlotType inType = NotificationConstant::SlotType::OTHER;
    bool isAddSlotByType = false;
    CallbackPromiseInfo info;
};

struct ParametersInfoAddSlots {
    std::vector<NotificationSlot> slots;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoAddSlots {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::vector<NotificationSlot> slots;
    CallbackPromiseInfo info;
};

struct ParametersInfoSetSlotByBundle {
    NotificationBundleOption option;
    std::vector<sptr<NotificationSlot>> slots;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoSetSlotByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoSetSlotByBundle params;
    CallbackPromiseInfo info;
};

struct ParametersInfoGetSlot {
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    CallbackPromiseInfo info;
    sptr<NotificationSlot> slot = nullptr;
};

struct ParametersInfoGetSlotNumByBundle {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlotNumByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotNumByBundle params;
    CallbackPromiseInfo info;
    uint64_t num = 0;
};

struct AsyncCallbackInfoGetSlots {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    std::vector<sptr<NotificationSlot>> slots;
};

struct ParametersInfoGetSlotsByBundle {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlotsByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotsByBundle params;
    CallbackPromiseInfo info;
    std::vector<sptr<NotificationSlot>> slots;
};

struct ParametersInfoGetSlotByBundle {
    NotificationBundleOption option;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlotByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotByBundle params;
    CallbackPromiseInfo info;
    sptr<NotificationSlot> slot;
};

struct ParametersInfoRemoveSlot {
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoRemoveSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    CallbackPromiseInfo info;
};

struct AsyncCallbackInfoRemoveAllSlots {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
};

struct ParametersInfoEnableSlot {
    NotificationBundleOption option;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    bool enable = false;
    bool isForceControl = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoInfoEnableSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoEnableSlot params;
    CallbackPromiseInfo info;
};

struct ParametersInfoIsEnableSlot {
    NotificationBundleOption option;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoInfoIsEnableSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoIsEnableSlot params;
    bool isEnable = false;
    CallbackPromiseInfo info;
};

struct ParametersInfoSetSlotFlagsByBundle {
    NotificationBundleOption option;
    uint32_t slotFlags;
    napi_ref callback = nullptr;
};

struct ParametersInfoGetSlotFlagsByBundle {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoSetSlotFlagsByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoSetSlotFlagsByBundle params;
    CallbackPromiseInfo info;
};

struct AsyncCallbackInfoGetSlotFlagsByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotFlagsByBundle params;
    CallbackPromiseInfo info;
    uint32_t slotFlags = 0;
};

napi_value ParseParametersByAddSlot(const napi_env &env, const napi_callback_info &info, ParametersInfoAddSlot &paras)
{
    ANS_LOGI("ParseParametersByAddSlot enter");
    size_t argc = ADD_SLOT_MAX_PARA;
    napi_value argv[ADD_SLOT_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: NotificationSlot
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object && valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Object or number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object or number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    if (valuetype == napi_number) {
        paras.isAddSlotByType = true;
        int32_t slotType = 0;
        napi_get_value_int32(env, argv[PARAM0], &slotType);
        if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), paras.inType)) {
            return nullptr;
        }
    } else {
        paras.isAddSlotByType = false;
        if (!Common::GetNotificationSlot(env, argv[PARAM0], paras.slot)) {
            return nullptr;
        }
    }

    // argv[1]:callback
    if (argc >= ADD_SLOT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
    }

    ANS_LOGI("ParseParametersByAddSlot OUT");
    return Common::NapiGetNull(env);
}

napi_value ParseParametersByAddSlots(const napi_env &env, const napi_callback_info &info, ParametersInfoAddSlots &paras)
{
    ANS_LOGI("ParseParametersByAddSlots enter");
    size_t argc = ADD_SLOTS_MAX_PARA;
    napi_value argv[ADD_SLOTS_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: Array<NotificationSlot>
    bool isArray = false;
    napi_is_array(env, argv[PARAM0], &isArray);
    if (!isArray) {
        ANS_LOGE("Wrong argument type. Array expected.");
        std::string msg = "Incorrect parameter types.The type of param must be array.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    uint32_t length = 0;
    napi_get_array_length(env, argv[PARAM0], &length);
    if (length == 0) {
        ANS_LOGE("The array is empty.");
        std::string msg = "Mandatory parameters are left unspecified. The array is empty.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    for (size_t i = 0; i < length; i++) {
        napi_value nSlot = nullptr;
        napi_get_element(env, argv[PARAM0], i, &nSlot);
        NAPI_CALL(env, napi_typeof(env, nSlot, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        NotificationSlot slot;
        if (!Common::GetNotificationSlot(env, nSlot, slot)) {
            return nullptr;
        }
        paras.slots.emplace_back(slot);
    }

    // argv[1]:callback
    if (argc >= ADD_SLOTS_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
    }
    ANS_LOGI("ParseParametersByAddSlots out");
    return Common::NapiGetNull(env);
}

napi_value ParseParametersSetSlotByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoSetSlotByBundle &params)
{
    ANS_LOGI("ParseParametersSetSlotByBundle enter");

    size_t argc = SET_SLOT_AS_BUNDLE_MAX_PARA;
    napi_value argv[SET_SLOT_AS_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < SET_SLOT_AS_BUNDLE_MAX_PARA - 1) {
        ANS_LOGE("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Argument type error. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: slot
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    NotificationSlot slot;
    if (!Common::GetNotificationSlot(env, argv[PARAM1], slot)) {
        return nullptr;
    }
    std::vector<NotificationSlot> slots;
    slots.emplace_back(slot);

    for (auto vec : slots) {
        sptr<NotificationSlot> slotPtr = new (std::nothrow) NotificationSlot(vec);
        if (slotPtr == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot ptr");
            std::string msg = "Parameter verification failed. Failed to create NotificationSlot ptr";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        params.slots.emplace_back(slotPtr);
    }

    // argv[2]:callback
    if (argc >= SET_SLOT_AS_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParametersByGetSlot(const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlot &paras)
{
    ANS_LOGD("enter");
    size_t argc = GET_SLOT_MAX_PARA;
    napi_value argv[GET_SLOT_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGE("Error number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: SlotType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Error argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int32_t slotType = 0;
    napi_get_value_int32(env, argv[PARAM0], &slotType);
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), paras.outType)) {
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= GET_SLOT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
    }
    return Common::NapiGetNull(env);
}

napi_value ParseParametersGetSlotNumByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotNumByBundle &params)
{
    ANS_LOGD("enter");

    size_t argc = GET_SLOT_NUM_AS_BUNDLE_MAX_PARA;
    napi_value argv[GET_SLOT_NUM_AS_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < GET_SLOT_NUM_AS_BUNDLE_MAX_PARA - 1) {
        ANS_LOGE("Error number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Argument type is error. Object anticipate.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= GET_SLOT_NUM_AS_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}


napi_value ParseParametersSetSlotFlagsByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoSetSlotFlagsByBundle &params)
    {
        ANS_LOGI("ParseParametersSetSlotByBundle enter");

        size_t argc = SET_SLOT_AS_BUNDLE_MAX_PARA;
        napi_value argv[SET_SLOT_AS_BUNDLE_MAX_PARA] = {nullptr};
        napi_value thisVar = nullptr;
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
        if (argc < SET_SLOT_AS_BUNDLE_MAX_PARA - 1) {
            ANS_LOGE("Wrong number of arguments.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
            return nullptr;
        }

        // argv[0]: bundle
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Argument type error. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
        if (retValue == nullptr) {
            ANS_LOGE("GetBundleOption failed.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }

        // argv[1]:slotFlags
        ANS_LOGI("ParseParametersSetSlotByBundle enter1");
        int32_t slotFlags = 0;
        napi_get_value_int32(env, argv[PARAM1], &slotFlags);
        params.slotFlags = slotFlags;
        ANS_LOGI("enter2");

        // argv[2]:callback
        if (argc >= SET_SLOT_AS_BUNDLE_MAX_PARA) {
            NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
            if (valuetype != napi_function) {
                ANS_LOGE("Callback is not function excute promise.");
                return Common::NapiGetNull(env);
            }
        ANS_LOGI("ParseParametersSetSlotByBundle enter3");
            napi_create_reference(env, argv[PARAM2], 1, &params.callback);
        }

        ANS_LOGI("ParseParametersSetSlotByBundle out!");
        return Common::NapiGetNull(env);
    }

napi_value ParseParametersGetSlotFlagsByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotFlagsByBundle &params)
    {
        ANS_LOGD("enter");

        size_t argc = GET_SLOTS_AS_BUNDLE_MAX_PARA;
        napi_value argv[GET_SLOTS_AS_BUNDLE_MAX_PARA] = {nullptr};
        napi_value thisVar = nullptr;
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
        if (argc < GET_SLOTS_AS_BUNDLE_MAX_PARA - 1) {
            ANS_LOGE("Wrong number of arguments");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
            return nullptr;
        }

        // argv[0]: bundle
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types.The type of param must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
        if (retValue == nullptr) {
            ANS_LOGE("GetBundleOption failed.");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            return nullptr;
        }

        // argv[1]:callback
        if (argc >= GET_SLOTS_AS_BUNDLE_MAX_PARA) {
            NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
            if (valuetype != napi_function) {
                ANS_LOGE("Callback is not function excute promise.");
                return Common::NapiGetNull(env);
            }
            napi_create_reference(env, argv[PARAM1], 1, &params.callback);
        }

        return Common::NapiGetNull(env);
    }

napi_value ParseParametersGetSlotsByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotsByBundle &params)
{
    ANS_LOGD("enter");

    size_t argc = GET_SLOTS_AS_BUNDLE_MAX_PARA;
    napi_value argv[GET_SLOTS_AS_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < GET_SLOTS_AS_BUNDLE_MAX_PARA - 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= GET_SLOTS_AS_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParametersGetSlotByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotByBundle &params)
{
    ANS_LOGD("enter");

    size_t argc = GET_SLOT_AS_BUNDLE_MAX_PARA;
    napi_value argv[GET_SLOT_AS_BUNDLE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < GET_SLOT_AS_BUNDLE_MAX_PARA - 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: SlotType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGW("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int slotType = 0;
    napi_get_value_int32(env, argv[PARAM1], &slotType);
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), params.outType)) {
        return nullptr;
    }

    // argv[2]:callback
    if (argc >= GET_SLOT_AS_BUNDLE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value ParseParametersByRemoveSlot(
    const napi_env &env, const napi_callback_info &info, ParametersInfoRemoveSlot &paras)
{
    ANS_LOGD("enter");
    size_t argc = REMOVE_SLOT_MAX_PARA;
    napi_value argv[REMOVE_SLOT_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    // argv[0]: SlotType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGE("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int32_t slotType = 0;
    napi_get_value_int32(env, argv[PARAM0], &slotType);
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), paras.outType)) {
        return nullptr;
    }

    // argv[1]:callback
    if (argc >= REMOVE_SLOT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &paras.callback);
    }
    return Common::NapiGetNull(env);
}

napi_value AddSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoAddSlot paras;
    if (ParseParametersByAddSlot(env, info, paras) == nullptr) {
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
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create addSlot string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "addSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("AddSlot work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlot *>(data);
            if (asynccallbackinfo) {
                ANS_LOGD("asynccallbackinfo is not nullptr.");
                if (asynccallbackinfo->isAddSlotByType) {
                    asynccallbackinfo->info.errorCode = NotificationHelper::AddSlotByType(asynccallbackinfo->inType);
                } else {
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::AddNotificationSlot(asynccallbackinfo->slot);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("AddSlot work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlot *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete addSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("AddSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("addSlot callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value AddSlots(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoAddSlots paras;
    if (ParseParametersByAddSlots(env, info, paras) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoAddSlots *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoAddSlots {.env = env, .asyncWork = nullptr, .slots = paras.slots};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("AddSlots work excute.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "addSlots", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("AddSlots work excute.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlots *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::AddNotificationSlots(asynccallbackinfo->slots);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("AddSlots work complete.");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoAddSlots *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete addSlots callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("AddSlots work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("addSlots callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SetSlotByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoSetSlotByBundle params {};
    if (ParseParametersSetSlotByBundle(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSetSlotByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSetSlotByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create setSlotByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setSlotByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("SetSlotByBundle napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::UpdateNotificationSlots(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.slots);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("SetSlotByBundle napi_create_async_work end");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotByBundle *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete setSlotByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("SetSlotByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("setSlotByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}


void AsyncCompleteCallbackGetSlot(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("GetSlot work complete.");

    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }

    auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlot *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is not nullptr.");
        napi_value result = Common::NapiGetNull(env);
        if (asynccallbackinfo->info.errorCode == ERR_OK) {
            if (asynccallbackinfo->slot != nullptr) {
                ANS_LOGD("slot is not nullptr.");
                napi_create_object(env, &result);
                if (!Common::SetNotificationSlot(env, *asynccallbackinfo->slot, result)) {
                    asynccallbackinfo->info.errorCode = ERROR;
                    result = Common::NapiGetNull(env);
                }
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete getSlot callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoGetSlot paras;
    if (ParseParametersByGetSlot(env, info, paras) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlot {.env = env, .asyncWork = nullptr, .outType = paras.outType};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getSlot string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetSlot napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::GetNotificationSlot(asynccallbackinfo->outType, asynccallbackinfo->slot);
            }
        },
        AsyncCompleteCallbackGetSlot,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("GetSlot callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetSlotNumByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoGetSlotNumByBundle params {};
    if (ParseParametersGetSlotNumByBundle(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotNumByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotNumByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("create getSlotNumByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotNumByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetSlotNumByBundle napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotNumByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotNumAsBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->num);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("GetSlotNumByBundle napi_create_async_work end");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlotNumByBundle *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_create_uint32(env, asynccallbackinfo->num, &result);
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete getSlotNumByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("GetSlotNumByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getSlotNumByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackGetSlots(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalid async callback data.");
        return;
    }
    napi_value result = nullptr;
    auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlots *>(data);
    if (asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is not nullptr.");
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            napi_create_array(env, &arr);
            size_t count = 0;
            for (auto vec : asynccallbackinfo->slots) {
                if (!vec) {
                    ANS_LOGW("Invalidity NotificationSlot object ptr.");
                    continue;
                }
                napi_value nSlot = nullptr;
                napi_create_object(env, &nSlot);
                if (!Common::SetNotificationSlot(env, *vec, nSlot)) {
                    ANS_LOGD("SetNotificationSlot is null.");
                    continue;
                }
                napi_set_element(env, arr, count, nSlot);
                count++;
            }
            ANS_LOGI("getSlots count : %{public}zu", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->slots.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete getSlots callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetSlots(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoGetSlots {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo failed.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getSlots string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlots", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetSlots napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlots *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlots(asynccallbackinfo->slots);
            }
        },
        AsyncCompleteCallbackGetSlots,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getSlots callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

void AsyncCompleteCallbackGetSlotsByBundle(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("enter");
    if (!data) {
        ANS_LOGE("Invalidated async callback data.");
        return;
    }
    napi_value result = nullptr;
    auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotsByBundle *>(data);
    if (asynccallbackinfo) {
        ANS_LOGE("asynccallbackinfo is not nullptr.");
        if (asynccallbackinfo->info.errorCode != ERR_OK) {
            result = Common::NapiGetNull(env);
        } else {
            napi_value arr = nullptr;
            napi_create_array(env, &arr);
            size_t count = 0;
            for (auto vec : asynccallbackinfo->slots) {
                if (!vec) {
                    ANS_LOGW("Invalidity NotificationSlot object ptr");
                    continue;
                }
                napi_value nSlot = nullptr;
                napi_create_object(env, &nSlot);
                if (!Common::SetNotificationSlot(env, *vec, nSlot)) {
                    ANS_LOGD("Set notification slot is nullptr.");
                    continue;
                }
                napi_set_element(env, arr, count, nSlot);
                count++;
            }
            ANS_LOGI("GetSlotsByBundle count = %{public}zu", count);
            result = arr;
            if ((count == 0) && (asynccallbackinfo->slots.size() > 0)) {
                asynccallbackinfo->info.errorCode = ERROR;
                result = Common::NapiGetNull(env);
            }
        }
        Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
        if (asynccallbackinfo->info.callback != nullptr) {
            ANS_LOGD("Delete getSlotsByBundle callback reference.");
            napi_delete_reference(env, asynccallbackinfo->info.callback);
        }
        napi_delete_async_work(env, asynccallbackinfo->asyncWork);
        delete asynccallbackinfo;
        asynccallbackinfo = nullptr;
    }
}

napi_value GetSlotsByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoGetSlotsByBundle params {};
    if (ParseParametersGetSlotsByBundle(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotsByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotsByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo failed.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create getSlotsByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotsByBundle", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetSlotsByBundle napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotsByBundle *>(data);
            if (asynccallbackinfo) {
            asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotsForBundle(
                asynccallbackinfo->params.option, asynccallbackinfo->slots);
            }
        },
        AsyncCompleteCallbackGetSlotsByBundle,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getSlotsByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value RemoveSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoRemoveSlot paras;
    if (ParseParametersByRemoveSlot(env, info, paras) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoRemoveSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoRemoveSlot {.env = env, .asyncWork = nullptr, .outType = paras.outType};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, paras.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, paras.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create removeSlot string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("removeSlot napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::RemoveNotificationSlot(asynccallbackinfo->outType);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("removeSlot napi_create_async_work end");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveSlot *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete removeSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("removeSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("removeSlot callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value RemoveAllSlots(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    if (Common::ParseParaOnlyCallback(env, info, callback) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    auto *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoRemoveAllSlots {.env = env, .asyncWork = nullptr};
    if (!asynccallbackinfo) {
        ANS_LOGD("Create asynccallbackinfo failed.");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create removeAll string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "removeAll", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("RemoveAllSlots napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveAllSlots *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::RemoveAllSlots();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("RemoveAllSlots napi_create_async_work end");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoRemoveAllSlots *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("RemoveAllSlots napi_delete_reference start");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("RemoveAllSlots work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("RemoveAllSlots callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

static napi_value ParseEnableSlotCallBackParam(
    const napi_env &env, size_t argc, napi_value *argv, ParametersInfoEnableSlot &params)
{
    // argv[4]: callback
    if (argc < SET_ENABLE_SLOT_MAX_PARA) {
        return Common::NapiGetNull(env);
    }
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM4], &valuetype));
    if (valuetype != napi_function) {
        ANS_LOGW("Callback is not function excute promise.");
        return Common::NapiGetNull(env);
    }
    napi_create_reference(env, argv[PARAM4], 1, &params.callback);
    return Common::NapiGetNull(env);
}

napi_value ParseParametersEnableSlot(
    const napi_env &env, const napi_callback_info &info, ParametersInfoEnableSlot &params)
{
    ANS_LOGD("enter");

    size_t argc = SET_ENABLE_SLOT_MAX_PARA;
    napi_value argv[SET_ENABLE_SLOT_MAX_PARA] = {nullptr};

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < SET_ENABLE_SLOT_MIN_PARA) {
        ANS_LOGW("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    if (!OHOS::AppExecFwk::IsTypeForNapiValue(env, argv[PARAM0], napi_object)) {
        ANS_LOGE("Parameter type is error. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: SlotType
    if (!OHOS::AppExecFwk::IsTypeForNapiValue(env, argv[PARAM1], napi_number)) {
        ANS_LOGE("Parameter type error. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int slotType = 0;
    napi_get_value_int32(env, argv[PARAM1], &slotType);
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), params.outType)) {
        return nullptr;
    }

    // argv[2]: enable
    if (!OHOS::AppExecFwk::IsTypeForNapiValue(env, argv[PARAM2], napi_boolean)) {
        ANS_LOGE("Wrong argument type. Bool expected.");
        std::string msg = "Incorrect parameter types.The type of param must be boolean.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_get_value_bool(env, argv[PARAM2], &params.enable);

    if (argc < SET_ENABLE_SLOT_MAX_PARA - 1) {
        return Common::NapiGetNull(env);
    }

    // argv[3]: maybe isForceControl or callback
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM3], &valuetype));
    if (valuetype == napi_boolean) {
        napi_get_value_bool(env, argv[PARAM3], &params.isForceControl);
    } else if (valuetype == napi_function) {
        napi_create_reference(env, argv[PARAM3], 1, &params.callback);
        return Common::NapiGetNull(env);
    } else {
        ANS_LOGI("Callback is not function excute promise.");
        return Common::NapiGetNull(env);
    }

    return ParseEnableSlotCallBackParam(env, argc, argv, params);
}

napi_value EnableNotificationSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoEnableSlot params {};
    if (ParseParametersEnableSlot(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoInfoEnableSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoInfoEnableSlot {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create EnableNotificationSlot string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "EnableNotificationSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("EnableNotificationSlot napi_create_async_work start");
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
            ANS_LOGI("EnableNotificationSlot napi_create_async_work end");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoEnableSlot *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete enableNotificationSlot callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("EnableNotificationSlot work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("enableNotificationSlot callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value ParseParametersIsEnableSlot(
    const napi_env &env, const napi_callback_info &info, ParametersInfoIsEnableSlot &params)
{
    ANS_LOGD("enter");

    size_t argc = GET_ENABLE_SLOT_MAX_PARA;
    napi_value argv[GET_ENABLE_SLOT_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < GET_ENABLE_SLOT_MAX_PARA - 1) {
        ANS_LOGW("Wrong number of arguments.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    // argv[0]: bundle
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGW("Wrong argument type. Object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    auto retValue = Common::GetBundleOption(env, argv[PARAM0], params.option);
    if (retValue == nullptr) {
        ANS_LOGE("GetBundleOption failed.");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
        return nullptr;
    }

    // argv[1]: SlotType
    NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
    if (valuetype != napi_number) {
        ANS_LOGW("Wrong argument type. Number expected.");
        std::string msg = "Incorrect parameter types.The type of param must be number.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    int slotType = 0;
    napi_get_value_int32(env, argv[PARAM1], &slotType);
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(slotType), params.outType)) {
        return nullptr;
    }

    // argv[2]:callback
    if (argc >= GET_ENABLE_SLOT_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGW("Callback is not function excute promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &params.callback);
    }

    return Common::NapiGetNull(env);
}

napi_value IsEnableNotificationSlot(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoIsEnableSlot params {};
    if (ParseParametersIsEnableSlot(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoInfoIsEnableSlot *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoInfoIsEnableSlot {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create IsEnableNotificationSlot string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "IsEnableNotificationSlot", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("IsEnableNotificationSlot napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoIsEnableSlot *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetEnabledForBundleSlot(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.outType, asynccallbackinfo->isEnable);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("IsEnableNotificationSlot napi_create_async_work end");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoInfoIsEnableSlot *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_get_boolean(env, asynccallbackinfo->isEnable, &result);
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("isEnableNotificationSlot callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value GetSlotFlagsByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGD("enter");

    ParametersInfoGetSlotFlagsByBundle params {};
    if (ParseParametersGetSlotFlagsByBundle(env, info, params) == nullptr) {
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoGetSlotFlagsByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoGetSlotFlagsByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("create getSlotFlagsByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "getSlotFlagsByBundle", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("GetSlotFlagsByBundle napi_create_async_work start");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoGetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::GetNotificationSlotFlagsAsBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->slotFlags);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("GetSlotFlagsByBundle napi_create_async_work end");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoGetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                napi_value result = nullptr;
                napi_create_uint32(env, asynccallbackinfo->slotFlags, &result);
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, result);
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete getSlotFlagsByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("GetSlotFlagsByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("getSlotFlagsByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

napi_value SetSlotFlagsByBundle(napi_env env, napi_callback_info info)
{
    ANS_LOGI("SetSlotFlagsByBundle enter");

    ParametersInfoSetSlotFlagsByBundle params {};
    if (ParseParametersSetSlotFlagsByBundle(env, info, params) == nullptr) {
        ANS_LOGI("Call ParseParametersSetSlotFlagsByBundle return nullptr");
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSetSlotFlagsByBundle *asynccallbackinfo =
        new (std::nothrow) AsyncCallbackInfoSetSlotFlagsByBundle {.env = env, .asyncWork = nullptr, .params = params};
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
        return Common::JSParaError(env, params.callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, params.callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create setSlotFlagsByBundle string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "setSlotFlagsByBundle", NAPI_AUTO_LENGTH, &resourceName);

    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGI("SetSlotFlagsByBundle napi_create_async_work start");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::SetNotificationSlotFlagsAsBundle(
                    asynccallbackinfo->params.option, asynccallbackinfo->params.slotFlags);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGI("SetSlotFlagsByBundle napi_create_async_work end");
            auto asynccallbackinfo = static_cast<AsyncCallbackInfoSetSlotFlagsByBundle *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete setSlotFlagsByBundle callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("SetSlotFlagsByBundle work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("setSlotFlagsByBundle callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
    ANS_LOGI("SetSlotFlagsByBundle out");
}

}  // namespace NotificationNapi
}  // namespace OHOS
