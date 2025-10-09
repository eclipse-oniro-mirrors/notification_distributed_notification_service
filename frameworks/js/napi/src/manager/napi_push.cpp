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
#include "common.h"
#include "ipc_skeleton.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "tokenid_kit.h"
#include "napi_common_util.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
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
    if (me == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return nullptr;
    }
    return me->OnRegisterPushCallback(env, info);
}

napi_value NapiPush::UnregisterPushCallback(napi_env env, napi_callback_info info)
{
    NapiPush *me = CheckParamsAndGetThis<NapiPush>(env, info);
    if (me == nullptr) {
        Common::NapiThrow(env, ERROR_PARAM_INVALID);
        return nullptr;
    }
    return me->OnUnregisterPushCallback(env, info);
}

napi_value NapiPush::OnRegisterPushCallback(napi_env env, const napi_callback_info info)
{
    ANS_LOGD("called");
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    size_t argc = ARGC_THREE;
    napi_value argv[ARGC_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, NULL));
    if (argc == ARGC_TWO) {
        ANS_LOGE("Old function param, don't need register.");
        return undefined;
    }
    if (argc < ARGC_THREE) {
        ANS_LOGE("The param is invalid.");
        ThrowTooFewParametersError(env);
        return undefined;
    }

    std::string type = AppExecFwk::UnwrapStringFromJS(env, argv[INDEX_ZERO]);
    if (type != "checkNotification") {
        ANS_LOGE("The type is not checkNotification");
        ThrowError(env, ERROR_PARAM_INVALID);
        return undefined;
    }

    sptr<NotificationCheckRequest> checkRequest = new NotificationCheckRequest();
    if (ParseCheckRequest(env, argv[INDEX_ONE], checkRequest) == nullptr) {
        ANS_LOGE("Failed to get check request info from param");
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
            ANS_LOGE("null jsPushCallBack_");
            ThrowError(env, ERROR_INTERNAL_ERROR);
            return undefined;
        }
    }
    NotificationConstant::SlotType outSlotType = checkRequest->GetSlotType();
    jsPushCallBack_->SetJsPushCallBackObject(outSlotType, argv[INDEX_TWO]);
    auto result = NotificationHelper::RegisterPushCallback(jsPushCallBack_->AsObject(), checkRequest);
    if (result != ERR_OK) {
        ANS_LOGE("result: %{public}d", result);
        ThrowError(env, OHOS::Notification::ErrorToExternal(result));
    }
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

napi_value NapiPush::ParseCheckRequest(const napi_env &env,
    const napi_value &obj, sptr<NotificationCheckRequest> &checkRequest)
{
    ANS_LOGD("start");

    if (!AppExecFwk::IsTypeForNapiValue(env, obj, napi_object)) {
        ANS_LOGE("Wrong argument type. Object expected.");
        return nullptr;
    }

    // contentType
    int32_t value = 0;
    if (!AppExecFwk::UnwrapInt32ByPropertyName(env, obj, "contentType", value)) {
        ANS_LOGE("Failed to get contentType from checkRequest.");
        return nullptr;
    }
    NotificationContent::Type outContentType = NotificationContent::Type::NONE;
    if (!AnsEnumUtil::ContentTypeJSToC(ContentType(value), outContentType)) {
        ANS_LOGE("Failed to convert contentType.");
        return nullptr;
    }
    checkRequest->SetContentType(outContentType);

    // slotType
    if (!AppExecFwk::UnwrapInt32ByPropertyName(env, obj, "slotType", value)) {
        ANS_LOGE("Failed to get slotType from checkRequest.");
        return nullptr;
    }
    NotificationConstant::SlotType outSlotType = NotificationConstant::SlotType::OTHER;
    if (!AnsEnumUtil::SlotTypeJSToC(SlotType(value), outSlotType)) {
        ANS_LOGE("Failed to convert slotType.");
        return nullptr;
    }
    checkRequest->SetSlotType(outSlotType);

    // extraInfoKeys
    std::vector<std::string> extraInfoKeys;
    if (!AppExecFwk::UnwrapStringArrayByPropertyName(env, obj, "extraInfoKeys", extraInfoKeys)) {
        ANS_LOGE("Failed to get extraInfoKeys from checkRequest.");
        return nullptr;
    }
    checkRequest->SetExtraKeys(extraInfoKeys);

    ANS_LOGD("end");
    return Common::NapiGetNull(env);
}

} // namespace NotificationNapi
} // namespace OHOS
