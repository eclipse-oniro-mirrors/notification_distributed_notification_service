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

#include "napi_push_callback.h"

#include "ans_log_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t ARGC_ONE = 1;
} // namespace
JSPushCallBack::JSPushCallBack(napi_env env) : env_(env) {}

JSPushCallBack::~JSPushCallBack() {}

void JSPushCallBack::SetJsPushCallBackObject(napi_value pushCallBackObject)
{
    napi_create_reference(env_, pushCallBackObject, 1, &pushCallBackObject_);
}

bool JSPushCallBack::IsEqualPushCallBackObject(napi_value pushCallBackObject)
{
    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return false;
    }
    napi_value value = nullptr;
    napi_get_reference_value(env_, pushCallBackObject_, &value);
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return false;
    }

    bool isEquals = false;
    napi_strict_equals(env_, value, pushCallBackObject, &isEquals);
    return isEquals;
}

bool JSPushCallBack::OnCheckNotification(const std::string &notificationData)
{
    AbilityRuntime::HandleEscape handleEscape(env_);
    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return false;
    }

    napi_value value = nullptr;
    napi_get_reference_value(env_, pushCallBackObject_, &value);
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return false;
    }

    std::string pkgName;
    int32_t notifyId, contentType;
    ConvertJsonStringToValue(notificationData, pkgName, notifyId, contentType);
    ANS_LOGI(
        "pkgName=%{public}s, notifyId=%{public}d, contentType=%{public}d ", pkgName.c_str(), notifyId, contentType);

    napi_value jsResult = nullptr;
    napi_create_object(env_, &jsResult);

    std::string bundleName = "bundleName";
    napi_value bundleNameNapiValue = nullptr;
    napi_value pkgNameNapiValue = nullptr;
    napi_create_string_utf8(env_, bundleName.c_str(), bundleName.length(), &bundleNameNapiValue);
    napi_create_string_utf8(env_, pkgName.c_str(), pkgName.length(), &pkgNameNapiValue);
    napi_set_property(env_, jsResult, bundleNameNapiValue, pkgNameNapiValue);

    std::string notificationId = "notificationId";
    napi_value notifyIdNapiValue = nullptr;
    napi_value notificationIdNapiValue = nullptr;
    napi_create_string_utf8(env_, notificationId.c_str(), notificationId.length(), &notificationIdNapiValue);
    napi_create_int32(env_, notifyId, &notifyIdNapiValue);
    napi_set_property(env_, jsResult, notificationIdNapiValue, notifyIdNapiValue);

    std::string contentTypeName = "contentType";
    napi_value contentTypeValueNapiValue = nullptr;
    napi_value contentTypeNameNapiValue = nullptr;
    napi_create_string_utf8(env_, contentTypeName.c_str(), contentTypeName.length(), &contentTypeNameNapiValue);
    napi_create_int32(env_, contentType, &contentTypeValueNapiValue);
    napi_set_property(env_, jsResult, contentTypeNameNapiValue, contentTypeValueNapiValue);

    napi_value funcResult;
    napi_value argv[] = { jsResult };

    napi_value resultOut = nullptr;
    napi_call_function(env_, value, value, ARGC_ONE, &argv[0], &resultOut);
    funcResult = handleEscape.Escape(resultOut);

    return ConvertFunctionResult(funcResult);
}

void JSPushCallBack::ConvertJsonStringToValue(
    const std::string &notificationData, std::string &pkgName, int32_t &notifyId, int32_t &contentType)
{
    nlohmann::json jsonobj = nlohmann::json::parse(notificationData);
    if (jsonobj.is_null() or !jsonobj.is_object()) {
        ANS_LOGE("Invalid JSON object");
        return;
    }

    const auto &jsonEnd = jsonobj.cend();
    if (jsonobj.find("pkgName") != jsonEnd) {
        if (!jsonobj.at("pkgName").is_string()) {
            ANS_LOGE("Invalid JSON object pkgName");
            return;
        }
        pkgName = jsonobj.at("pkgName").get<std::string>();
    }
    if (jsonobj.find("notifyId") != jsonEnd) {
        if (!jsonobj.at("notifyId").is_number()) {
            ANS_LOGE("Invalid JSON object notifyId");
            return;
        }
        notifyId = jsonobj.at("notifyId").get<int32_t>();
    }
    if (jsonobj.find("contentType") != jsonEnd) {
        if (!jsonobj.at("contentType").is_number()) {
            ANS_LOGE("Invalid JSON object contentType");
            return;
        }
        contentType = jsonobj.at("contentType").get<int32_t>();
    }
}

bool JSPushCallBack::ConvertFunctionResult(napi_value funcResult)
{
    if (funcResult == nullptr) {
        ANS_LOGE("The funcResult is error.");
        return false;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env_, napi_typeof(env_, funcResult, &valueType), false);
    if (valueType != napi_object) {
        ANS_LOGE("The funcResult is not napi_object.");
        return false;
    }
    bool hasProperty = false;
    NAPI_CALL_BASE(env_, napi_has_named_property(env_, funcResult, "code", &hasProperty), false);
    if (!hasProperty) {
        ANS_LOGE("GetProperty code failed.");
        return false;
    }

    napi_value codeValue = nullptr;
    napi_valuetype codeType = napi_undefined;
    napi_get_named_property(env_, funcResult, "code", &codeValue);
    NAPI_CALL_BASE(env_, napi_typeof(env_, codeValue, &codeType), false);

    if (codeType != napi_number) {
        ANS_LOGE("GetProperty code failed. Number expected.");
        return false;
    }
    int32_t code = -1;
    if (!AbilityRuntime::ConvertFromJsValue(env_, codeValue, code)) {
        ANS_LOGE("Parse code failed.");
        return false;
    }

    bool hasMessageProperty = false;
    NAPI_CALL_BASE(env_, napi_has_named_property(env_, funcResult, "message", &hasMessageProperty), false);
    if (!hasMessageProperty) {
        ANS_LOGE("Property message expected.");
        return false;
    }

    napi_value messageValue = nullptr;
    napi_valuetype messageType = napi_undefined;
    napi_get_named_property(env_, funcResult, "message", &messageValue);
    NAPI_CALL_BASE(env_, napi_typeof(env_, messageValue, &messageType), false);

    if (messageType != napi_string) {
        ANS_LOGE("GetProperty message failed. String expected.");
        return false;
    }

    std::string message;
    if (!AbilityRuntime::ConvertFromJsValue(env_, messageValue, message)) {
        ANS_LOGE("Parse message failed.");
        return false;
    }

    ANS_LOGI("code : %{public}d ,message : %{public}s", code, message.c_str());
    return code == 0;
}
} // namespace Notification
} // namespace OHOS