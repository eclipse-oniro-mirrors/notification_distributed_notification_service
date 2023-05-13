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
}
JSPushCallBack::JSPushCallBack(NativeEngine &engine) : engine_(engine) {}

JSPushCallBack::~JSPushCallBack() {}

void JSPushCallBack::SetJsPushCallBackObject(NativeValue *pushCallBackObject)
{
    pushCallBackObject_ = std::unique_ptr<NativeReference>(engine_.CreateReference(pushCallBackObject, 1));
}

bool JSPushCallBack::IsEqualPushCallBackObject(NativeValue *pushCallBackObject)
{
    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return false;
    }

    NativeValue *value = pushCallBackObject_->Get();
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return false;
    }

    return value->StrictEquals(pushCallBackObject);
}

bool JSPushCallBack::OnCheckNotification(const std::string &notificationData)
{
    AbilityRuntime::HandleEscape handleEscape(engine_);
    if (pushCallBackObject_ == nullptr) {
        ANS_LOGE("pushCallBackObject_ nullptr");
        return false;
    }

    NativeValue *value = pushCallBackObject_->Get();
    if (value == nullptr) {
        ANS_LOGE("Failed to get value");
        return false;
    }

    std::string pkgName;
    int32_t notifyId, contentType;
    ConvertJsonStringToValue(notificationData, pkgName, notifyId, contentType);
    ANS_LOGI(
        "pkgName=%{public}s, notifyId=%{public}d, contentType=%{public}d ", pkgName.c_str(), notifyId, contentType);

    NativeValue *jsResult = engine_.CreateObject();
    NativeObject *result = AbilityRuntime::ConvertNativeValueTo<NativeObject>(jsResult);
    result->SetProperty("bundleName", AbilityRuntime::CreateJsValue(engine_, pkgName));
    result->SetProperty("notificationId", AbilityRuntime::CreateJsValue(engine_, notifyId));
    result->SetProperty("contentType", AbilityRuntime::CreateJsValue(engine_, contentType));

    NativeValue *funcResult;
    NativeValue *argv[] = { jsResult };
    funcResult = handleEscape.Escape(engine_.CallFunction(value, value, argv, ARGC_ONE));

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
        if(!jsonobj.at("pkgName").is_string()){
            ANS_LOGE("Invalid JSON object pkgName");
            return;
        }
        pkgName = jsonobj.at("pkgName").get<std::string>();
    }
    if (jsonobj.find("notifyId") != jsonEnd) {
        if(!jsonobj.at("notifyId").is_number()){
            ANS_LOGE("Invalid JSON object notifyId");
            return;
        }
        notifyId = jsonobj.at("notifyId").get<int32_t>();
    }
    if (jsonobj.find("contentType") != jsonEnd) {
        if(!jsonobj.at("contentType").is_number()){
            ANS_LOGE("Invalid JSON object contentType");
            return;
        }
        contentType = jsonobj.at("contentType").get<int32_t>();
    }
}

bool JSPushCallBack::ConvertFunctionResult(NativeValue *funcResult)
{
    if (funcResult == nullptr || funcResult->TypeOf() != NativeValueType::NATIVE_OBJECT) {
        ANS_LOGE("funcResult TypeOf error.");
        return false;
    }

    NativeObject *obj = AbilityRuntime::ConvertNativeValueTo<NativeObject>(funcResult);
    if (obj == nullptr) {
        ANS_LOGE("obj is nullptr.");
        return false;
    }

    auto codeJsvalue = obj->GetProperty("code");
    if (codeJsvalue == nullptr || codeJsvalue->TypeOf() != NativeValueType::NATIVE_NUMBER) {
        ANS_LOGE("GetProperty code failed.");
        return false;
    }

    int32_t code = -1;
    if (!AbilityRuntime::ConvertFromJsValue(engine_, codeJsvalue, code)) {
        ANS_LOGE("Parse code failed.");
        return false;
    }

    auto messageJsvalue = obj->GetProperty("message");
    if (messageJsvalue == nullptr || messageJsvalue->TypeOf() != NativeValueType::NATIVE_STRING) {
        ANS_LOGE("GetProperty message failed.");
    }

    std::string message;
    if (!AbilityRuntime::ConvertFromJsValue(engine_, messageJsvalue, message)) {
        ANS_LOGE("Parse message failed.");
    }

    ANS_LOGI("code : %{public}d ,message : %{public}s", code, message.c_str());
    return code == 0;
}
} // namespace Notification
} // namespace OHOS