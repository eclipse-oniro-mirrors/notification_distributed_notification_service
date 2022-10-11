/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMOVE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMOVE_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct BundleAndKeyInfo {
    NotificationBundleOption option;
    NotificationKey key;
};

struct RemoveParams {
    std::optional<std::string> hashcode {};
    std::optional<BundleAndKeyInfo> bundleAndKeyInfo {};
    int32_t userId = SUBSCRIBE_USER_INIT;
    int32_t removeReason = NotificationConstant::CANCEL_REASON_DELETE;
    bool hasUserId = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoRemove {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    RemoveParams params {};
    CallbackPromiseInfo info;
};

struct RemoveParamsGroupByBundle {
    NotificationBundleOption option;
    std::string groupName = "";
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoRemoveGroupByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    RemoveParamsGroupByBundle params {};
    CallbackPromiseInfo info;
};

napi_value Remove(napi_env env, napi_callback_info info);
napi_value RemoveAsBundle(napi_env env, napi_callback_info info);
napi_value RemoveAll(napi_env env, napi_callback_info info);
napi_value RemoveGroupByBundle(napi_env env, napi_callback_info info);

bool ParseBundleOptionTypeParams(const napi_env &env, napi_value* argv, size_t argc, RemoveParams &params);
bool ParseHashcodeTypeParams(const napi_env &env, napi_value* argv, size_t argc, RemoveParams &params);
bool ParseCallbackFunc(const napi_env &env, const napi_value &value, RemoveParams &params);
bool ParseRemoveReason(const napi_env &env, const napi_value &value, RemoveParams &params);
bool ParseParameters(const napi_env &env, const napi_callback_info &info, RemoveParams &params);
napi_value ParseParametersByRemoveAll(const napi_env &env, const napi_callback_info &info, RemoveParams &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, RemoveParamsGroupByBundle &params);
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMOVE_H