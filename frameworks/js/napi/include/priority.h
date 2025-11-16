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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_PRIORITY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_PRIORITY_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;
struct EnabledParams {
    bool enable = false;
};

struct EnabledByBundleParams {
    NotificationBundleOption option;
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
};

struct ConfigByBundleParams {
    NotificationBundleOption option;
    std::string configValue;
};

struct AsyncCallbackInfoEnabled {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    bool enable = false;
};

struct AsyncCallbackInfoEnabledByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    NotificationBundleOption option;
    NotificationConstant::PriorityEnableStatus enableStatus =
        NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT;
};

struct AsyncCallbackInfoConfigByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    NotificationBundleOption option;
    std::string configValue;
};

napi_value ParsePriorityParameters(const napi_env &env, const napi_callback_info &info, EnabledParams &params);
napi_value ParsePriorityParameters(const napi_env &env, const napi_callback_info &info, EnabledByBundleParams &params);
napi_value ParsePriorityParameters(const napi_env &env, const napi_callback_info &info, ConfigByBundleParams &params);
napi_value ParseIsPriorityEnabledParameters(
    const napi_env &env, const napi_callback_info &info, EnabledByBundleParams &params);
napi_value ParseGetPriorityConfigParameters(
    const napi_env &env, const napi_callback_info &info, ConfigByBundleParams &params);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_PRIORITY_H