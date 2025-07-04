/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_DISTRIBUTED_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_DISTRIBUTED_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

const int32_t DISTURB_DEFAULT_FLAG = 13;
struct AsyncCallbackInfoIsEnabled {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    bool enable = false;
    std::string deviceType;
};

struct EnabledParams {
    napi_ref callback = nullptr;
    bool enable = false;
    std::string deviceType;
};

struct AsyncCallbackInfoEnabled {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    EnabledParams params;
};

struct EnabledByBundleParams {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
    bool enable = false;
};

struct AsyncCallbackInfoEnabledByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    EnabledByBundleParams params;
};

struct IsEnabledByBundleParams {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
    std::string deviceType;
    bool hasDeviceType = false;
};

struct AsyncCallbackInfoIsEnabledByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    IsEnabledByBundleParams params;
    bool enable = false;
};

struct AsyncCallbackInfoGetRemindType {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::NONE;
};

struct EnabledWithoutAppParams {
    int32_t userId = SUBSCRIBE_USER_INIT;
    bool enable = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoEnabledWithoutApp {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    EnabledWithoutAppParams params;
};

struct GetEnabledWithoutAppParams {
    int32_t userId = SUBSCRIBE_USER_INIT;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetEnabledWithoutApp {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    GetEnabledWithoutAppParams params;
    bool enable = false;
};

struct DeviceStatus {
    std::string deviceType;
    int32_t status;
    napi_ref callback = nullptr;
};

struct AsynDeviceStatusConfig {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    DeviceStatus deviceStatus;
    CallbackPromiseInfo info;
};

struct AsynCallbackInfoGetDistributedDeviceList {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    std::vector<std::string> deviceList;
};

napi_value IsDistributedEnabled(napi_env env, napi_callback_info info);
napi_value EnableDistributed(napi_env env, napi_callback_info info);
napi_value EnableDistributedByBundle(napi_env env, napi_callback_info info);
napi_value EnableDistributedSelf(napi_env env, napi_callback_info info);
napi_value IsDistributedEnableByBundle(napi_env env, napi_callback_info info);
napi_value GetDeviceRemindType(napi_env env, napi_callback_info info);
napi_value SetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info);
napi_value GetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info);

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, DeviceStatus &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnabledParams &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnabledByBundleParams &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, IsEnabledByBundleParams &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnabledWithoutAppParams &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, GetEnabledWithoutAppParams &params);
napi_value ParseSetDistributedEnabledParams(const napi_env &env, const napi_callback_info &info, EnabledParams &params);
napi_value ParseIsDistributedEnabledParams(const napi_env &env, const napi_callback_info &info, EnabledParams &params);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_DISTRIBUTED_H
