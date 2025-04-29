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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_ENABLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_ENABLE_H

#include "common.h"
#include <string>

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;
struct DistributedEnableParams {
    NotificationBundleOption option;
    std::string deviceType;
    bool enable = false;
};

struct AsyncCallbackDistributedEnable {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    DistributedEnableParams params;
    CallbackPromiseInfo info;
};

struct SmartReminderEnabledParams {
    std::string deviceType;
    bool enable = false;
};

struct AsyncCallbackSmartReminderEnabled {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    SmartReminderEnabledParams params;
    CallbackPromiseInfo info;
};

struct DistributedEnableBySlotParams {
    NotificationConstant::SlotType slot;
    std::string deviceType;
    bool enable = false;
};

struct AsyncCallbackDistributedEnableBySlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    DistributedEnableBySlotParams params;
    CallbackPromiseInfo info;
};
napi_value NapiSetDistributedEnabledByBundle(napi_env env, napi_callback_info info);
napi_value NapiSetSmartReminderEnabled(napi_env env, napi_callback_info info);
napi_value NapiIsSmartReminderEnabled(napi_env env, napi_callback_info info);
napi_value NapiSetDistributedEnabledBySlot(napi_env env, napi_callback_info info);
napi_value NapiIsDistributedEnabledBySlot(napi_env env, napi_callback_info info);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_ENABLE_H
