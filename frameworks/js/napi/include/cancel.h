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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_CANCEL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_CANCEL_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct ParametersInfoCancel {
    int32_t id = 0;
    std::string label = "";
    napi_ref callback = nullptr;
    NotificationBundleOption option;
    bool hasOption = false;
};

struct AsyncCallbackInfoCancel {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    int32_t id = 0;
    std::string label;
    CallbackPromiseInfo info;
    NotificationBundleOption option;
    bool hasOption = false;
};

struct ParametersInfoCancelGroup {
    std::string groupName = "";
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoCancelGroup {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    ParametersInfoCancelGroup params {};
};

struct  ParametersInfoCancelAsBundle {
    int32_t id = 0;
    std::string representativeBundle = "";
    int32_t userId = 0;
    NotificationBundleOption option;
    bool hasOption = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoCancelAsBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    int32_t id = 0;
    std::string representativeBundle = "";
    int32_t userId = 0;
    NotificationBundleOption option;
    bool hasOption = false;
    CallbackPromiseInfo info;
};

napi_value Cancel(napi_env env, napi_callback_info info);
napi_value CancelAll(napi_env env, napi_callback_info info);
napi_value CancelGroup(napi_env env, napi_callback_info info);
napi_value CancelAsBundle(napi_env env, napi_callback_info info);

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoCancelAsBundle &paras);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoCancelGroup &paras);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, ParametersInfoCancel &paras);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_CANCEL_H