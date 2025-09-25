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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_NOTIFICATION_EXTENSION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_NOTIFICATION_EXTENSION_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct AsyncCallbackInfoNotificationExtensionSubscription {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> subscriptionInfo;
};

struct NotificationExtensionUserGrantedParams {
    NotificationBundleOption targetBundle;
    bool enabled = false;
    std::vector<sptr<NotificationBundleOption>> bundles;
};

struct AsyncCallbackInfoNotificationExtensionUserGranted {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    NotificationExtensionUserGrantedParams params;
};

napi_value NapiNotificationExtensionSubscribe(napi_env env, napi_callback_info info);
napi_value NapiNotificationExtensionUnsubscribe(napi_env env, napi_callback_info info);
napi_value NapiGetSubscribeInfo(napi_env env, napi_callback_info info);
napi_value NapiIsUserGranted(napi_env env, napi_callback_info info);
napi_value NapiGetUserGrantedState(napi_env env, napi_callback_info info);
napi_value NapiSetUserGrantedState(napi_env env, napi_callback_info info);
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_NOTIFICATION_EXTENSION_H