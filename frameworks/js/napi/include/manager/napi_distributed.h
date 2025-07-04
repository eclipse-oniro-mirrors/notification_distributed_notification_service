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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

napi_value NapiIsDistributedEnabled(napi_env env, napi_callback_info info);
napi_value NapiEnableDistributed(napi_env env, napi_callback_info info);
napi_value NapiEnableDistributedByBundle(napi_env env, napi_callback_info info);
napi_value NapiEnableDistributedSelf(napi_env env, napi_callback_info info);
napi_value NapiIsDistributedEnableByBundle(napi_env env, napi_callback_info info);
napi_value NapiGetDeviceRemindType(napi_env env, napi_callback_info info);
napi_value NapiSetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info);
napi_value NapiGetSyncNotificationEnabledWithoutApp(napi_env env, napi_callback_info info);
napi_value NapiSetTargetDeviceStatus(napi_env env, napi_callback_info info);
napi_value NapiSetDistributedEnabled(napi_env env, napi_callback_info info);
napi_value NapiGetDistributedDeviceList(napi_env env, napi_callback_info info);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_H
