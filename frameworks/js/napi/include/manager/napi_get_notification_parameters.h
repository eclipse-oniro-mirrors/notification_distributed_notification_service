/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANS_FRAMEWORKS_JS_NAPI_INCLUDE_MANAGER_NAPI_GET_NOTIFICATION_PARAMETERS_H
#define ANS_FRAMEWORKS_JS_NAPI_INCLUDE_MANAGER_NAPI_GET_NOTIFICATION_PARAMETERS_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct AsyncCallbackInfoNotificationParameters {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info {};
    int32_t notificationId = 0;
    std::string label = 0;
    sptr<NotificationParameters> parameters = nullptr;
};

napi_value NapiGetNotificationParameters(napi_env env, napi_callback_info info);

}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // ANS_FRAMEWORKS_JS_NAPI_INCLUDE_MANAGER_NAPI_GET_NOTIFICATION_PARAMETERS_H