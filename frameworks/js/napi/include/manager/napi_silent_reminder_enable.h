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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SILEMT_REMINDER_ENABLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SILEMT_REMINDER_ENABLE_H

#include "common.h"
#include <string>

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct SilentReminderEnableParams {
    NotificationBundleOption option;
    int32_t enableStatus = 0;
    bool enabled;
};
 
struct AsyncCallbackSilentReminderEnable {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    SilentReminderEnableParams params;
    CallbackPromiseInfo info;
};

napi_value NapiSetSilentReminderEnabled(napi_env env, napi_callback_info info);
napi_value NapiIsSilentReminderEnabled(napi_env env, napi_callback_info info);
}
}

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SILEMT_REMINDER_ENABLE_H