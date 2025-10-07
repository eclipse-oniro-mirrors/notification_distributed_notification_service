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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_REMINDER_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_REMINDER_INFO_H

#include <string>
#include "common.h"
#include "notification_bundle_option.h"
#include "notification_reminder_info.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct AsyncCallbackInfoReminderInfo {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::vector<NotificationReminderInfo> reminderInfo;
    std::vector<NotificationBundleOption> bundles;
    CallbackPromiseInfo info;
};

napi_value NapiGetReminderInfoByBundles(napi_env env, napi_callback_info info);
napi_value NapiSetReminderInfoByBundles(napi_env env, napi_callback_info info);
}
}

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_REMINDER_INFO_H
