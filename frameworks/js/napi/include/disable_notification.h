/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISABLE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISABLE_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct AsyncCallbackInfoDisableNotification {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationDisable disableNotification;
    CallbackPromiseInfo info;
};

bool ParseDisabledParameters(const napi_env &env, const napi_value &value, bool &disabled);
bool ParseBundleListParameters(const napi_env &env, const napi_value &value, std::vector<std::string> &bundleList);
bool ParseUserIdParameters(const napi_env &env, const napi_value &value, int32_t &userId);
bool ParseDisableNotificationParameters(
    const napi_env &env, const napi_callback_info &info, NotificationDisable &paras);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISABLE_H