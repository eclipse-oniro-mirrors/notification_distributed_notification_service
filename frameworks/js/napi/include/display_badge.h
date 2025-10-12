/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_DISPLAY_BADGE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_DISPLAY_BADGE_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct EnableBadgeParams {
    NotificationBundleOption option;
    bool enable = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoEnableBadge {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    EnableBadgeParams params;
    CallbackPromiseInfo info;
};

struct IsDisplayBadgeParams {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
    bool hasBundleOption = false;
};

struct AsyncCallbackInfoIsDisplayBadge {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    IsDisplayBadgeParams params;
    CallbackPromiseInfo info;
    bool enabled = false;
};

struct AsyncCallbackInfoBatchSetBadge {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::vector<std::pair<NotificationBundleOption, bool>> params;
    CallbackPromiseInfo info;
};

struct AsyncCallbackInfoBatchGetBadge {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::vector<NotificationBundleOption> bundles;
    CallbackPromiseInfo info;
    std::map<sptr<NotificationBundleOption>, bool> bundleEnable;
};

napi_value DisplayBadge(napi_env env, napi_callback_info info);
napi_value IsBadgeDisplayed(napi_env env, napi_callback_info info);

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, EnableBadgeParams &params);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, IsDisplayBadgeParams &params);
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_DISPLAY_BADGE_H