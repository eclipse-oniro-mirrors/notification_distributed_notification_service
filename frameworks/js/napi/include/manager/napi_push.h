/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_PUSH_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_PUSH_H

#include "common.h"
#include "napi_push_callback.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

class NapiPush {
public:
    NapiPush() = default;
    ~NapiPush() = default;
    static void Finalizer(napi_env env, void *data, void *hint);
    static napi_value RegisterPushCallback(napi_env env, napi_callback_info info);
    static napi_value UnregisterPushCallback(napi_env env, napi_callback_info info);
private:
    sptr<OHOS::Notification::JSPushCallBack> jsPushCallBack_;
    napi_value OnRegisterPushCallback(napi_env env, const napi_callback_info info);
    napi_value OnUnregisterPushCallback(napi_env env, const napi_callback_info info);
    bool CheckCallerIsSystemApp();
    napi_value ParseCheckRequest(const napi_env &env,
        const napi_value &obj, sptr<NotificationCheckRequest> &checkRequest);
};
} // namespace NotificationNapi
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_PUSH_H
