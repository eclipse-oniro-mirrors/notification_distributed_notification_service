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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_UV_QUEUE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_UV_QUEUE_H

#include <iostream>

#include "napi/native_api.h"
#include "uv.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace NotificationNapi {

struct OperationOnCallBack {
    napi_env env;
    napi_value thisVar;
    napi_deferred deferred = nullptr;
    int32_t operationResult = 0;
};

class UvQueue {
public:
    static bool Call(napi_env env, OperationOnCallBack *data, uv_after_work_cb afterCallback);
};
}  // namespace NotificationNapi
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_UV_QUEUE_H
