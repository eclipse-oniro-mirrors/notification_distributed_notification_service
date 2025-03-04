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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_OPERATION_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_OPERATION_CALLBACK_H

#include "ans_operation_callback_stub.h"

#include "uv.h"
#include "subscribe.h"

namespace OHOS::NotificationNapi {

class DistributedOperationCallback : public OperationCallbackStub {
public:
    explicit DistributedOperationCallback(const AsyncOperationCallbackInfo &asyncCallbackInfo);
    ~DistributedOperationCallback() override;
    void OnOperationCallback(const int32_t operationResult) override;

private:
    static void UvWorkOnCallBack(uv_work_t *work, int32_t status);

private:
    AsyncOperationCallbackInfo asyncCallbackInfo_;
};
} // namespace OHOS::NotificationNapi

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_DISTRIBUTED_OPERATION_CALLBACK_H
