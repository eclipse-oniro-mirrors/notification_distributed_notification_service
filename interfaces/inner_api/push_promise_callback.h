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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_PROMISE_CALLBACK_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_PROMISE_CALLBACK_H

#include <mutex>
#include <condition_variable>

namespace OHOS {
namespace Notification {

struct PushCallBackParam {
    std::mutex callBackMutex;
    std::condition_variable callBackCondition;
    bool ready = false;
    int32_t result;
    std::string event;
    std::string eventControl;
};

class PromiseCallbackInfo {
public:
    static PromiseCallbackInfo *Create(const std::weak_ptr<PushCallBackParam> pushCallBackParam);

    static void Destroy(PromiseCallbackInfo *callbackInfo);

    std::weak_ptr<PushCallBackParam> GetJsCallBackParam();

private:
    PromiseCallbackInfo(const std::weak_ptr<PushCallBackParam> pushCallBackParam);

    ~PromiseCallbackInfo();

    std::weak_ptr<PushCallBackParam> pushCallBackParam_;
};
} // namespace Notification
} // namespace OHOS
#endif //BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PUSH_PROMISE_CALLBACK_H