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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_GET_ACTIVE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_GET_ACTIVE_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_callback_promise.h"
#include "sts_request.h"

namespace OHOS {
namespace NotificationManagerSts {
enum GetActiveFunction {
    GET_ACTIVE_NONE,
    GET_ACTIVE_NOTIFICATION_COUNT,
    GET_ALL_ACTIVE_NOTIFICATIONS,
    GET_ACTIVE_NOTIFICATIONS,
    GET_ACTIVE_NOTIFICATIONS_BY_FILTER,
};

struct AsyncCallbackActiveInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    GetActiveFunction functionType = GET_ACTIVE_NONE;
    uint64_t notificationNums = 0;
    std::vector<sptr<NotificationSts::NotificationSts>> notifications;
    std::vector<sptr<NotificationSts::NotificationRequest>> requests;
    sptr<OHOS::Notification::NotificationRequest> notificationRequest;
    Notification::LiveViewFilter liveViewFilter;
};

void HandleGetActiveFunctionComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniGetActiveNotificationCount(ani_env *env, ani_object callback);
ani_object AniGetAllActiveNotifications(ani_env *env, ani_object callback);
ani_object AniGetActiveNotifications(ani_env *env, ani_object callback);
ani_object AniGetActiveNotificationByFilter(ani_env *env, ani_object obj, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif

