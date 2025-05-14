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

#ifndef OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_SUBSCRIBER_H
#define OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_SUBSCRIBER_H
#include "ani.h"
#include "sts_request.h"
#include "enabled_notification_callback_data.h"
#include "badge_number_callback_data.h"
#include "sts_sorting_map.h"

namespace OHOS {
namespace NotificationSts {
using EnabledNotificationCallbackData = OHOS::Notification::EnabledNotificationCallbackData;
using BadgeNumberCallbackData = OHOS::Notification::BadgeNumberCallbackData;

bool WarpSubscribeCallbackData(
    ani_env *env,
    const std::shared_ptr<NotificationSts> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason,
    ani_object &outObj);
bool WarpSubscribeCallbackDataArray(
    ani_env *env,
    const std::vector<std::shared_ptr<NotificationSts>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason,
    ani_object &outObj);
bool WarpEnabledNotificationCallbackData(
    ani_env *env, const std::shared_ptr<EnabledNotificationCallbackData> &callbackData, ani_object &outObj);
bool WarpBadgeNumberCallbackData(
    ani_env *env, const std::shared_ptr<BadgeNumberCallbackData> &badgeData, ani_object &outObj);
} // namespace NotificationSts
} // OHOS
#endif