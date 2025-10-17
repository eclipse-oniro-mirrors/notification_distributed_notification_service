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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_EXTENSION_SUBSCRIPTION_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_EXTENSION_SUBSCRIPTION_INFO_H
 
#include "ani.h"
#include "notification_extension_subscription_info.h"
 
namespace OHOS {
namespace NotificationSts {
using NotificationExtensionSubscriptionInfo = OHOS::Notification::NotificationExtensionSubscriptionInfo;
ani_status UnwarpNotificationExtensionSubscribeInfo(ani_env *env, ani_object value,
    sptr<NotificationExtensionSubscriptionInfo> &info);
ani_status UnwarpNotificationExtensionSubscribeInfoArrayByAniObj(ani_env *env, ani_object arrayValue,
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> &infos);
bool WrapNotificationExtensionSubscribeInfo(ani_env *env, sptr<NotificationExtensionSubscriptionInfo> info,
    ani_object &outAniObj);
bool WrapNotificationExtensionSubscribeInfoArray(ani_env *env,
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>> &infos, ani_object &outAniObj);

enum class STSSubscribeType {
    BLUETOOTH = 0
};
}
}
#endif