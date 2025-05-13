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

#ifndef OHOS_DISTRIBUTED_NOTIFICATION_SERVER_ANI_LOCAL_LIVE_VIEW_H
#define OHOS_DISTRIBUTED_NOTIFICATION_SERVER_ANI_LOCAL_LIVE_VIEW_H
#include "ani.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniTriggerSystemLiveView(
    ani_env *env, ani_object bundleOptionObj, ani_double notificationId, ani_object buttonOptionsObj);
void AniSubscribeSystemLiveView(ani_env *env, ani_object subscriberObj);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif