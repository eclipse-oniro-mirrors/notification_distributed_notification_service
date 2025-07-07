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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DO_NOT_DISTURB_DATA_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DO_NOT_DISTURB_DATA_H
#include "ani.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniSetDoNotDisturbDate(ani_env *env, ani_object date);
void AniSetDoNotDisturbDateWithId(ani_env *env, ani_object date, ani_double userId);
ani_object AniGetDoNotDisturbDate(ani_env *env);
ani_object AniGetDoNotDisturbDateWithId(ani_env *env, ani_double userId);
ani_boolean AniIsSupportDoNotDisturbMode(ani_env *env);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif