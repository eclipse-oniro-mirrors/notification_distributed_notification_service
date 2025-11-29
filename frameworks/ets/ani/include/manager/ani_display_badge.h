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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DISPLAY_BADGE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_DISPLAY_BADGE_H
#include "ani.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniDisplayBadge(ani_env *env, ani_object obj, ani_boolean enable);
ani_boolean AniIsBadgeDisplayed(ani_env *env, ani_object obj);
void AniSetBadgeNumber(ani_env *env, ani_int badgeNumber);
void AniSetBadgeNumberByBundle(ani_env *env, ani_object obj, ani_int badgeNumber);
void AniSetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj);
ani_object AniGetBadgeDisplayStatusByBundles(ani_env *env, ani_object obj);
ani_long AniGetBadgeNumber(ani_env *env);
void AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn);
void AniOffBadgeNumberQuery(ani_env *env);
void AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num);
}
}
#endif
