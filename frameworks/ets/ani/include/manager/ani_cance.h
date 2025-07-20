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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_CANCEL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_CANCEL_H
#include "ani.h"

namespace OHOS {
namespace NotificationManagerSts {
void AniCancelAll(ani_env* env);
void AniCancelWithId(ani_env* env, ani_int id);
void AniCancelWithIdLabel(ani_env* env, ani_int id, ani_string label);
void AniCancelWithBundle(ani_env* env, ani_object bundleObj, ani_int id);
void AniCancelWithIdOptinalLabel(ani_env* env, ani_int id, ani_string label);
void AniCancelAsBundle(ani_env *env, ani_int id, ani_string representativeBundle, ani_int userId);
void AniCancelAsBundleWithBundleOption(ani_env *env, ani_object representativeBundle, ani_int id);
void AniCancelGroup(ani_env *env, ani_string groupName);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif

