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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_RINGTONE_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_RINGTONE_INFO_H
#include "ani.h"
#include "notification_ringtone_info.h"

using NotificationRingtoneInfo = OHOS::Notification::NotificationRingtoneInfo;
namespace OHOS {
namespace NotificationSts {
bool UnwrapRingtoneInfo(ani_env *env, ani_object obj, NotificationRingtoneInfo &ringtoneInfo);
bool WrapRingtoneInfo(ani_env *env, const NotificationRingtoneInfo &ringtoneInfo, ani_object &ringtoneInfoObject);
}  // namespace NotificationSts
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_RINGTONE_INFO_H