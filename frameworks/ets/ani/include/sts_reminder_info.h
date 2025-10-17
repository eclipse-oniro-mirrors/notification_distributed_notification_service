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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_REMINDER_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_REMINDER_INFO_H
#include "ani.h"
#include "notification_bundle_option.h"
#include "notification_reminder_info.h"

using ReminderInfo = OHOS::Notification::NotificationReminderInfo;
namespace OHOS {
namespace NotificationSts {
ani_object GetAniArrayReminderInfo(ani_env* env, const std::vector<ReminderInfo> &reminders);
bool UnwrapArrayReminderInfo(ani_env *env, ani_ref arrayObj, std::vector<ReminderInfo>& reminders);
} // namespace NotificationSts
} // OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_REMINDER_INFO_H
