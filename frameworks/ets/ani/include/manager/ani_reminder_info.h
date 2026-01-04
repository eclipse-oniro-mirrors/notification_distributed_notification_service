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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_REMINDER_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_REMINDER_INFO_H
#include "ani.h"
#include "notification_reminder_info.h"
#include "concurrency_helpers.h"
#include "sts_callback_promise.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"

using ReminderInfo = OHOS::Notification::NotificationReminderInfo;
namespace OHOS {
namespace NotificationManagerSts {
struct AsyncCallbackReminderInfo {
    ani_vm* vm = nullptr;
    arkts::concurrency_helpers::AsyncWork* asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    std::vector<BundleOption> bundles;
    std::vector<ReminderInfo> reminders;
    bool isGetReminderInfo = false;
};

void HandleReminderFunctionCallbackComplete(ani_env* env, arkts::concurrency_helpers::WorkStatus status, void* data);

ani_object AniGetReminderInfoByBundles(ani_env *env, ani_object obj, ani_object callback);
ani_object AniSetReminderInfoByBundles(ani_env *env, ani_object obj, ani_object callback);
} // namespace NotificationManagerSts
} // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_REMINDER_INFO_H
