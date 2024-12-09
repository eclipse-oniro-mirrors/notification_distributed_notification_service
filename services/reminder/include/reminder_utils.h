/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_UTILS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_UTILS_H

#include "ans_log_wrapper.h"
#include "reminder_bundle_manager_helper.h"
#include <memory>


namespace OHOS {
namespace Notification {
#define REMINDER_CHECK_NULL_VOID(ptr, msg)  \
    do {                                    \
        if ((ptr) == nullptr) {             \
            ANSR_LOGW("%{public}s", msg);   \
            return;                         \
        }                                   \
    } while (0)

#define REMINDER_CHECK_NULL_RETURN(ptr, msg, ret)   \
    do {                                            \
        if ((ptr) == nullptr) {                     \
            ANSR_LOGW("%{public}s", msg);           \
            return ret;                             \
        }                                           \
    } while (0)

inline std::string GetClientBundleNameByUid(int32_t callingUid)
{
    std::string bundle;

    std::shared_ptr<ReminderBundleManagerHelper> bundleManager = ReminderBundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        bundle = bundleManager->GetBundleNameByUid(callingUid);
    }

    return bundle;
}

inline std::string GetClientBundleName()
{
    return GetClientBundleNameByUid(IPCSkeleton::GetCallingUid());
}

inline int64_t GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

}  // namespace Notification
}  // namespace OHOS
#endif