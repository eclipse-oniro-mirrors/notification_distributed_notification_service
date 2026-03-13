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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_SOUND_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_SOUND_HELPER_H

#include <memory>
#include <vector>
#include <string>

#include "singleton.h"
#include "ffrt.h"
#include "notification_ringtone_info.h"

namespace OHOS {
namespace Notification {
class SystemSoundHelper final {
public:
    static std::shared_ptr<SystemSoundHelper> GetInstance();
    void RemoveCustomizedTone(const std::string uri);

    void RemoveCustomizedTone(sptr<NotificationRingtoneInfo> ringtoneInfo);

    void RemoveCustomizedTones(std::vector<NotificationRingtoneInfo> ringtoneInfos);

private:
    static ffrt::mutex instanceMutex_;
    static std::shared_ptr<SystemSoundHelper> instance_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_SOUND_HELPER_H
