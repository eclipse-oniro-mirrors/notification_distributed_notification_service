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

#ifdef PLAYER_FRAMEWORK_ENABLE
#include "system_sound_manager.h"
#endif

#include "singleton.h"
#include "ffrt.h"
#include "notification_ringtone_info.h"

namespace OHOS {
namespace Notification {
class SystemSoundHelper : public DelayedSingleton<SystemSoundHelper> {
public:
    void RemoveCustomizedTone(const std::string uri);

    void RemoveCustomizedTone(sptr<NotificationRingtoneInfo> ringtoneInfo);

    void RemoveCustomizedTones(std::vector<NotificationRingtoneInfo> ringtoneInfos);
#ifdef PLAYER_FRAMEWORK_ENABLE
    void Connect();
    int32_t InvokeRemoveCustomizedTone(const std::string uri, bool retry = false);
    std::vector<std::pair<std::string, int32_t>> InvokeRemoveCustomizedTones(
        const std::vector<std::string> uris, bool retry = false);
#endif
private:
    ffrt::mutex lock_;
#ifdef PLAYER_FRAMEWORK_ENABLE
    std::shared_ptr<Media::SystemSoundManager> systemSoundClient_ = nullptr;
#endif
    DECLARE_DELAYED_SINGLETON(SystemSoundHelper)
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_SOUND_HELPER_H
