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

#include "system_sound_manager.h"

namespace OHOS {
namespace Notification {
class SystemSoundDynamicWrapper final {
public:
    SystemSoundDynamicWrapper();
    ~SystemSoundDynamicWrapper() = default;
    static SystemSoundDynamicWrapper& GetInstance();
    bool RemoveCustomizedTone(const std::string uri);
    bool RemoveCustomizedToneList(const std::vector<std::string> uris);
private:
    std::shared_ptr<Media::SystemSoundManager> systemSoundClient_ = nullptr;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_SYSTEM_SOUND_HELPER_H
