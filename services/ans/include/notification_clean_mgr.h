/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLEAN_MGR_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLEAN_MGR_H

#include <string>
#include <vector>

#include "notification_ringtone_info.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
class NotificationCleanMgr : public DelayedSingleton<NotificationCleanMgr> {
public:
    NotificationCleanMgr();
    ~NotificationCleanMgr();

    int32_t OnClean();

    static int32_t CollectRingtoneInfos(const std::string &mirrorDbDir,
        std::vector<NotificationRingtoneInfo> &ringtoneInfos);

private:
    void CleanCustomizedTones(const std::string &mirrorDbDir);

    void NotifyCleanupStart();

    int32_t CleanRdbFiles(const std::string &mirrorDbDir);

    int32_t CleanKeyFileDir(const std::string &mirrorDbDir);

    std::string GetMirrorDbDir();
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_CLEAN_MGR_H
