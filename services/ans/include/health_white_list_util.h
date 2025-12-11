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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_HEALTH_WHITE_LIST_UTIL_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_HEALTH_WHITE_LIST_UTIL_H
#include <string>

#include "errors.h"
#include "ans_inner_errors.h"
#include "notification_preferences.h"
#include "notification.h"

namespace OHOS {
namespace Notification {
class HealthWhiteListUtil : public DelayedSingleton<HealthWhiteListUtil> {
public:
    HealthWhiteListUtil();
    ~HealthWhiteListUtil();
    bool CheckInLiveViewList(const std::string& bundleName);
    void AddExtendFlagForRequest(std::vector<sptr<Notification>> &notifications);

private:
    bool ParseDbDate(nlohmann::json& bundles);
};
}  // namespace OHOS::Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_HEALTH_WHITE_LIST_UTIL_H
