/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_ABILITY_MANAGER_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_ABILITY_MANAGER_HELPER_H

#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "ans_log_wrapper.h"
#include "distributed_operation_connection.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {

class AbilityManagerHelper {
public:
    AbilityManagerHelper();
    ~AbilityManagerHelper() = default;
    /**
     * @brief Get NotificationPreferences instance object.
     */
    static AbilityManagerHelper& GetInstance();

    int ConnectAbility(const std::string &eventId, const AAFwk::Want &want,
        const std::string& userInputKey, const std::string& userInput);
    void DisconnectServiceAbility(const std::string &eventId, const AppExecFwk::ElementName& element);

private:
    std::mutex connectionLock_;
    std::shared_ptr<ffrt::queue> operationQueue_ = nullptr;
    std::map<std::string, sptr<DistributedOperationConnection>> operationConnection_;
};
}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_ABILITY_MANAGER_HELPER_H
