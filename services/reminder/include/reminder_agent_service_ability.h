/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_SERVICE_ABILITY_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_SERVICE_ABILITY_H

#include "system_ability.h"

#include "reminder_data_manager.h"
#include "reminder_agent_service.h"
#include "system_ability_definition.h"

namespace OHOS::Notification {
class ReminderAgentServiceAbility final : public SystemAbility {
public:
    /**
     * @brief The constructor of service ability.
     *
     * @param systemAbilityId Indicates the system ability id.
     * @param runOnCreate Run the system ability on created.
     */
    ReminderAgentServiceAbility(const int32_t systemAbilityId, bool runOnCreate);

    /**
     * @brief The destructor.
     */
    ~ReminderAgentServiceAbility() final;

    DISALLOW_COPY_AND_MOVE(ReminderAgentServiceAbility);
    DECLARE_SYSTEM_ABILITY(ReminderAgentServiceAbility);

private:
    void OnStart() final;
    void OnStop() final;

private:
    sptr<ReminderAgentService> service_;
    std::shared_ptr<ReminderDataManager> reminderDataManager_;
};
}  // namespace OHOS::Notification

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_REMINDER_INCLUDE_REMINDER_SERVICE_ABILITY_H
