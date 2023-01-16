/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_H

#include "ability_record.h"
#include "iremote_object.h"

namespace OHOS {
namespace Notification {
class NotificationDialog {
public:
    NotificationDialog() = default;
    ~NotificationDialog() = default;

    /**
     * @brief  To judge whether the caller is current application.
     *
     * @param abilityRecord The abilityRecord of comparison.
     * @return true if it is selfcalled, else not.
     */
    bool JudgeSelfCalled(const std::shared_ptr<AAFwk::AbilityRecord> &abilityRecord);

    /**
     * @brief To start the enableNotificationDialog ability.
     *
     * @param callbackInfo The callbackInfo.
     * @return ERR_OK if success, else not.
     */
    ErrCode StartEnableNotificationDialogAbility();
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_H