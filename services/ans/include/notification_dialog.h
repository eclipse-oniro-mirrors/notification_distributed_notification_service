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

#include <string>

#include "iremote_object.h"

namespace OHOS {
namespace Notification {
class NotificationDialog {
public:
    /**
     * @brief To start the enableNotificationDialog ability.
     *
     * @param uid The uid of application that want launch notification dialog.
     * @return ERR_OK if success, else not.
     */
    static ErrCode StartEnableNotificationDialogAbility(
        const std::string &serviceBundleName,
        const std::string &serviceAbilityName,
        int32_t uid,
        std::string appBundleName,
        const sptr<IRemoteObject> &callerToken,
        const bool innerLake,
        const bool easyAbroad);

    static int32_t GetUidByBundleName(const std::string &bundleName);
};
} // namespace Notification
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_H
