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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_DISTURB_MANAGER_H
#define BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_DISTURB_MANAGER_H

#include <functional>
#include <map>

#include "ans_manager_interface.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "base_manager.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "iremote_stub.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
class DisturbManager final : protected BaseManager, public DelayedSingleton<DisturbManager> {
public:
    DisturbManager() = default;
    ~DisturbManager() = default;
public:
    /**
     * @brief Handle remote request.
     *
     * @param data Indicates the input parcel.
     * @param reply Indicates the output parcel.
     * @param option Indicates the message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
private:
    ErrCode RemoveDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply);
    ErrCode SetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply);
    ErrCode GetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply);

private:
    int32_t CheckInterfacePermission(uint32_t code);
    ErrCode RemoveDoNotDisturbProfilesInner(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    ErrCode SetDoNotDisturbDateInner(const sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetDoNotDisturbDateInner(sptr<NotificationDoNotDisturbDate> &date);
    ErrCode SetDoNotDisturbDateByUser(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetDoNotDisturbDateByUser(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date);
    void AdjustDateForDndTypeOnce(int64_t &beginDate, int64_t &endDate);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_DISTURB_MANAGER_H
