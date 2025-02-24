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
    DisturbManager();
    ~DisturbManager() = default;
    using ExecutionType = std::function<ErrCode(MessageParcel &data, MessageParcel &reply)>;
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
    ErrCode HandleRemoveDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleAddDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDoNotDisturbProfile(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDoesSupportDoNotDisturbMode(MessageParcel &data, MessageParcel &reply);

private:
    int32_t CheckSystemAndControllerPermission();
    void AdjustDateForDndTypeOnce(int64_t &beginDate, int64_t &endDate);
    ErrCode SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date);

    ErrCode RemoveDoNotDisturbProfilesSyncQueue(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);
    ErrCode GetDoNotDisturbDateSyncQueue(sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetDoNotDisturbDateByUserSyncQueue(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date);
    ErrCode SetDoNotDisturbDateByUserSyncQueue(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date);
    ErrCode AddDoNotDisturbProfilesSyncQueue(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);

    ErrCode SetDoNotDisturbDateByUserInner(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetDoNotDisturbDateByUserInner(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetDoNotDisturbProfileInner(int32_t id, sptr<NotificationDoNotDisturbProfile> &profile);
    ErrCode DoesSupportDoNotDisturbModeInner(bool &doesSupport);
private:
    std::map<uint32_t, ExecutionType> codeAndExecuteFuncMap_;
    std::map<uint32_t, std::function<ErrCode()>> codeAndPermissionFuncMap_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_SERVICES_ANS_INCLUDE_DISTURB_MANAGER_H
