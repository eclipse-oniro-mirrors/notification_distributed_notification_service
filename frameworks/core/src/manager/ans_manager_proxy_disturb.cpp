/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <unistd.h>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "ians_subscriber_local_live_view.h"
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerProxy::SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date)
{
    if (date == nullptr) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: date is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: write interface token error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(date)) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: write date failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        date = reply.ReadParcelable<NotificationDoNotDisturbDate>();
        if (date == nullptr) {
            ANS_LOGE("[GetDoNotDisturbDate] fail: read date error.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return result;
}

ErrCode AnsManagerProxy::AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!WriteParcelableVector(profiles, data)) {
        ANS_LOGE("Write profiles vector error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::ADD_DO_NOTDISTURB_PROFILES, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact ErrCode is %{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INVALID_PARAM;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!WriteParcelableVector(profiles, data)) {
        ANS_LOGE("Write profiles vector error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::REMOVE_DO_NOT_DISTURB_PROFILES, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("Transact ErrCode is %{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANS_LOGE("Read result error.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}

ErrCode AnsManagerProxy::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[DoesSupportDoNotDisturbMode] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::DOES_SUPPORT_DO_NOT_DISTURB_MODE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[DoesSupportDoNotDisturbMode] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[DoesSupportDoNotDisturbMode] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!reply.ReadBool(doesSupport)) {
        ANS_LOGE("[DoesSupportDoNotDisturbMode] fail: read doesSupport failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::SetDoNotDisturbDate(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date)
{
    if (date == nullptr) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: date is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: write userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteParcelable(date)) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: write date failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SET_DO_NOT_DISTURB_DATE_BY_USER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[SetDoNotDisturbDate] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetDoNotDisturbDate(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: write userId failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_DO_NOT_DISTURB_DATE_BY_USER, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[GetDoNotDisturbDate] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result == ERR_OK) {
        date = reply.ReadParcelable<NotificationDoNotDisturbDate>();
        if (date == nullptr) {
            ANS_LOGE("[GetDoNotDisturbDate] fail: read date failed.");
            return ERR_ANS_PARCELABLE_FAILED;
        }
    }

    return result;
}

ErrCode AnsManagerProxy::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[IsNeedSilentInDoNotDisturbMode] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteString(phoneNumber)) {
        ANS_LOGE("[IsNeedSilentInDoNotDisturbMode] fail: write phoneNumber failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(callerType)) {
        ANS_LOGE("[IsNeedSilentInDoNotDisturbMode] fail: write callerType failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::IS_NEED_SILENT_IN_DO_NOT_DISTURB_MODE,
        option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[IsNeedSilentInDoNotDisturbMode] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[IsNeedSilentInDoNotDisturbMode] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return result;
}

ErrCode AnsManagerProxy::GetDoNotDisturbProfile(int32_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("GetDoNotDisturbProfile write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (!data.WriteInt32(id)) {
        ANS_LOGE("GetDoNotDisturbProfile write id failed");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::GET_DONOTDISTURB_PROFILE, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("GetDoNotDisturbProfile transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }

    if (!reply.ReadInt32(result)) {
        ANS_LOGE("GetDoNotDisturbProfile read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    if (result != ERR_OK) {
        ANS_LOGE("GetDoNotDisturbProfile result failed %{public}d.", result);
        return result;
    }

    profile = reply.ReadParcelable<NotificationDoNotDisturbProfile>();
    if (profile == nullptr) {
        ANS_LOGE("GetDoNotDisturbProfile read data failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }

    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
