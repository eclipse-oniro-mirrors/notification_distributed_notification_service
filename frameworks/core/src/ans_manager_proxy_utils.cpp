/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "message_option.h"
#include "message_parcel.h"
#include "parcel.h"
#include "ans_manager_proxy.h"

namespace OHOS {
namespace Notification {
ErrCode AnsManagerProxy::InnerTransact(NotificationInterfaceCode code,
    MessageOption &flags, MessageParcel &data, MessageParcel &reply)
{
    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("[InnerTransact] defeat: get Remote defeat code %{public}u", code);
        return ERR_DEAD_OBJECT;
    }
    int32_t err = remote->SendRequest(static_cast<uint32_t>(code), data, reply, flags);
    switch (err) {
        case NO_ERROR: {
            return ERR_OK;
        }
        case DEAD_OBJECT: {
            ANS_LOGE("[InnerTransact] defeat: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_DEAD_OBJECT;
        }
        default: {
            ANS_LOGE("[InnerTransact] defeat: ipcErr=%{public}d code %{public}d", err, code);
            return ERR_ANS_TRANSACT_FAILED;
        }
    }
}

ErrCode AnsManagerProxy::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(AnsManagerProxy::GetDescriptor())) {
        ANS_LOGE("[ShellDump] fail: write interface token failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteString(cmd)) {
        ANS_LOGE("[ShellDump] fail: write dump cmd failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteString(bundle)) {
        ANS_LOGE("[ShellDump] fail: write dump bundle failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(userId)) {
        ANS_LOGE("[ShellDump] fail: write dump userId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!data.WriteInt32(recvUserId)) {
        ANS_LOGE("[ShellDump] fail: write dump recvUserId failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    ErrCode result = InnerTransact(NotificationInterfaceCode::SHELL_DUMP, option, data, reply);
    if (result != ERR_OK) {
        ANS_LOGE("[ShellDump] fail: transact ErrCode=%{public}d", result);
        return ERR_ANS_TRANSACT_FAILED;
    }
    if (!reply.ReadInt32(result)) {
        ANS_LOGE("[ShellDump] fail: read result failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    if (!reply.ReadStringVector(&dumpInfo)) {
        ANS_LOGE("[ShellDump] fail: read dumpInfo failed.");
        return ERR_ANS_PARCELABLE_FAILED;
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
