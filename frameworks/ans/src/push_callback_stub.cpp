/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "push_callback_stub.h"

#include "ans_log_wrapper.h"
#include "event_handler.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "push_callback_proxy.h"
#include "singleton.h"
#include "ans_inner_errors.h"
#include "nlohmann/json.hpp"

using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace Notification {
PushCallBackStub::PushCallBackStub() {}

PushCallBackStub::~PushCallBackStub() {}

enum PushCheckErrCode : int32_t {
    SUCCESS = 0,
    FIXED_PARAMETER_INVALID = 1,
    NETWORK_UNREACHABLE = 2,
    SPECIFIED_NOTIFICATIONS_FAILED = 3,
    SYSTEM_ERROR = 4,
    OPTIONAL_PARAMETER_INVALID = 5
};

ErrCode PushCallBackStub::ConvertPushCheckCodeToErrCode(int32_t pushCheckCode)
{
    ErrCode errCode;
    PushCheckErrCode checkCode = static_cast<PushCheckErrCode>(pushCheckCode);

    switch (checkCode) {
        case PushCheckErrCode::SUCCESS:
            errCode = ERR_OK;
            break;
        case PushCheckErrCode::FIXED_PARAMETER_INVALID:
            errCode = ERR_ANS_TASK_ERR;
            break;
        case PushCheckErrCode::NETWORK_UNREACHABLE:
            errCode = ERR_ANS_PUSH_CHECK_NETWORK_UNREACHABLE;
            break;
        case PushCheckErrCode::SPECIFIED_NOTIFICATIONS_FAILED:
            errCode = ERR_ANS_PUSH_CHECK_FAILED;
            break;
        case PushCheckErrCode::SYSTEM_ERROR:
            errCode = ERR_ANS_TASK_ERR;
            break;
        case PushCheckErrCode::OPTIONAL_PARAMETER_INVALID:
            errCode = ERR_ANS_PUSH_CHECK_EXTRAINFO_INVALID;
            break;
        default:
            errCode = ERR_ANS_PUSH_CHECK_FAILED;
            break;
    }
    return errCode;
}

int PushCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ANS_LOGD("called.");
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ANS_LOGE("local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }
    switch (code) {
        case static_cast<uint32_t>(NotificationInterfaceCode::ON_CHECK_NOTIFICATION): {
            auto notificationData = data.ReadString();
            int32_t checkResult = ERR_ANS_TASK_ERR;

            std::shared_ptr<PushCallBackParam> pushCallBackParam = std::make_shared<PushCallBackParam>();
            checkResult = this->OnCheckNotification(notificationData, pushCallBackParam);
            checkResult = ConvertPushCheckCodeToErrCode(checkResult);
            ANS_LOGI("Push check result:%{public}d,eventControl:%{public}s",
                checkResult, pushCallBackParam->eventControl.c_str());

            if (!reply.WriteInt32(checkResult)) {
                ANS_LOGE("Failed to write reply ");
                return ERR_INVALID_REPLY;
            }
            if (!reply.WriteString(pushCallBackParam->eventControl)) {
                ANS_LOGE("Failed to write reply ");
                return ERR_INVALID_REPLY;
            }
            return NO_ERROR;
        }

        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t PushCallBackProxy::OnCheckNotification(
    const std::string &notificationData, const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(PushCallBackProxy::GetDescriptor())) {
        ANS_LOGE("Write interface token failed.");
        return false;
    }

    if (!data.WriteString(notificationData)) {
        ANS_LOGE("Connect done element error.");
        return false;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        ANS_LOGE("Get Remote fail.");
        return false;
    }

    int error = remote->SendRequest(static_cast<uint32_t>(NotificationInterfaceCode::ON_CHECK_NOTIFICATION),
        data, reply, option);
    if (error != NO_ERROR) {
        ANS_LOGE("Connect done fail, error: %{public}d", error);
        return false;
    }

    int result = reply.ReadInt32();
    std::string eventControl;
    if (reply.ReadString(eventControl)) {
        HandleEventControl(eventControl, pushCallBackParam);
    }
    return result;
}

void PushCallBackProxy::HandleEventControl(
    std::string eventControl, const std::shared_ptr<PushCallBackParam> &pushCallBackParam)
{
    if (pushCallBackParam == nullptr) {
        ANS_LOGE("pushCallBackParam is null");
        return;
    }
    std::string event = pushCallBackParam->event;
    if (event.empty()) {
        ANS_LOGE("event is null");
        return;
    }
    ANS_LOGI("eventControl:%{public}s,event:%{public}s", eventControl.c_str(), event.c_str());
    if (eventControl.empty() || !nlohmann::json::accept(eventControl)) {
        return;
    }
    auto jsonObject = nlohmann::json::parse(eventControl);
    if (jsonObject.is_null() || !jsonObject.is_object()) {
        ANS_LOGE("jsonObject is not right");
        return;
    }
    if (jsonObject.find(event)  == jsonObject.cend()) {
        ANS_LOGE("This event has not eventControl");
        return;
    }
    pushCallBackParam->eventControl = jsonObject.at(event).dump();
}
} // namespace Notification
} // namespace OHOS
