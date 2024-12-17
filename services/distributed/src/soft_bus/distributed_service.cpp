/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "distributed_service.h"

#include "notification_helper.h"
#include "distributed_client.h"
#include "request_box.h"
#include "state_box.h"
#include "in_process_call_wrapper.h"
#include "distributed_screenlock_service.h"

namespace OHOS {
namespace Notification {

DistributedService& DistributedService::GetInstance()
{
    static DistributedService distributedService;
    return distributedService;
}

DistributedService::DistributedService()
{
    serviceQueue_ = std::make_shared<ffrt::queue>("ans_distributed");
    if (serviceQueue_ == nullptr) {
        ANS_LOGW("ffrt create failed!");
        return;
    }
    ANS_LOGI("Distributed service init successfully.");
}

void DistributedService::initService(const std::string &deviceId, uint16_t deviceType)
{
    localDevice_.deviceId_ = deviceId;
    localDevice_.deviceType_ = deviceType;
}

void DistributedService::OnReceiveMsg(const void *data, uint32_t dataLen)
{
    if (!TlvBox::CheckMessageCRC((const unsigned char*)data, dataLen)) {
        ANS_LOGW("Dans check message crc failed.");
        return;
    }
    std::shared_ptr<TlvBox> box = std::make_shared<TlvBox>();
    if (!box->Parse((const unsigned char*)data, dataLen - sizeof(uint32_t))) {
        ANS_LOGW("Dans parse message failed.");
        return;
    }
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, box]() {
        int32_t type = NOTIFICATION_EVENT_TYPE_BUTT;
        if (!box->GetMessageType(type)) {
            ANS_LOGW("Dans invalid message type failed.");
            return;
        }
        switch (type) {
            case NotificationEventType::PUBLISH_NOTIFICATION:
                PublishNotifictaion(box);
                break;
            case NotificationEventType::NOTIFICATION_STATE_SYNC:
                SetDeviceState(box);
                break;
            default:
                ANS_LOGW("Dans receive msg %{public}d %{public}d.", type, box->bytesLength_);
                break;
        }
    });
    serviceQueue_->submit(task);
}

}
}
