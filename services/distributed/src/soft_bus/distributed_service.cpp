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
#include "distributed_observer_service.h"
#include "os_account_manager.h"
#include "distributed_server.h"
#include "distributed_device_data.h"
#include "distributed_timer_service.h"

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

int32_t DistributedService::InitService(const std::string &deviceId, uint16_t deviceType,
    std::function<bool(std::string, int32_t, bool)> callback)
{
    int32_t userId;
    localDevice_.deviceId_ = deviceId;
    localDevice_.deviceType_ = deviceType;
    if (DistributedServer::GetInstance().InitServer(deviceId, deviceType) != 0) {
        ANS_LOGI("Distributed service init server failed.");
        return -1;
    }

    if (OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId) == 0) {
        userId_ = userId;
    }
    if (callback == nullptr) {
        ANS_LOGI("Distributed service callback is null.");
        return -1;
    }
    callBack_ = callback;
    return 0;
}

void DistributedService::DestoryService()
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ANS_LOGI("Start destory service.");
        DistributedServer::GetInstance().ReleaseServer();
        for (auto& subscriberInfo : subscriberMap_) {
            int32_t result = NotificationHelper::UnSubscribeNotification(subscriberInfo.second);
            ANS_LOGI("UnSubscribe %{public}s %{public}d.", subscriberInfo.first.c_str(), result);
        }
    });
    serviceQueue_->wait(handler);
}

void DistributedService::AddDevice(DistributedDeviceInfo device)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    serviceQueue_->submit_h([&, device]() {
        SyncDeviceMatch(device, MatchType::MATCH_SYN);
        InitDeviceState(device);
        DistributedDeviceInfo deviceItem = device;
        deviceItem.peerState_ = DeviceState::STATE_SYNC;
        peerDevice_.insert(std::make_pair(deviceItem.deviceId_, deviceItem));
        DistributedTimerService::GetInstance().CancelTimer(localDevice_.deviceId_);
        if (callBack_ == nullptr) {
            ANS_LOGW("Dans status callback is null.");
        } else {
            callBack_(device.deviceId_, DeviceState::STATE_SYNC, false);
        }
        DistributedTimerService::GetInstance().StartTimer(device.deviceId_,
            GetCurrentTime() + TEN_SECEND);
    });
}

void DistributedService::ReportDeviceStatus(std::string deviceId)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    serviceQueue_->submit_h([&, deviceId]() {
        ANS_LOGI("Report device status %{public}s.", deviceId.c_str());
        auto iter = peerDevice_.find(deviceId);
        if (iter != peerDevice_.end() &&
            iter->second.peerState_ == DeviceState::STATE_ONLINE) {
            return;
        }
        if (callBack_ == nullptr) {
            ANS_LOGE("Report device status callback is null.");
            return;
        }

        if (callBack_(deviceId, 0, true)) {
            DistributedServer::GetInstance().ReleaseServer();
        }
        return;
    });
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
        int32_t type;
        if (!box->GetMessageType(type)) {
            ANS_LOGW("Dans invalid message type failed.");
            return;
        }
        switch (type) {
            case NotificationEventType::PUBLISH_NOTIFICATION:
                PublishNotifictaion(box);
                break;
            case NotificationEventType::NOTIFICATION_STATE_SYNC:
                HandleDeviceState(box);
                break;
            case NotificationEventType::NOTIFICATION_MATCH_SYNC:
                HandleMatchSync(box);
                break;
            default:
                ANS_LOGW("Dans receive msg %{public}d %{public}d.", type, box->bytesLength_);
                break;
        }
    });
    serviceQueue_->submit(task);
}

int64_t DistributedService::GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

}
}