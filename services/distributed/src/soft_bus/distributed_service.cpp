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

#include <thread>
#include "notification_helper.h"
#include "distributed_client.h"
#include "request_box.h"
#include "state_box.h"
#include "in_process_call_wrapper.h"
#include "distributed_observer_service.h"
#include "os_account_manager.h"
#include "distributed_server.h"
#include "common_event_support.h"
#include "distributed_device_data.h"
#include "distributed_bundle_service.h"
#include "distributed_device_service.h"
#include "distributed_operation_service.h"
#include "distributed_publish_service.h"
#include "distributed_subscribe_service.h"
#include "bundle_resource_helper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {

static const std::string DISTRIBUTED_LABEL = "ans_distributed";

namespace {
static const int32_t ADD_DEVICE_SLEEP_TIMES_MS = 1000;  // 1s
static const uint64_t SYNC_TASK_DELAY = 7 * 1000 * 1000;
}

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

std::string DistributedService::GetNotificationKey(const std::shared_ptr<Notification>& notification)
{
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
        return "";
    }
    std::string notificationKey = notification->GetKey();
    if (notification->GetNotificationRequestPoint()->GetDistributedCollaborate()) {
        size_t pos = notificationKey.find(DISTRIBUTED_LABEL);
        if (pos != std::string::npos) {
            notificationKey.erase(pos, DISTRIBUTED_LABEL.length());
        }
    } else {
        notificationKey = DISTRIBUTED_LABEL + notificationKey;
    }
    return notificationKey;
}

int32_t DistributedService::InitService(const std::string &deviceId, uint16_t deviceType)
{
    DistributedDeviceService::GetInstance().InitLocalDevice(deviceId, deviceType);
    if (DistributedServer::GetInstance().InitServer(deviceId, deviceType) != 0) {
        ANS_LOGI("Distributed service init server failed.");
        return -1;
    }
    OberverService::GetInstance().Init(deviceType);
    return 0;
}

void DistributedService::DestroyService()
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    ffrt::task_handle handler = serviceQueue_->submit_h([&]() {
        ANS_LOGI("Start destory service.");
        DistributedClient::GetInstance().ReleaseClient();
        DistributedServer::GetInstance().ReleaseServer();
        OberverService::GetInstance().Destory();
#ifdef DISTRIBUTED_FEATURE_MASTER
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UnSubscribeAllConnect();
#endif
        DistributedSubscribeService::GetInstance().UnSubscribeAllNotification();
    });
    serviceQueue_->wait(handler);
}

void DistributedService::ConnectPeerDevice(DistributedDeviceInfo device)
{
    if (!DistributedDeviceService::GetInstance().CheckDeviceNeedSync(device.deviceId_)) {
        ANS_LOGI("ConnectPeerDevice device is failed.");
        return;
    }

    int32_t result = DistributedDeviceService::GetInstance().SyncDeviceMatch(device, MatchType::MATCH_SYN);
    ANS_LOGI("ConnectPeerDevice try %{public}d.", result);
    DistributedDeviceService::GetInstance().IncreaseDeviceSyncCount(device.deviceId_);
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    serviceQueue_->submit_h([&, device]() { ConnectPeerDevice(device); },
        ffrt::task_attr().name("sync").delay(SYNC_TASK_DELAY));
}

void DistributedService::AddDevice(DistributedDeviceInfo device)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    serviceQueue_->submit_h([&, device]() {
        ANS_LOGI("Dans AddDevice %{public}s %{public}d", StringAnonymous(device.deviceId_).c_str(),
            device.deviceType_);
        DistributedDeviceInfo deviceItem = device;
        deviceItem.peerState_ = DeviceState::STATE_SYNC;
        DistributedDeviceService::GetInstance().AddDeviceInfo(deviceItem);
        if (device.IsPadOrPc() || DistributedDeviceService::GetInstance().IsLocalPadOrPC()) {
            ANS_LOGI("Dans wait peer %{public}s.", StringAnonymous(device.deviceId_).c_str());
            return;
        }
        // Delay linking to avoid bind failure, There is a delay in reporting the device online
        auto sleepTime = std::chrono::milliseconds(ADD_DEVICE_SLEEP_TIMES_MS);
        std::this_thread::sleep_for(sleepTime);
        ConnectPeerDevice(device);
    });
}

void DistributedService::ReleaseDevice(const std::string &deviceId, uint16_t deviceType)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> subscribeTask = std::bind([deviceId, deviceType]() {
        DistributedDeviceInfo device;
        if (!DistributedDeviceService::GetInstance().GetDeviceInfo(deviceId, device)) {
            ANS_LOGW("Dans bundle get device info failed %{public}s.", StringAnonymous(deviceId).c_str());
            return;
        }
        DistributedSubscribeService::GetInstance().UnSubscribeNotification(deviceId, deviceType);
        auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
        if (localDevice.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH) {
            ANS_LOGD("watch not delete notifications");
            return;
        }
        if (deviceType == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
            std::vector<std::string> hashcodes;
            NotificationHelper::RemoveDistributedNotifications(hashcodes,
                NotificationConstant::SlotType::SOCIAL_COMMUNICATION,
                NotificationConstant::DistributedDeleteType::DEVICE_ID,
                NotificationConstant::DISTRIBUTED_RELEASE_DELETE,
                device.udid_);
        }
    });
    serviceQueue_->submit(subscribeTask);
}

void DistributedService::DeviceStatusChange(const DeviceStatueChangeInfo& changeInfo)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, changeInfo]() {
        ANS_LOGI("Device change %{public}d %{public}d %{public}d", changeInfo.changeType,
            changeInfo.enableChange, changeInfo.liveViewChange);
#ifdef DISTRIBUTED_FEATURE_MASTER
        if (changeInfo.changeType == DeviceStatueChangeType::DEVICE_USING_ONLINE) {
            HandleDeviceUsingChange(changeInfo);
        }

        if (changeInfo.changeType == DeviceStatueChangeType::ALL_CONNECT_STATUS_CHANGE) {
            if (DistributedDeviceService::GetInstance().CheckNeedSubscribeAllConnect()) {
                DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->SubscribeAllConnect();
                DistributedDeviceService::GetInstance().SetSubscribeAllConnect(true);
            }
        }

        if (changeInfo.changeType == DeviceStatueChangeType::DEVICE_USING_CLOSE) {
            DistributedDeviceInfo device;
            if (!DistributedDeviceService::GetInstance().GetDeviceInfoByUdid(changeInfo.deviceId, device)) {
                ANS_LOGW("get deviceId err");
                return;
            }
            DistributedPublishService::GetInstance().RemoveAllDistributedNotifications(device);
            DistributedSubscribeService::GetInstance().UnSubscribeNotification(device.deviceId_,
                device.deviceType_, false);
            std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
            if (!deviceType.empty()) {
                auto ret = NotificationHelper::SetTargetDeviceBundleList(deviceType, device.udid_,
                    BunleListOperationType::RELEASE_BUNDLES, std::vector<std::string>());
                ANS_LOGI("Remove bundle %{public}s %{public}s %{public}d.", deviceType.c_str(),
                    StringAnonymous(device.deviceId_).c_str(), ret);
            }

            DistributedDeviceService::GetInstance().SyncDeviceMatch(device, MatchType::MATCH_OFFLINE);
            DistributedClient::GetInstance().ReleaseDevice(device.deviceId_, device.deviceType_, false);
            DistributedDeviceService::GetInstance().ResetDeviceInfo(device.deviceId_);
        }
#else
        if (changeInfo.changeType == DeviceStatueChangeType::NOTIFICATION_ENABLE_CHANGE) {
            DistributedDeviceService::GetInstance().SyncDeviceStatus(DistributedDeviceService::STATE_TYPE_SWITCH,
                false, changeInfo.enableChange, changeInfo.liveViewChange);
        }
#endif
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnCanceled(const std::shared_ptr<Notification>& notification,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("check handler is null");
        return;
    }
    if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
        ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
        return;
    }
    std::string notificationKey = GetNotificationKey(notification);
    auto slotType = notification->GetNotificationRequestPoint()->GetSlotType();
    std::function<void()> task = std::bind([peerDevice, notificationKey, slotType]() {
        DistributedPublishService::GetInstance().OnRemoveNotification(peerDevice,
            notificationKey, slotType);
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnBatchCanceled(const std::vector<std::shared_ptr<Notification>>& notifications,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("check handler is null.");
        return;
    }

    std::ostringstream keysStream;
    std::ostringstream slotTypesStream;
    for (auto notification : notifications) {
        if (notification == nullptr || notification->GetNotificationRequestPoint() == nullptr) {
            ANS_LOGE("notification or GetNotificationRequestPoint is nullptr");
            continue;
        }
        keysStream << GetNotificationKey(notification) << ' ';
        slotTypesStream << std::to_string(notification->GetNotificationRequestPoint()->GetSlotType()) << ' ';
    }
    std::string notificationKeys = keysStream.str();
    std::string slotTypes = slotTypesStream.str();
    std::function<void()> task = std::bind([peerDevice, notificationKeys, slotTypes]() {
        DistributedPublishService::GetInstance().OnRemoveNotifications(peerDevice,
            notificationKeys, slotTypes);
    });
    serviceQueue_->submit(task);
}

#ifdef DISTRIBUTED_FEATURE_MASTER
int32_t DistributedService::OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> & operationInfo,
    const DistributedDeviceInfo& device)
{
    return ERR_OK;
}

void DistributedService::OnConsumed(const std::shared_ptr<Notification> &request,
    const DistributedDeviceInfo& peerDevice)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([request, peerDevice, this]() {
        if (!OnConsumedSetFlags(request, peerDevice)) {
            return;
        }
        DistributedPublishService::GetInstance().SendNotifictionRequest(request, peerDevice);
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnApplicationInfnChanged(const std::string& bundleName)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }

    std::function<void()> task = std::bind([&, bundleName]() {
        DistributedBundleService::GetInstance().HandleBundleChanged(bundleName, false);
    });
    serviceQueue_->submit(task);
}

void DistributedService::HandleBundlesEvent(const std::string& bundleName, const std::string& action)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }

    std::function<void()> task = std::bind([&, bundleName, action]() {
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
            DistributedBundleService::GetInstance().HandleBundleChanged(bundleName, true);
        }
        if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
            DistributedBundleService::GetInstance().HandleBundleRemoved(bundleName);
        }
        ANS_LOGI("Handle bundle event %{public}s, %{public}s.", bundleName.c_str(), action.c_str());
    });
    serviceQueue_->submit(task);
}

void DistributedService::HandleDeviceUsingChange(const DeviceStatueChangeInfo& changeInfo)
{
    DistributedDeviceInfo device;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfoByUdid(changeInfo.deviceId, device)) {
        return;
    }
    DistributedDeviceService::GetInstance().SetDeviceSyncData(device.deviceId_,
        DistributedDeviceService::DEVICE_USAGE, true);
    if (!DistributedDeviceService::GetInstance().IsSubscribeAllConnect()) {
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->SubscribeAllConnect();
        DistributedDeviceService::GetInstance().SetSubscribeAllConnect(true);
    }
    // sync to peer device
    ConnectPeerDevice(device);
}
#else
void DistributedService::OnConsumed(const std::shared_ptr<Notification> &request,
    const DistributedDeviceInfo& peerDevice)
{
    return;
}

int32_t DistributedService::OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> & operationInfo,
    const DistributedDeviceInfo& device)
{
    return DistributedOperationService::GetInstance().OnOperationResponse(operationInfo, device);
}

void DistributedService::SyncDeviceStatus(int32_t status)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    status = (static_cast<uint32_t>(status) << 1);
    std::function<void()> task = std::bind([&, status]() {
        DistributedDeviceService::GetInstance().SyncDeviceStatus(DistributedDeviceService::STATE_TYPE_LOCKSCREEN,
            status, false, false);
    });
    serviceQueue_->submit(task);
}

void DistributedService::SyncInstalledBundle(const std::string& bundleName, bool isAdd)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, bundleName, isAdd]() {
        std::vector<std::string> bundles = { bundleName };
        auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
        auto peerDevices = DistributedDeviceService::GetInstance().GetDeviceList();
        bool isPad = DistributedDeviceService::GetInstance().IsLocalPadOrPC();
        if (isAdd) {
            int32_t userId = DistributedSubscribeService::GetCurrentActiveUserId();
            if (DelayedSingleton<BundleResourceHelper>::GetInstance()->CheckSystemApp(bundleName, userId)) {
                ANS_LOGI("Bundle no sycn %{public}d %{public}s.", userId, bundleName.c_str());
                return;
            }
        }
        int32_t syncType = isAdd ? BunleListOperationType::ADD_BUNDLES : BunleListOperationType::REMOVE_BUNDLES;
        for (auto& device : peerDevices) {
            if (isPad && device.second.peerState_ != DeviceState::STATE_ONLINE) {
                ANS_LOGI("DeviceState bundle %{public}d %{public}d %{public}s.", syncType, device.second.deviceType_,
                    StringAnonymous(device.second.deviceId_).c_str());
                continue;
            }
            DistributedBundleService::GetInstance().SendInstalledBundles(device.second, localDevice.deviceId_,
                bundles, syncType);
        }
        ANS_LOGI("Sync bundle %{public}d %{public}s %{public}zu.", syncType, bundleName.c_str(), peerDevices.size());
    });
    serviceQueue_->submit(task);
}

void DistributedService::OnApplicationInfnChanged(const std::string& bundleName)
{
    return;
}
#endif

void DistributedService::HandleMatchSync(const std::shared_ptr<TlvBox>& boxMessage)
{
    DistributedDeviceInfo peerDevice;
    NotifticationMatchBox matchBox = NotifticationMatchBox(boxMessage);
    if (!matchBox.GetLocalDeviceId(peerDevice.deviceId_)) {
        ANS_LOGI("Dans handle match device id failed.");
        return;
    }
    int32_t matchType = 0;
    if (!matchBox.GetMatchType(matchType)) {
        ANS_LOGI("Dans handle match sync failed.");
        return;
    }
    ANS_LOGI("Dans handle match device type %{public}d.", matchType);
    DistributedDeviceInfo device;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfo(peerDevice.deviceId_, device)) {
        return;
    }
#ifdef DISTRIBUTED_FEATURE_MASTER
    if (matchType == MatchType::MATCH_SYN) {
        DistributedDeviceService::GetInstance().SyncDeviceMatch(device, MatchType::MATCH_ACK);
        DistributedPublishService::GetInstance().SyncLiveViewNotification(device, true);
    } else if (matchType == MatchType::MATCH_ACK) {
        DistributedSubscribeService::GetInstance().SubscribeNotification(device);
        DistributedPublishService::GetInstance().SyncLiveViewNotification(device, false);
    }
#else
    if (DistributedDeviceService::GetInstance().IsLocalPadOrPC()) {
        if (matchType == MatchType::MATCH_SYN) {
            DistributedSubscribeService::GetInstance().SubscribeNotification(device);
            DistributedDeviceService::GetInstance().InitCurrentDeviceStatus();
            DistributedBundleService::GetInstance().SyncInstalledBundles(device, true);
            DistributedDeviceService::GetInstance().SyncDeviceMatch(device, MatchType::MATCH_ACK);
            return;
        }
        if (matchType == MatchType::MATCH_OFFLINE) {
            DistributedSubscribeService::GetInstance().UnSubscribeNotification(device.deviceId_,
                device.deviceType_, false);
            DistributedClient::GetInstance().ReleaseDevice(device.deviceId_, device.deviceType_, false);
            DistributedDeviceService::GetInstance().ResetDeviceInfo(device.deviceId_);
        }
    }

    if (matchType == MatchType::MATCH_SYN) {
        DistributedDeviceService::GetInstance().SyncDeviceMatch(device, MatchType::MATCH_ACK);
    } else if (matchType == MatchType::MATCH_ACK) {
        DistributedDeviceService::GetInstance().InitCurrentDeviceStatus();
        DistributedSubscribeService::GetInstance().SubscribeNotification(device);
    }
#endif
}

void DistributedService::OnHandleMsg(std::shared_ptr<TlvBox>& box)
{
    if (serviceQueue_ == nullptr || box == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }
    std::function<void()> task = std::bind([&, box]() {
        int32_t type;
        if (!box->GetMessageType(type)) {
            ANS_LOGW("Dans invalid message type failed.");
            return;
        }
        ANS_LOGI("Dans handle message type %{public}d.", type);
        switch (type) {
            case NotificationEventType::NOTIFICATION_MATCH_SYNC:
                HandleMatchSync(box);
                break;
            case NotificationEventType::REMOVE_NOTIFICATION:
                DistributedPublishService::GetInstance().RemoveNotification(box);
                break;
            case NotificationEventType::REMOVE_ALL_NOTIFICATIONS:
                DistributedPublishService::GetInstance().RemoveNotifications(box);
                break;
            case NotificationEventType::BUNDLE_ICON_SYNC:
                DistributedBundleService::GetInstance().HandleBundleIconSync(box);
                break;
            case NotificationEventType::NOTIFICATION_RESPONSE_SYNC:
            case NotificationEventType::NOTIFICATION_RESPONSE_REPLY_SYNC:
                DistributedOperationService::GetInstance().HandleNotificationOperation(box);
                break;
#ifdef DISTRIBUTED_FEATURE_MASTER
            case NotificationEventType::NOTIFICATION_STATE_SYNC:
                DistributedDeviceService::GetInstance().SetDeviceStatus(box);
                break;
            case NotificationEventType::INSTALLED_BUNDLE_SYNC:
                DistributedBundleService::GetInstance().SetDeviceBundleList(box);
                break;
#else
            case NotificationEventType::PUBLISH_NOTIFICATION:
                DistributedPublishService::GetInstance().PublishNotification(box);
                break;
            case NotificationEventType::SYNC_NOTIFICATION:
                DistributedPublishService::GetInstance().PublishSynchronousLiveView(box);
                break;
            case NotificationEventType::REMOVE_ALL_DISTRIBUTED_NOTIFICATIONS:
                DistributedPublishService::GetInstance().RemoveAllDistributedNotifications(box);
                break;
#endif
            default:
                break;
        }
    });
    serviceQueue_->submit(task);
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
    OnHandleMsg(box);
}

bool DistributedService::OnConsumedSetFlags(const std::shared_ptr<Notification> &request,
    const DistributedDeviceInfo& peerDevice)
{
    std::string deviceType =  DistributedDeviceService::DeviceTypeToTypeString(peerDevice.deviceType_);
    sptr<NotificationRequest> requestPoint = request->GetNotificationRequestPoint();
    auto flagsMap = requestPoint->GetDeviceFlags();
    if (flagsMap == nullptr || flagsMap->size() <= 0) {
        return false;
    }
    auto flagIter = flagsMap->find(deviceType);
    if (flagIter != flagsMap->end() && flagIter->second != nullptr) {
        ANS_LOGI("SetFlags-before filte, notificationKey = %{public}s flagIter \
            flags = %{public}d, deviceType:%{public}s",
            requestPoint->GetKey().c_str(), flagIter->second->GetReminderFlags(), deviceType.c_str());
        std::shared_ptr<NotificationFlags> tempFlags = requestPoint->GetFlags();
        tempFlags->SetSoundEnabled(tempFlags->IsSoundEnabled() ==  NotificationConstant::FlagStatus::OPEN &&
            flagIter->second->IsSoundEnabled() == NotificationConstant::FlagStatus::OPEN ?
            NotificationConstant::FlagStatus::OPEN : NotificationConstant::FlagStatus::CLOSE);
        tempFlags->SetVibrationEnabled(tempFlags->IsVibrationEnabled() ==  NotificationConstant::FlagStatus::OPEN  &&
            flagIter->second->IsVibrationEnabled() ==  NotificationConstant::FlagStatus::OPEN ?
            NotificationConstant::FlagStatus::OPEN : NotificationConstant::FlagStatus::CLOSE);
        tempFlags->SetLockScreenVisblenessEnabled(
            tempFlags->IsLockScreenVisblenessEnabled() && flagIter->second->IsLockScreenVisblenessEnabled());
        tempFlags->SetBannerEnabled(
            tempFlags->IsBannerEnabled() && flagIter->second->IsBannerEnabled());
        tempFlags->SetLightScreenEnabled(
            tempFlags->IsLightScreenEnabled() && flagIter->second->IsLightScreenEnabled());
        requestPoint->SetFlags(tempFlags);
        ANS_LOGI("SetFlags-after filte, notificationKey = %{public}s flags = %{public}d",
            requestPoint->GetKey().c_str(), tempFlags->GetReminderFlags());
    } else {
        return false;
    }
    return true;
}
}
}
