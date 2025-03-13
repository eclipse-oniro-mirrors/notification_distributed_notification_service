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

#include "notification_local_live_view_subscriber_manager.h"

#include <algorithm>
#include <memory>
#include <set>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_button_option.h"
#include "os_account_manager.h"
#include "remote_death_recipient.h"
#include "bundle_manager_helper.h"
#include "advanced_notification_service.h"

namespace OHOS {
namespace Notification {
struct NotificationLocalLiveViewSubscriberManager::LocalLiveViewSubscriberRecord {
    sptr<IAnsSubscriberLocalLiveView> subscriber {nullptr};
    std::string bundleName {};
    int32_t userId {SUBSCRIBE_USER_INIT};
};

NotificationLocalLiveViewSubscriberManager::NotificationLocalLiveViewSubscriberManager()
{
    ANS_LOGI("constructor");
    notificationButtonQueue_ = std::make_shared<ffrt::queue>("NotificationLocalLiveViewMgr");
    recipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&NotificationLocalLiveViewSubscriberManager::OnRemoteDied,
            this, std::placeholders::_1));
    if (recipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
}

NotificationLocalLiveViewSubscriberManager::~NotificationLocalLiveViewSubscriberManager()
{
    ANS_LOGI("deconstructor");
    buttonRecordList_.clear();
}

void NotificationLocalLiveViewSubscriberManager::ResetFfrtQueue()
{
    if (notificationButtonQueue_ != nullptr) {
        notificationButtonQueue_.reset();
    }
}

ErrCode NotificationLocalLiveViewSubscriberManager::AddLocalLiveViewSubscriber(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("subscriber is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption;
    std::string bundle;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        bundle = bundleManager->GetBundleNameByUid(callingUid);
    }
    bundleOption = new (std::nothrow) NotificationBundleOption(bundle, callingUid);
    ErrCode result = ERR_ANS_TASK_ERR;
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption instance");
        return ERR_ANS_NO_MEMORY;
    }
    ANS_LOGD("Get userId succeeded, callingUid = <%{public}d> bundleName = <%{public}s>", callingUid, bundle.c_str());
    if (notificationButtonQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return result;
    }
    ANS_LOGD("ffrt start!");
    ffrt::task_handle handler =
        notificationButtonQueue_->submit_h(std::bind([this, &subscriber, &bundleOption, &result]() {
            ANS_LOGD("ffrt enter!");
            result = this->AddSubscriberInner(subscriber, bundleOption);
    }));
    notificationButtonQueue_->wait(handler);
    ANS_LOGD("ffrt end!");
    return result;
}

ErrCode NotificationLocalLiveViewSubscriberManager::RemoveLocalLiveViewSubscriber(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("subscriber is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_ANS_TASK_ERR;
    if (notificationButtonQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return result;
    }
    ANS_LOGD("ffrt start!");
    ffrt::task_handle handler = notificationButtonQueue_->submit_h(std::bind([this, &subscriber,
        &subscribeInfo, &result]() {
        ANS_LOGD("ffrt enter!");
        result = this->RemoveSubscriberInner(subscriber, subscribeInfo);
    }));
    notificationButtonQueue_->wait(handler);
    ANS_LOGD("ffrt end!");
    return result;
}

void NotificationLocalLiveViewSubscriberManager::NotifyTriggerResponse(const sptr<Notification> &notification,
    const sptr<NotificationButtonOption> &buttonOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationButtonQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyTriggerResponseFunc =
        std::bind(&NotificationLocalLiveViewSubscriberManager::NotifyTriggerResponseInner,
            this, notification, buttonOption);

    ANS_LOGD("ffrt start!");
    notificationButtonQueue_->submit(NotifyTriggerResponseFunc);
    ANS_LOGD("ffrt end!");
}

void NotificationLocalLiveViewSubscriberManager::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    ANS_LOGI("OnRemoteDied");
    if (notificationButtonQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    ffrt::task_handle handler = notificationButtonQueue_->submit_h(std::bind([this, object]() {
        ANS_LOGD("ffrt enter!");
        std::shared_ptr<LocalLiveViewSubscriberRecord> record = FindSubscriberRecord(object);
        if (record != nullptr) {
            ANS_LOGI("subscriber removed . userId = %{public}d", record->userId);
            AdvancedNotificationService::GetInstance()->RemoveSystemLiveViewNotifications(
                record->bundleName, record->userId);
            buttonRecordList_.remove(record);
        }
    }));
    ANS_LOGD("ffrt start!");
    notificationButtonQueue_->wait(handler);
    ANS_LOGD("ffrt end!");
}

std::shared_ptr<NotificationLocalLiveViewSubscriberManager::LocalLiveViewSubscriberRecord> NotificationLocalLiveViewSubscriberManager::FindSubscriberRecord(
    const wptr<IRemoteObject> &object)
{
    auto iter = buttonRecordList_.begin();

    for (; iter != buttonRecordList_.end(); iter++) {
        if ((*iter)->subscriber->AsObject() == object) {
            return (*iter);
        }
    }
    return nullptr;
}

std::shared_ptr<NotificationLocalLiveViewSubscriberManager::LocalLiveViewSubscriberRecord> NotificationLocalLiveViewSubscriberManager::FindSubscriberRecord(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber)
{
    auto iter = buttonRecordList_.begin();

    for (; iter != buttonRecordList_.end(); iter++) {
        if ((*iter)->subscriber->AsObject() == subscriber->AsObject()) {
            return (*iter);
        }
    }
    return nullptr;
}

std::shared_ptr<NotificationLocalLiveViewSubscriberManager::LocalLiveViewSubscriberRecord> NotificationLocalLiveViewSubscriberManager::CreateSubscriberRecord(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber,
    const sptr<NotificationBundleOption> &bundleOption)
{
    std::shared_ptr<LocalLiveViewSubscriberRecord> record = std::make_shared<LocalLiveViewSubscriberRecord>();
    // set bundleName and uid
    if (record != nullptr) {
        record->subscriber = subscriber;
        record->bundleName = bundleOption->GetBundleName();
        record->userId = bundleOption->GetUid();
        ANS_LOGD("Get userId succeeded, callingUid = <%{public}d> bundleName = <%{public}s>",
            record->userId, record->bundleName.c_str());
    }
    return record;
}


ErrCode NotificationLocalLiveViewSubscriberManager::AddSubscriberInner(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber, const sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    std::shared_ptr<LocalLiveViewSubscriberRecord> record = FindSubscriberRecord(subscriber);
    if (record == nullptr) {
        record = CreateSubscriberRecord(subscriber, bundleOption);
        if (record == nullptr) {
            ANS_LOGE("CreateSubscriberRecord failed.");
            return ERR_ANS_NO_MEMORY;
        }
        buttonRecordList_.push_back(record);

        record->subscriber->AsObject()->AddDeathRecipient(recipient_);

        record->subscriber->OnConnected();
        ANS_LOGI("subscriber is connected.");
    }

    return ERR_OK;
}

ErrCode NotificationLocalLiveViewSubscriberManager::RemoveSubscriberInner(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    std::shared_ptr<LocalLiveViewSubscriberRecord> record = FindSubscriberRecord(subscriber);

    if (record == nullptr) {
        ANS_LOGE("subscriber not found.");
        return ERR_ANS_INVALID_PARAM;
    }

    record->subscriber->AsObject()->RemoveDeathRecipient(recipient_);

    buttonRecordList_.remove(record);

    record->subscriber->OnDisconnected();
    ANS_LOGI("subscriber is disconnected.");

    return ERR_OK;
}

void NotificationLocalLiveViewSubscriberManager::NotifyTriggerResponseInner(
    const sptr<Notification> &notification, const sptr<NotificationButtonOption> buttonOption)
{
    ANS_LOGD("ffrt enter!");
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);

    int32_t sendUserId;
    std::string bundleName;
    if (notification->GetNotificationRequestPoint()->GetAgentBundle() != nullptr) {
        sendUserId = notification->GetNotificationRequestPoint()->GetAgentBundle()->GetUid();
        bundleName = notification->GetNotificationRequestPoint()->GetAgentBundle()->GetBundleName();
    } else {
        sendUserId = notification->GetUid();
        bundleName = notification->GetBundleName();
    }
    ANS_LOGD("%{public}s sendUserId <%{public}d>, bundlename <%{public}s>",
        __FUNCTION__, sendUserId, bundleName.c_str());

    for (auto record : buttonRecordList_) {
        ANS_LOGD("%{public}s record->userId = <%{public}d>, bundlename <%{public}s>",
            __FUNCTION__, record->userId, record->bundleName.c_str());
        if (record->bundleName == bundleName && record->userId == sendUserId) {
            record->subscriber->OnResponse(notification->GetId(), *buttonOption);
        }
    }
}

bool NotificationLocalLiveViewSubscriberManager::IsSystemUser(int32_t userId)
{
    return ((userId >= SUBSCRIBE_USER_SYSTEM_BEGIN) && (userId <= SUBSCRIBE_USER_SYSTEM_END));
}

}  // namespace Notification
}  // namespace OHOS
