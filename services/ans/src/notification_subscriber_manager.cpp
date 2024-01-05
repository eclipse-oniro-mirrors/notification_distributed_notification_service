/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "notification_subscriber_manager.h"

#include <algorithm>
#include <memory>
#include <set>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_watchdog.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "remote_death_recipient.h"

namespace OHOS {
namespace Notification {
struct NotificationSubscriberManager::SubscriberRecord {
    sptr<AnsSubscriberInterface> subscriber {nullptr};
    std::set<std::string> bundleList_ {};
    bool subscribedAll {false};
    int32_t userId {SUBSCRIBE_USER_INIT};
};

NotificationSubscriberManager::NotificationSubscriberManager()
{
    ANS_LOGI("constructor");
    notificationSubQueue_ = std::make_shared<ffrt::queue>("NotificationSubscriberMgr");
    recipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&NotificationSubscriberManager::OnRemoteDied, this, std::placeholders::_1));
    if (recipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
}

NotificationSubscriberManager::~NotificationSubscriberManager()
{
    ANS_LOGI("deconstructor");
    subscriberRecordList_.clear();
}

void NotificationSubscriberManager::ResetFfrtQueue()
{
    if (notificationSubQueue_ != nullptr) {
        notificationSubQueue_.reset();
    }
}

ErrCode NotificationSubscriberManager::AddSubscriber(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("subscriber is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationSubscribeInfo> subInfo = subscribeInfo;
    if (subInfo == nullptr) {
        subInfo = new (std::nothrow) NotificationSubscribeInfo();
        if (subInfo == nullptr) {
            ANS_LOGE("Failed to create NotificationSubscribeInfo ptr.");
            return ERR_ANS_NO_MEMORY;
        }
    }

    if (subInfo->GetAppUserId() == SUBSCRIBE_USER_INIT) {
        int32_t userId = SUBSCRIBE_USER_INIT;
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        ErrCode ret = OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
        if (ret != ERR_OK) {
            ANS_LOGD("Get userId failed, callingUid = <%{public}d>", callingUid);
            return ERR_ANS_INVALID_PARAM;
        }

        ANS_LOGD("Get userId succeeded, callingUid = <%{public}d> userId = <%{public}d>", callingUid, userId);
        subInfo->AddAppUserId(userId);
    }

    ErrCode result = ERR_ANS_TASK_ERR;
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return result;
    }
    ANS_LOGE("ffrt start!");
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, &subscriber, &subInfo, &result]() {
        ANS_LOGE("ffrt enter!");
        result = this->AddSubscriberInner(subscriber, subInfo);
    }));
    notificationSubQueue_->wait(handler);
    ANS_LOGE("ffrt end!");
    return result;
}

ErrCode NotificationSubscriberManager::RemoveSubscriber(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("subscriber is null.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_ANS_TASK_ERR;
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return result;
    }
    ANS_LOGE("ffrt start!");
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, &subscriber,
        &subscribeInfo, &result]() {
        ANS_LOGE("ffrt enter!");
        result = this->RemoveSubscriberInner(subscriber, subscribeInfo);
    }));
    notificationSubQueue_->wait(handler);
    ANS_LOGE("ffrt end!");
    return result;
}

void NotificationSubscriberManager::NotifyConsumed(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyConsumedFunc =
        std::bind(&NotificationSubscriberManager::NotifyConsumedInner, this, notification, notificationMap);

    ANS_LOGE("ffrt start!");
    notificationSubQueue_->submit(NotifyConsumedFunc);
    ANS_LOGE("ffrt end!");
}

void NotificationSubscriberManager::BatchNotifyConsumed(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, const std::shared_ptr<SubscriberRecord> &record)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGI("Start batch notifyConsumed.");
    if (notifications.empty() || notificationMap == nullptr || record == nullptr) {
        ANS_LOGE("Invalid input.");
        return;
    }

    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("Queue is nullptr");
        return;
    }

    AppExecFwk::EventHandler::Callback batchNotifyConsumedFunc = std::bind(
        &NotificationSubscriberManager::BatchNotifyConsumedInner, this, notifications, notificationMap, record);

    notificationSubQueue_->submit(batchNotifyConsumedFunc);
}

void NotificationSubscriberManager::NotifyCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyCanceledFunc = std::bind(
        &NotificationSubscriberManager::NotifyCanceledInner, this, notification, notificationMap, deleteReason);

    ANS_LOGE("ffrt start!");
    notificationSubQueue_->submit(NotifyCanceledFunc);
    ANS_LOGE("ffrt end!");
}

void NotificationSubscriberManager::BatchNotifyCanceled(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGD("queue is nullptr");
        return;
    }

    AppExecFwk::EventHandler::Callback NotifyCanceledFunc = std::bind(
        &NotificationSubscriberManager::BatchNotifyCanceledInner, this, notifications, notificationMap, deleteReason);

    notificationSubQueue_->submit(NotifyCanceledFunc);
}

void NotificationSubscriberManager::NotifyUpdated(const sptr<NotificationSortingMap> &notificationMap)
{
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyUpdatedFunc =
        std::bind(&NotificationSubscriberManager::NotifyUpdatedInner, this, notificationMap);

    ANS_LOGE("ffrt start!");
    notificationSubQueue_->submit(NotifyUpdatedFunc);
    ANS_LOGE("ffrt end!");
}

void NotificationSubscriberManager::NotifyDoNotDisturbDateChanged(const sptr<NotificationDoNotDisturbDate> &date)
{
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyDoNotDisturbDateChangedInner, this, date);

    ANS_LOGE("ffrt start!");
    notificationSubQueue_->submit(func);
    ANS_LOGE("ffrt end!");
}

void NotificationSubscriberManager::NotifyEnabledNotificationChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyEnabledNotificationChangedInner, this, callbackData);

    ANS_LOGE("ffrt start!");
    notificationSubQueue_->submit(func);
    ANS_LOGE("ffrt end!");
}

void NotificationSubscriberManager::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    ANS_LOGI("OnRemoteDied");
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, object]() {
        ANS_LOGE("ffrt enter!");
        std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(object);
        if (record != nullptr) {
            ANS_LOGW("subscriber removed.");
            subscriberRecordList_.remove(record);
        }
    }));
    ANS_LOGE("ffrt start!");
    notificationSubQueue_->wait(handler);
    ANS_LOGE("ffrt end!");
}

std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> NotificationSubscriberManager::FindSubscriberRecord(
    const wptr<IRemoteObject> &object)
{
    auto iter = subscriberRecordList_.begin();

    for (; iter != subscriberRecordList_.end(); iter++) {
        if ((*iter)->subscriber->AsObject() == object) {
            return (*iter);
        }
    }
    return nullptr;
}

std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> NotificationSubscriberManager::FindSubscriberRecord(
    const sptr<AnsSubscriberInterface> &subscriber)
{
    auto iter = subscriberRecordList_.begin();

    for (; iter != subscriberRecordList_.end(); iter++) {
        if ((*iter)->subscriber->AsObject() == subscriber->AsObject()) {
            return (*iter);
        }
    }
    return nullptr;
}

std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> NotificationSubscriberManager::CreateSubscriberRecord(
    const sptr<AnsSubscriberInterface> &subscriber)
{
    std::shared_ptr<SubscriberRecord> record = std::make_shared<SubscriberRecord>();
    if (record != nullptr) {
        record->subscriber = subscriber;
    }
    return record;
}

void NotificationSubscriberManager::AddRecordInfo(
    std::shared_ptr<SubscriberRecord> &record, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    if (subscribeInfo != nullptr) {
        record->bundleList_.clear();
        record->subscribedAll = true;
        for (auto bundle : subscribeInfo->GetAppNames()) {
            record->bundleList_.insert(bundle);
            record->subscribedAll = false;
        }
        record->userId = subscribeInfo->GetAppUserId();
    } else {
        record->bundleList_.clear();
        record->subscribedAll = true;
    }
}

void NotificationSubscriberManager::RemoveRecordInfo(
    std::shared_ptr<SubscriberRecord> &record, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    if (subscribeInfo != nullptr) {
        for (auto bundle : subscribeInfo->GetAppNames()) {
            if (record->subscribedAll) {
                record->bundleList_.insert(bundle);
            } else {
                record->bundleList_.erase(bundle);
            }
        }
    } else {
        record->bundleList_.clear();
        record->subscribedAll = false;
    }
}

ErrCode NotificationSubscriberManager::AddSubscriberInner(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(subscriber);
    if (record == nullptr) {
        record = CreateSubscriberRecord(subscriber);
        if (record == nullptr) {
            ANS_LOGE("CreateSubscriberRecord failed.");
            return ERR_ANS_NO_MEMORY;
        }
        subscriberRecordList_.push_back(record);

        record->subscriber->AsObject()->AddDeathRecipient(recipient_);

        record->subscriber->OnConnected();
        ANS_LOGI("subscriber is connected.");
    }

    AddRecordInfo(record, subscribeInfo);
    if (onSubscriberAddCallback_ != nullptr) {
        onSubscriberAddCallback_(record);
    }

    ANS_LOGI("Add subscriber success.");
    return ERR_OK;
}

ErrCode NotificationSubscriberManager::RemoveSubscriberInner(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(subscriber);

    if (record == nullptr) {
        ANS_LOGE("subscriber not found.");
        return ERR_ANS_INVALID_PARAM;
    }

    RemoveRecordInfo(record, subscribeInfo);

    if (!record->subscribedAll && record->bundleList_.empty()) {
        record->subscriber->AsObject()->RemoveDeathRecipient(recipient_);

        subscriberRecordList_.remove(record);

        record->subscriber->OnDisconnected();
        ANS_LOGI("subscriber is disconnected.");
    }

    return ERR_OK;
}

void NotificationSubscriberManager::NotifyConsumedInner(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    ANS_LOGE("ffrt enter!");
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s notification->GetUserId <%{public}d>", __FUNCTION__, notification->GetUserId());
    int32_t recvUserId = notification->GetNotificationRequest().GetReceiverUserId();
    int32_t sendUserId = notification->GetUserId();
    for (auto record : subscriberRecordList_) {
        auto BundleNames = notification->GetBundleName();
        ANS_LOGD("%{public}s record->userId = <%{public}d> BundleName  = <%{public}s",
            __FUNCTION__, record->userId, BundleNames.c_str());
        auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), BundleNames);
        if (!record->subscribedAll == (iter != record->bundleList_.end()) &&
            ((record->userId == sendUserId) ||
            (record->userId == SUBSCRIBE_USER_ALL) ||
            (record->userId == recvUserId) ||
            IsSystemUser(record->userId) ||  // Delete this, When the systemui subscribe carry the user ID.
            IsSystemUser(sendUserId))) {
            record->subscriber->OnConsumed(notification, notificationMap);
        }
    }
}

void NotificationSubscriberManager::BatchNotifyConsumedInner(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, const std::shared_ptr<SubscriberRecord> &record)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notifications.empty() || notificationMap == nullptr || record == nullptr) {
        ANS_LOGE("Invalid input.");
        return;
    }

    ANS_LOGD("Record->userId = <%{public}d>", record->userId);
    std::vector<sptr<Notification>> currNotifications;
    for (size_t i = 0; i < notifications.size(); i ++) {
        sptr<Notification> notification = notifications[i];
        if (notification == nullptr) {
            continue;
        }
        auto bundleName = notification->GetBundleName();
        auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), bundleName);
        int32_t recvUserId = notification->GetNotificationRequest().GetReceiverUserId();
        int32_t sendUserId = notification->GetUserId();
        if (!record->subscribedAll == (iter != record->bundleList_.end()) &&
            ((record->userId == sendUserId) ||
            (record->userId == SUBSCRIBE_USER_ALL) ||
            (record->userId == recvUserId) ||
            IsSystemUser(record->userId) ||   // Delete this, When the systemui subscribe carry the user ID.
            IsSystemUser(sendUserId))) {
            currNotifications.emplace_back(notification);
        }
    }
    if (!currNotifications.empty()) {
        ANS_LOGD("OnConsumedList currNotifications size = <%{public}zu>", currNotifications.size());
        if (record->subscriber != nullptr) {
            record->subscriber->OnConsumedList(currNotifications, notificationMap);
        }
    }
}

void NotificationSubscriberManager::NotifyCanceledInner(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    ANS_LOGE("ffrt enter!");
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s notification->GetUserId <%{public}d>", __FUNCTION__, notification->GetUserId());
    bool isCommonLiveView = notification->GetNotificationRequest().IsCommonLiveView();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = nullptr;
    if (isCommonLiveView) {
        liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
            notification->GetNotificationRequest().GetContent()->GetNotificationContent());
        liveViewContent->FillPictureMarshallingMap();
    }

    int32_t recvUserId = notification->GetNotificationRequest().GetReceiverUserId();
    int32_t sendUserId = notification->GetUserId();
    for (auto record : subscriberRecordList_) {
        ANS_LOGD("%{public}s record->userId = <%{public}d>", __FUNCTION__, record->userId);
        auto BundleNames = notification->GetBundleName();
        auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), BundleNames);
        if (!record->subscribedAll == (iter != record->bundleList_.end()) &&
            ((record->userId == sendUserId) ||
            (record->userId == SUBSCRIBE_USER_ALL) ||
            (record->userId == recvUserId) ||
            IsSystemUser(record->userId) ||   // Delete this, When the systemui subscribe carry the user ID.
            IsSystemUser(sendUserId))) {
            record->subscriber->OnCanceled(notification, notificationMap, deleteReason);
        }
    }

    if (isCommonLiveView && liveViewContent != nullptr) {
        liveViewContent->ClearPictureMarshallingMap();
    }
}

void NotificationSubscriberManager::BatchNotifyCanceledInner(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);

    ANS_LOGD("notifications size = <%{public}zu>", notifications.size());
    for (auto record : subscriberRecordList_) {
        if (record == nullptr) {
            continue;
        }
        ANS_LOGD("record->userId = <%{public}d>", record->userId);
        std::vector<sptr<Notification>> currNotifications;
        for (size_t i = 0; i < notifications.size(); i ++) {
            sptr<Notification> notification = notifications[i];
            if (notification == nullptr) {
                continue;
            }
            auto bundleName = notification->GetBundleName();
            auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), bundleName);
            int32_t recvUserId = notification->GetNotificationRequest().GetReceiverUserId();
            int32_t sendUserId = notification->GetUserId();
            if (!record->subscribedAll == (iter != record->bundleList_.end()) &&
                ((record->userId == sendUserId) ||
                (record->userId == SUBSCRIBE_USER_ALL) ||
                (record->userId == recvUserId) ||
                IsSystemUser(record->userId) ||   // Delete this, When the systemui subscribe carry the user ID.
                IsSystemUser(sendUserId))) {
                currNotifications.emplace_back(notification);
            }
        }
        if (!currNotifications.empty()) {
            ANS_LOGD("onCanceledList currNotifications size = <%{public}zu>", currNotifications.size());
            if (record->subscriber != nullptr) {
                record->subscriber->OnCanceledList(currNotifications, notificationMap, deleteReason);
            }
        }
    }
}

void NotificationSubscriberManager::NotifyUpdatedInner(const sptr<NotificationSortingMap> &notificationMap)
{
    ANS_LOGE("ffrt enter!");
    for (auto record : subscriberRecordList_) {
        record->subscriber->OnUpdated(notificationMap);
    }
}

void NotificationSubscriberManager::NotifyDoNotDisturbDateChangedInner(const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGE("ffrt enter!");
    for (auto record : subscriberRecordList_) {
        record->subscriber->OnDoNotDisturbDateChange(date);
    }
}

bool NotificationSubscriberManager::IsSystemUser(int32_t userId)
{
    return ((userId >= SUBSCRIBE_USER_SYSTEM_BEGIN) && (userId <= SUBSCRIBE_USER_SYSTEM_END));
}

void NotificationSubscriberManager::NotifyEnabledNotificationChangedInner(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGE("ffrt enter!");
    for (auto record : subscriberRecordList_) {
        record->subscriber->OnEnabledNotificationChanged(callbackData);
    }
}

void NotificationSubscriberManager::SetBadgeNumber(const sptr<BadgeNumberCallbackData> &badgeData)
{
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    std::function<void()> setBadgeNumberFunc = [badgeData] () {
        for (auto record : NotificationSubscriberManager::GetInstance()->subscriberRecordList_) {
            record->subscriber->OnBadgeChanged(badgeData);
        }
    };
    ANS_LOGE("ffrt start!");
    notificationSubQueue_->submit(setBadgeNumberFunc);
    ANS_LOGE("ffrt end!");
}

void NotificationSubscriberManager::RegisterOnSubscriberAddCallback(
    std::function<void(const std::shared_ptr<SubscriberRecord> &)> callback)
{
    if (callback == nullptr) {
        ANS_LOGE("Callback is nullptr");
        return;
    }

    onSubscriberAddCallback_ = callback;
}

void NotificationSubscriberManager::UnRegisterOnSubscriberAddCallback()
{
    onSubscriberAddCallback_ = nullptr;
}

using SubscriberRecordPtr = std::shared_ptr<NotificationSubscriberManager::SubscriberRecord>;
std::list<SubscriberRecordPtr> NotificationSubscriberManager::GetSubscriberRecords()
{
    return subscriberRecordList_;
}

}  // namespace Notification
}  // namespace OHOS
