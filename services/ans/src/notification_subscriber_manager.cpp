/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "notification_flags.h"
#include "notification_constant.h"
#include "notification_config_parse.h"
#include "notification_extension_wrapper.h"
#include "os_account_manager_helper.h"
#include "remote_death_recipient.h"
#include "advanced_notification_service.h"
#include "notification_analytics_util.h"

#include "advanced_notification_inline.cpp"
#include "liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {
struct NotificationSubscriberManager::SubscriberRecord {
    sptr<AnsSubscriberInterface> subscriber {nullptr};
    std::set<std::string> bundleList_ {};
    bool subscribedAll {false};
    int32_t userId {SUBSCRIBE_USER_INIT};
    std::string deviceType {CURRENT_DEVICE_TYPE};
    int32_t subscriberUid {DEFAULT_UID};
    bool needNotifyApplicationChanged = false;
    int32_t filterType {0};
    std::set<NotificationConstant::SlotType> slotTypes {};
};

const uint32_t FILTETYPE_IM = 1 << 0;
const uint32_t FILTETYPE_QUICK_REPLY_IM = 2 << 0;

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

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_9, EventBranchId::BRANCH_2);
    message.Message(GetClientBundleName() + "_" +
        " user:" + std::to_string(subInfo->GetAppUserId()));
    if (subInfo->GetAppUserId() == SUBSCRIBE_USER_INIT) {
        int32_t userId = SUBSCRIBE_USER_INIT;
        ErrCode ret = OsAccountManagerHelper::GetInstance().GetCurrentCallingUserId(userId);
        if (ret != ERR_OK) {
            ANS_LOGE("Get current calling userId failed.");
            message.ErrorCode(ret).Append(" Get userId Failed");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return ret;
        }
        subInfo->AddAppUserId(userId);
    }

    ErrCode result = ERR_ANS_TASK_ERR;
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return result;
    }

    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, &subscriber, &subInfo, &result]() {
        result = this->AddSubscriberInner(subscriber, subInfo);
    }));
    notificationSubQueue_->wait(handler);

    ANS_LOGI("%{public}s_, user: %{public}s, Add subscriber result: %{public}d", GetClientBundleName().c_str(),
        std::to_string(subInfo->GetAppUserId()).c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_9, EventBranchId::BRANCH_1);
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, &subscriber,
        &subscribeInfo, &result]() {
        ANS_LOGE("ffrt enter!");
        result = this->RemoveSubscriberInner(subscriber, subscribeInfo);
    }));
    notificationSubQueue_->wait(handler);
    std::string appUserId = (subscribeInfo == nullptr) ? "all" : std::to_string(subscribeInfo->GetAppUserId());

    ANS_LOGI("%{public}s_, user: %{public}s, Remove subscriber result: %{public}d", GetClientBundleName().c_str(),
        appUserId.c_str(), result);
    message.Message(GetClientBundleName() + "_" + "  user:" + appUserId);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
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

    notificationSubQueue_->submit(NotifyConsumedFunc);
}

void NotificationSubscriberManager::NotifyApplicationInfoNeedChanged(const std::string& bundleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr || bundleName.empty()) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyConsumedFunc =
        std::bind(&NotificationSubscriberManager::NotifyApplicationInfochangedInner, this, bundleName);

    notificationSubQueue_->submit(NotifyConsumedFunc);
}


void NotificationSubscriberManager::NotifyApplicationInfochangedInner(const std::string& bundleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGI("NotifyApplicationInfochangedInner %{public}s", bundleName.c_str());
    for (auto record : subscriberRecordList_) {
        if (record->needNotifyApplicationChanged) {
            record->subscriber->OnApplicationInfoNeedChanged(bundleName);
        }
    }
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
#ifdef ENABLE_ANS_AGGREGATION
    std::vector<sptr<Notification>> notifications;
    notifications.emplace_back(notification);
    EXTENTION_WRAPPER->UpdateByCancel(notifications, deleteReason);
#endif

    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyCanceledFunc = std::bind(
        &NotificationSubscriberManager::NotifyCanceledInner, this, notification, notificationMap, deleteReason);

    notificationSubQueue_->submit(NotifyCanceledFunc);
}

void NotificationSubscriberManager::BatchNotifyCanceled(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
#ifdef ENABLE_ANS_AGGREGATION
    EXTENTION_WRAPPER->UpdateByCancel(notifications, deleteReason);
#endif

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

    notificationSubQueue_->submit(NotifyUpdatedFunc);
}

void NotificationSubscriberManager::NotifyDoNotDisturbDateChanged(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyDoNotDisturbDateChangedInner, this, userId, date);

    notificationSubQueue_->submit(func);
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

    notificationSubQueue_->submit(func);
}

void NotificationSubscriberManager::NotifyBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("Queue is nullptr.");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyBadgeEnabledChangedInner, this, callbackData);

    notificationSubQueue_->submit(func);
}

void NotificationSubscriberManager::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    ANS_LOGI("OnRemoteDied");
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, object]() {
        ANS_LOGD("ffrt enter!");
        std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(object);
        if (record != nullptr) {
            auto subscriberUid = record->subscriberUid;
            ANS_LOGI("subscriber removed . subscriberUid = %{public}d", record->subscriberUid);
            subscriberRecordList_.remove(record);
            AdvancedNotificationService::GetInstance()->RemoveSystemLiveViewNotificationsOfSa(record->subscriberUid);
        }
    }));
    notificationSubQueue_->wait(handler);
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
        record->slotTypes.clear();
        for (auto slotType : subscribeInfo->GetSlotTypes()) {
            record->slotTypes.insert(slotType);
        }
        record->userId = subscribeInfo->GetAppUserId();
        // deviceType is empty, use default
        if (!subscribeInfo->GetDeviceType().empty()) {
            record->deviceType = subscribeInfo->GetDeviceType();
        }
        record->subscriberUid = subscribeInfo->GetSubscriberUid();
        record->filterType = subscribeInfo->GetFilterType();
        record->needNotifyApplicationChanged = subscribeInfo->GetNeedNotifyApplication();
    } else {
        record->bundleList_.clear();
        record->subscribedAll = true;
        record->slotTypes.clear();
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

    if (subscribeInfo->GetDeviceType() == DEVICE_TYPE_WEARABLE ||
        subscribeInfo->GetDeviceType() == DEVICE_TYPE_LITE_WEARABLE) {
        AdvancedNotificationService::GetInstance()->SetAndPublishSubscriberExistFlag(DEVICE_TYPE_WEARABLE, true);
    }
    if (subscribeInfo->GetDeviceType() == DEVICE_TYPE_HEADSET) {
        AdvancedNotificationService::GetInstance()->SetAndPublishSubscriberExistFlag(DEVICE_TYPE_HEADSET, true);
    }
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
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s notification->GetUserId <%{public}d>", __FUNCTION__, notification->GetUserId());

    bool wearableFlag = false;
    bool headsetFlag = false;
    bool keyNodeFlag = false;
    for (auto record : subscriberRecordList_) {
        ANS_LOGD("%{public}s record->userId = <%{public}d> BundleName  = <%{public}s deviceType = %{public}s",
            __FUNCTION__, record->userId, notification->GetBundleName().c_str(), record->deviceType.c_str());
        if (IsSubscribedBysubscriber(record, notification) && ConsumeRecordFilter(record, notification)) {
            if (!record->subscriber->AsObject()->IsProxyObject()) {
                MessageParcel data;
                if (!data.WriteParcelable(notification)) {
                    ANS_LOGE("WriteParcelable failed.");
                    continue;
                }
                sptr<Notification> notificationStub = data.ReadParcelable<Notification>();
                if (notificationStub == nullptr) {
                    ANS_LOGE("ReadParcelable failed.");
                    continue;
                }
                record->subscriber->OnConsumed(notificationStub, notificationMap);
                NotificationSubscriberManager::IsDeviceFlag(
                    record, notification, wearableFlag, headsetFlag, keyNodeFlag);
                continue;
            }
            record->subscriber->OnConsumed(notification, notificationMap);
            NotificationSubscriberManager::IsDeviceFlag(record, notification, wearableFlag, headsetFlag, keyNodeFlag);
        }
    }
    NotificationSubscriberManager::TrackCodeLog(notification, wearableFlag, headsetFlag, keyNodeFlag);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
bool NotificationSubscriberManager::GetIsEnableEffectedRemind()
{
    // Ignore the impact of the bundleName and userId for smart reminder switch now.
    for (auto record : subscriberRecordList_) {
        if (record->deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) != 0) {
            return true;
        }
    }
    return false;
}

bool NotificationSubscriberManager::IsDeviceTypeSubscriberd(const std::string deviceType)
{
    for (auto record : subscriberRecordList_) {
        if (record->deviceType.compare(deviceType) == 0) {
            return true;
        }
    }
    ANS_LOGE("device not subscribe, device = %{public}s", deviceType.c_str());
    return false;
}
#endif

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
        bool wearableFlag = false;
        bool headsetFlag = false;
        bool keyNodeFlag = false;
        if (IsSubscribedBysubscriber(record, notification) && ConsumeRecordFilter(record, notification)) {
            currNotifications.emplace_back(notification);
            if (record->subscriber != nullptr) {
                NotificationSubscriberManager::IsDeviceFlag(
                    record, notification, wearableFlag, headsetFlag, keyNodeFlag);
                NotificationSubscriberManager::TrackCodeLog(notification, wearableFlag, headsetFlag, keyNodeFlag);
            }
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
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s notification->GetUserId <%{public}d>", __FUNCTION__, notification->GetUserId());
    bool isCommonLiveView = notification->GetNotificationRequest().IsCommonLiveView();
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = nullptr;
    if (isCommonLiveView) {
        liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
            notification->GetNotificationRequest().GetContent()->GetNotificationContent());
        liveViewContent->FillPictureMarshallingMap();
    }

    ANS_LOGI("CancelNotification key = %{public}s", notification->GetKey().c_str());
    for (auto record : subscriberRecordList_) {
        ANS_LOGD("%{public}s record->userId = <%{public}d>", __FUNCTION__, record->userId);
        if (IsSubscribedBysubscriber(record, notification)) {
            record->subscriber->OnCanceled(notification, notificationMap, deleteReason);
        }
    }

    if (isCommonLiveView && liveViewContent != nullptr) {
        liveViewContent->ClearPictureMarshallingMap();
    }
}

bool NotificationSubscriberManager::IsSubscribedBysubscriber(
    const std::shared_ptr<SubscriberRecord> &record, const sptr<Notification> &notification)
{
    auto BundleNames = notification->GetBundleName();
    auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), BundleNames);
    bool isSubscribedTheNotification = record->subscribedAll || (iter != record->bundleList_.end()) ||
        (notification->GetNotificationRequestPoint()->GetCreatorUid() == record->subscriberUid);
    if (!isSubscribedTheNotification) {
        return false;
    }
    auto soltType = notification->GetNotificationRequestPoint()->GetSlotType();
    ANS_LOGI("slotTypecount:%{public}d", (int)record->slotTypes.size());
    auto slotIter = std::find(record->slotTypes.begin(), record->slotTypes.end(), soltType);
    bool isSubscribedSlotType = (record->slotTypes.size() == 0) || (slotIter != record->slotTypes.end());
    if (!isSubscribedSlotType) {
        return false;
    }

    if (record->userId == SUBSCRIBE_USER_ALL || IsSystemUser(record->userId)) {
        return true;
    }

    int32_t recvUserId = notification->GetNotificationRequestPoint()->GetReceiverUserId();
    int32_t sendUserId = notification->GetUserId();
    if (record->userId == recvUserId) {
        return true;
    }

    if (IsSystemUser(sendUserId)) {
        return true;
    }

    return false;
}

bool NotificationSubscriberManager::ConsumeRecordFilter(
    const std::shared_ptr<SubscriberRecord> &record, const sptr<Notification> &notification)
{
    NotificationRequest request = notification->GetNotificationRequest();
    // filterType
    ANS_LOGI("filterType = %{public}d", record->filterType);
    if (NotificationConstant::SlotType::SOCIAL_COMMUNICATION == request.GetSlotType()) {
        bool isQuickReply = request.HasUserInputButton();
        if (isQuickReply && (record->filterType & FILTETYPE_QUICK_REPLY_IM) > 0) {
            ANS_LOGI("ConsumeRecordFilter-filterType-quickReply");
            return false;
        }
        if (!isQuickReply && (record->filterType & FILTETYPE_IM) > 0) {
            ANS_LOGI("ConsumeRecordFilter-filterType-im");
            return false;
        }
    }
    
    return true;
}

void NotificationSubscriberManager::BatchNotifyCanceledInner(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);

    ANS_LOGD("notifications size = <%{public}zu>", notifications.size());

    std::string notificationKeys = "";
    for (auto notification : notifications) {
        notificationKeys.append(notification->GetKey()).append("-");
    }
    ANS_LOGI("CancelNotification key = %{public}s", notificationKeys.c_str());

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
            auto requestContent = notification->GetNotificationRequest().GetContent();
            if (notification->GetNotificationRequest().IsCommonLiveView() &&
                requestContent->GetNotificationContent() != nullptr) {
                auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
                    requestContent->GetNotificationContent());
                liveViewContent->ClearPictureMap();
                liveViewContent->ClearPictureMarshallingMap();
                ANS_LOGD("live view batch delete clear picture");
            }
            if (notification->GetNotificationRequest().IsSystemLiveView() &&
                requestContent->GetNotificationContent() != nullptr) {
                auto localLiveViewContent = std::static_pointer_cast<NotificationLocalLiveViewContent>(
                    requestContent->GetNotificationContent());
                localLiveViewContent->ClearButton();
                localLiveViewContent->ClearCapsuleIcon();
                ANS_LOGD("local live view batch delete clear picture");
            }
            if (IsSubscribedBysubscriber(record, notification)) {
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
    for (auto record : subscriberRecordList_) {
        record->subscriber->OnUpdated(notificationMap);
    }
}

void NotificationSubscriberManager::NotifyDoNotDisturbDateChangedInner(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    for (auto record : subscriberRecordList_) {
        if (record->userId == SUBSCRIBE_USER_ALL || IsSystemUser(record->userId) ||
            IsSystemUser(userId) || record->userId == userId) {
            record->subscriber->OnDoNotDisturbDateChange(date);
        }
    }
}

void NotificationSubscriberManager::NotifyBadgeEnabledChangedInner(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(callbackData->GetUid(), userId);
    for (auto record : subscriberRecordList_) {
        if (record->userId == SUBSCRIBE_USER_ALL || IsSystemUser(record->userId) ||
            IsSystemUser(userId) || record->userId == userId) {
            record->subscriber->OnBadgeEnabledChanged(callbackData);
        }
    }
}

bool NotificationSubscriberManager::IsSystemUser(int32_t userId)
{
    return ((userId >= SUBSCRIBE_USER_SYSTEM_BEGIN) && (userId <= SUBSCRIBE_USER_SYSTEM_END));
}

void NotificationSubscriberManager::NotifyEnabledNotificationChangedInner(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(callbackData->GetUid(), userId);
    for (auto record : subscriberRecordList_) {
        if (record->userId == SUBSCRIBE_USER_ALL || IsSystemUser(record->userId) ||
                IsSystemUser(userId) || record->userId == userId) {
            record->subscriber->OnEnabledNotificationChanged(callbackData);
        }
    }
}

void NotificationSubscriberManager::SetBadgeNumber(const sptr<BadgeNumberCallbackData> &badgeData)
{
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    std::function<void()> setBadgeNumberFunc = [this, badgeData] () {
        int32_t userId = SUBSCRIBE_USER_INIT;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(badgeData->GetUid(), userId);
        for (auto record : subscriberRecordList_) {
            if (record->userId == SUBSCRIBE_USER_ALL || IsSystemUser(record->userId) ||
                IsSystemUser(userId) || record->userId == userId) {
                ANS_LOGD("SetBadgeNumber instanceKey: %{public}s", badgeData->GetAppInstanceKey().c_str());
                record->subscriber->OnBadgeChanged(badgeData);
            }
        }
    };
    notificationSubQueue_->submit(setBadgeNumberFunc);
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

void NotificationSubscriberManager::IsDeviceFlag(const std::shared_ptr<SubscriberRecord> &record,
    const sptr<Notification> &notification, bool &wearableFlag, bool &headsetFlag, bool &keyNodeFlag)
{
    if (record == nullptr || notification == nullptr) {
        ANS_LOGE("record or notification is nullptr.");
        return;
    }
    sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("request is nullptr.");
        return;
    }
    auto flagsMap = request->GetDeviceFlags();
    if (flagsMap == nullptr || flagsMap->size() <= 0) {
        ANS_LOGE("flagsMap is nullptr or flagsMap size <= 0.");
        return;
    }

    if (record->deviceType == DEVICE_TYPE_LITE_WEARABLE) {
        auto flagIter = flagsMap->find(DEVICE_TYPE_LITE_WEARABLE);
        if (flagIter != flagsMap->end() && flagIter->second != nullptr) {
            wearableFlag = true;
        }
    } else if (record->deviceType == DEVICE_TYPE_WEARABLE) {
        auto flagIter = flagsMap->find(DEVICE_TYPE_WEARABLE);
        if (flagIter != flagsMap->end() && flagIter->second != nullptr) {
            wearableFlag = true;
        }
    } else if (record->deviceType == DEVICE_TYPE_HEADSET) {
        auto flagIter = flagsMap->find(DEVICE_TYPE_HEADSET);
        if (flagIter != flagsMap->end() && flagIter->second != nullptr) {
            headsetFlag = true;
        }
    }
    if (request->IsCommonLiveView()) {
        auto flags = request->GetFlags();
        if (flags == nullptr) {
            ANS_LOGE("flags is nullptr.");
            return;
        }
        if (flags->IsVibrationEnabled() == NotificationConstant::FlagStatus::OPEN &&
            flags->IsSoundEnabled() == NotificationConstant::FlagStatus::OPEN) {
            keyNodeFlag = true;
        }
    }
}

void NotificationSubscriberManager::TrackCodeLog(
    const sptr<Notification> &notification, const bool &wearableFlag, const bool &headsetFlag, const bool &keyNodeFlag)
{
    if (notification == nullptr) {
        ANS_LOGE("notification is empty.");
        return;
    }
    sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("request is nullptr.");
        return;
    }
    auto slotType = request->GetSlotType();
    bool isLiveViewType = (slotType == NotificationConstant::SlotType::LIVE_VIEW);
    if (wearableFlag && headsetFlag) {
        HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1)
                                    .syncWatchHeadSet(isLiveViewType)
                                    .keyNode(keyNodeFlag)
                                    .SlotType(slotType);
        NotificationAnalyticsUtil::ReportOperationsDotEvent(message);
    } else {
        if (headsetFlag) {
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1)
                                        .syncHeadSet(isLiveViewType)
                                        .keyNode(keyNodeFlag)
                                        .SlotType(slotType);
            NotificationAnalyticsUtil::ReportOperationsDotEvent(message);
        } else if (wearableFlag) {
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1)
                                        .syncWatch(isLiveViewType)
                                        .keyNode(keyNodeFlag)
                                        .SlotType(slotType);
            NotificationAnalyticsUtil::ReportOperationsDotEvent(message);
        }
    }
}
void NotificationSubscriberManager::DistributeOperation(const sptr<Notification>& notification)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("queue is nullptr");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::DistributeOperationInner, this, notification);

    notificationSubQueue_->submit(func);
}

void NotificationSubscriberManager::DistributeOperationInner(const sptr<Notification>& notification)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    for (const auto& record : subscriberRecordList_) {
        if (record == nullptr) {
            continue;
        }
        if (IsSubscribedBysubscriber(record, notification)) {
            if (record->subscriber != nullptr) {
                ANS_LOGI("call OnResponse.");
                record->subscriber->OnResponse(notification);
            }
        }
    }
}
}  // namespace Notification
}  // namespace OHOS
