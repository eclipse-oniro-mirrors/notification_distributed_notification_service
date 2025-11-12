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

#include "notification_subscriber_manager.h"

#include <algorithm>
#include <memory>
#include <set>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ipc_skeleton.h"
#include "notification_flags.h"
#include "notification_constant.h"
#include "notification_config_parse.h"
#include "notification_extension_wrapper.h"
#include "os_account_manager_helper.h"
#include "remote_death_recipient.h"
#include "advanced_notification_service.h"
#include "notification_analytics_util.h"

#include "bool_wrapper.h"
#include "advanced_notification_inline.h"
#include "liveview_all_scenarios_extension_wrapper.h"
#ifdef ALL_SCENARIO_COLLABORATION
#include "distributed_collaboration_service.h"
#endif

namespace OHOS {
namespace Notification {

const uint32_t FILTETYPE_IM = 1 << 0;
const uint32_t FILTETYPE_QUICK_REPLY_IM = 2 << 0;
static const std::string EXTENDINFO_INFO_PRE = "notification_collaboration_";
static const std::string EXTENDINFO_DEVICE_ID = "deviceId";

NotificationSubscriberManager::NotificationSubscriberManager()
{
    ANS_LOGD("called");
    notificationSubQueue_ = std::make_shared<ffrt::queue>("NotificationSubscriberMgr");
    recipient_ = new (std::nothrow)
        RemoteDeathRecipient(std::bind(&NotificationSubscriberManager::OnRemoteDied, this, std::placeholders::_1));
    if (recipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
}

NotificationSubscriberManager::~NotificationSubscriberManager()
{
    ANS_LOGD("called");
    subscriberRecordList_.clear();
}

void NotificationSubscriberManager::ResetFfrtQueue()
{
    if (notificationSubQueue_ != nullptr) {
        notificationSubQueue_.reset();
    }
}

ErrCode NotificationSubscriberManager::AddSubscriber(const sptr<IAnsSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo, uint32_t subscribedFlags)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationSubscribeInfo> subInfo = subscribeInfo;
    if (subInfo == nullptr) {
        subInfo = new (std::nothrow) NotificationSubscribeInfo();
        if (subInfo == nullptr) {
            ANS_LOGE("null subInfo");
            return ERR_ANS_NO_MEMORY;
        }
    }
    int32_t callingUid = IPCSkeleton().GetCallingUid();
    std::string callingBuneldName = GetClientBundleName();
    subInfo->SetSubscriberBundleName(callingBuneldName);
    subInfo->SetSubscriberUid(callingUid);
    subInfo->SetSubscribedFlags(subscribedFlags);

    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_9, EventBranchId::BRANCH_2);
    message.Message(callingBuneldName + "_" +
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
        ANS_LOGE("null queue");
        return result;
    }

    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, &subscriber, &subInfo, &result]() {
        result = this->AddSubscriberInner(subscriber, subInfo);
    }));
    notificationSubQueue_->wait(handler);

    std::string bundleNames;
    for (auto bundleName : subInfo->GetAppNames()) {
        bundleNames += bundleName;
        bundleNames += " ";
    }
    std::string slotTypes;
    for (auto slotType : subInfo->GetSlotTypes()) {
        slotTypes += std::to_string(slotType);
        slotTypes += " ";
    }
    ANS_LOGI("%{public}s_, user: %{public}s, bundleNames: %{public}s, deviceType: %{public}s, slotTypes: %{public}s, "
        "Add subscriber result: %{public}d", callingBuneldName.c_str(),
        std::to_string(subInfo->GetAppUserId()).c_str(), bundleNames.c_str(), subInfo->GetDeviceType().c_str(),
        slotTypes.c_str(), result);
    message.ErrorCode(result).Append(bundleNames + "," + subInfo->GetDeviceType() + "," + slotTypes);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode NotificationSubscriberManager::RemoveSubscriber(
    const sptr<IAnsSubscriber> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_ANS_TASK_ERR;
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
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
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyConsumedFunc =
        std::bind(&NotificationSubscriberManager::NotifyConsumedInner, this, notification, notificationMap);

    notificationSubQueue_->submit(NotifyConsumedFunc);
}

void NotificationSubscriberManager::NotifyApplicationInfoNeedChanged(const std::string& bundleName)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationSubQueue_ == nullptr || bundleName.empty()) {
        ANS_LOGE("null queue");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyConsumedFunc =
        std::bind(&NotificationSubscriberManager::NotifyApplicationInfochangedInner, this, bundleName);

    notificationSubQueue_->submit(NotifyConsumedFunc);
}


void NotificationSubscriberManager::NotifyApplicationInfochangedInner(const std::string& bundleName)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("bundleName: %{public}s", bundleName.c_str());
    for (auto record : subscriberRecordList_) {
        if (record->needNotifyApplicationChanged && (record->subscribedFlags_ &
            NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_APPLICATIONINFONEED_CHANGED)) {
            record->subscriber->OnApplicationInfoNeedChanged(bundleName);
        }
    }
}

void NotificationSubscriberManager::BatchNotifyConsumed(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, const std::shared_ptr<SubscriberRecord> &record)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGI("Start batch notifyConsumed.");
    if (notifications.empty() || notificationMap == nullptr || record == nullptr) {
        ANS_LOGE("Invalid input.");
        return;
    }

    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }

#ifdef ALL_SCENARIO_COLLABORATION
    for (auto item : notifications) {
        DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(item);
    }
#endif
    AppExecFwk::EventHandler::Callback batchNotifyConsumedFunc = std::bind(
        &NotificationSubscriberManager::BatchNotifyConsumedInner, this, notifications, notificationMap, record);

    notificationSubQueue_->submit(batchNotifyConsumedFunc);
}

void NotificationSubscriberManager::NotifyCanceled(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
#ifdef ENABLE_ANS_AGGREGATION
    std::vector<sptr<Notification>> notifications;
    notifications.emplace_back(notification);
    EXTENTION_WRAPPER->UpdateByCancel(notifications, deleteReason);
#endif

    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }
#ifdef ALL_SCENARIO_COLLABORATION
    DistributedCollaborationService::GetInstance().AddCollaborativeDeleteItem(notification);
#endif
    AppExecFwk::EventHandler::Callback NotifyCanceledFunc = std::bind(
        &NotificationSubscriberManager::NotifyCanceledInner, this, notification, notificationMap, deleteReason);

    notificationSubQueue_->submit(NotifyCanceledFunc);
}

void NotificationSubscriberManager::BatchNotifyCanceled(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
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
        ANS_LOGE("null queue");
        return;
    }
    AppExecFwk::EventHandler::Callback NotifyUpdatedFunc =
        std::bind(&NotificationSubscriberManager::NotifyUpdatedInner, this, notificationMap);

    notificationSubQueue_->submit(NotifyUpdatedFunc);
}

void NotificationSubscriberManager::NotifyDoNotDisturbDateChanged(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date, const std::string &bundle)
{
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyDoNotDisturbDateChangedInner, this, userId, date, bundle);

    notificationSubQueue_->submit(func);
}

void NotificationSubscriberManager::NotifyEnabledNotificationChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyEnabledNotificationChangedInner, this, callbackData);

    notificationSubQueue_->submit(func);
}

void NotificationSubscriberManager::NotifyBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }
    AppExecFwk::EventHandler::Callback func =
        std::bind(&NotificationSubscriberManager::NotifyBadgeEnabledChangedInner, this, callbackData);

    notificationSubQueue_->submit(func);
}

void NotificationSubscriberManager::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    ANS_LOGD("called");
    if (notificationSubQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([this, object]() {
        ANS_LOGD("ffrt enter!");
        std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(object);
        if (record != nullptr) {
            auto subscriberUid = record->subscriberUid;
            ANS_LOGI("subscriber removed . subscriberUid = %{public}d", record->subscriberUid);
            {
                std::lock_guard<ffrt::mutex> lock(subscriberRecordListMutex_);
                subscriberRecordList_.remove(record);
            }
            if (record->isSubscribeSelf) {
                AdvancedNotificationService::GetInstance()->RemoveSystemLiveViewNotificationsOfSa(subscriberUid);
            }
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
    const sptr<IAnsSubscriber> &subscriber)
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
    const sptr<IAnsSubscriber> &subscriber)
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
    record->bundleList_.clear();
    record->uidList_.clear();
    record->subscribedAll = true;
    for (auto bundle : subscribeInfo->GetAppNames()) {
        record->bundleList_.insert(bundle);
        record->subscribedAll = false;
    }
    for (auto uid : subscribeInfo->GetAppUids()) {
        record->uidList_.insert(uid);
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
    record->subscriberBundleName_ = subscribeInfo->GetSubscriberBundleName();
    record->filterType = subscribeInfo->GetFilterType();
    record->needNotifyApplicationChanged = subscribeInfo->GetNeedNotifyApplication();
    record->needNotifyResponse = subscribeInfo->GetNeedNotifyResponse();
    record->isSubscribeSelf = subscribeInfo->GetIsSubscribeSelf();
    record->subscribedFlags_ = subscribeInfo->GetSubscribedFlags();
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
        for (auto uid : subscribeInfo->GetAppUids()) {
            if (record->subscribedAll) {
                record->uidList_.insert(uid);
            } else {
                record->uidList_.erase(uid);
            }
        }
    } else {
        record->bundleList_.clear();
        record->uidList_.clear();
        record->subscribedAll = false;
    }
}

ErrCode NotificationSubscriberManager::AddSubscriberInner(
    const sptr<IAnsSubscriber> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(subscriber);
    if (record == nullptr) {
        record = CreateSubscriberRecord(subscriber);
        if (record == nullptr) {
            ANS_LOGE("null record");
            return ERR_ANS_NO_MEMORY;
        }

        {
            std::lock_guard<ffrt::mutex> lock(subscriberRecordListMutex_);
            subscriberRecordList_.push_back(record);
        }
        record->subscriber->AsObject()->AddDeathRecipient(recipient_);
        if (subscribeInfo->GetSubscribedFlags() & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CONNECTED) {
            record->subscriber->OnConnected();
        }
        ANS_LOGD("subscriber connected");
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
    const sptr<IAnsSubscriber> &subscriber, const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    std::shared_ptr<SubscriberRecord> record = FindSubscriberRecord(subscriber);

    if (record == nullptr) {
        ANS_LOGE("null record");
        return ERR_ANS_INVALID_PARAM;
    }

    RemoveRecordInfo(record, subscribeInfo);

    if (!record->subscribedAll && record->bundleList_.empty() && record->uidList_.empty()) {
        record->subscriber->AsObject()->RemoveDeathRecipient(recipient_);
        {
            std::lock_guard<ffrt::mutex> lock(subscriberRecordListMutex_);
            subscriberRecordList_.remove(record);
        }
        if (record->subscribedFlags_ & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_DISCONNECTED) {
            record->subscriber->OnDisconnected();
        }
        ANS_LOGI("subscriber is disconnected.");
    }

    return ERR_OK;
}

void NotificationSubscriberManager::NotifyConsumedInner(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap)
{
    if (notification == nullptr) {
        ANS_LOGE("null notification");
        return;
    }
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s notification->GetUserId <%{public}d>", __FUNCTION__, notification->GetUserId());
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
    AdvancedNotificationService::GetInstance()->UpdatePriorityType(notification->GetNotificationRequestPoint());
#endif
    for (auto record : subscriberRecordList_) {
        ANS_LOGD("%{public}s record->userId = <%{public}d> BundleName  = <%{public}s deviceType = %{public}s",
            __FUNCTION__, record->userId, notification->GetBundleName().c_str(), record->deviceType.c_str());
        if (IsSubscribedBysubscriber(record, notification) && ConsumeRecordFilter(record, notification) &&
            (record->subscribedFlags_ & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CONSUMED)) {
            if (!record->subscriber->AsObject()->IsProxyObject()) {
                MessageParcel data;
                if (!data.WriteParcelable(notification)) {
                    ANS_LOGE("WriteParcelable failed.");
                    continue;
                }
                sptr<Notification> notificationStub = data.ReadParcelable<Notification>();
                if (notificationStub == nullptr) {
                    ANS_LOGE("null notificationStub");
                    continue;
                }
                record->subscriber->OnConsumed(notificationStub, notificationMap);
                continue;
            }

        if (notificationMap != nullptr && notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            record->subscriber->OnConsumedWithMaxCapacity(notification, notificationMap);
        } else if (notificationMap != nullptr && !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            record->subscriber->OnConsumed(notification, notificationMap);
        } else if (notificationMap == nullptr && notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
            record->subscriber->OnConsumedWithMaxCapacity(notification);
        } else {
            record->subscriber->OnConsumed(notification);
        }
        }
    }
    NotificationSubscriberManager::TrackCodeLog(notification);
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
bool NotificationSubscriberManager::GetIsEnableEffectedRemind()
{
    // Ignore the impact of the bundleName and userId for smart reminder switch now.
    std::lock_guard<ffrt::mutex> lock(subscriberRecordListMutex_);
    for (auto record : subscriberRecordList_) {
        if (record->deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) != 0) {
            return true;
        }
    }
    return false;
}

bool NotificationSubscriberManager::IsDeviceTypeSubscriberd(const std::string deviceType)
{
    std::lock_guard<ffrt::mutex> lock(subscriberRecordListMutex_);
    for (auto record : subscriberRecordList_) {
        if (record->deviceType.compare(deviceType) == 0) {
            return true;
        }
    }
    ANS_LOGE("device = %{public}s", deviceType.c_str());
    return false;
}

ErrCode NotificationSubscriberManager::IsDeviceTypeAffordConsume(
    const std::string deviceType,
    const sptr<NotificationRequest> &request,
    bool &result)
{
    std::list<std::shared_ptr<SubscriberRecord>> copySubscriberRecordList;
    {
        std::lock_guard<ffrt::mutex> lock(subscriberRecordListMutex_);
        for (auto record : subscriberRecordList_) {
            if (record->deviceType.compare(deviceType) != 0) {
                continue;
            }
            copySubscriberRecordList.push_back(record);
        }
    }

    for (auto record : copySubscriberRecordList) {
        sptr<Notification> notification = new (std::nothrow) Notification(request);
        if (notification == nullptr) {
            ANS_LOGE("null notification");
            return ERR_ANS_NO_MEMORY;
        }
        if (IsSubscribedBysubscriber(record, notification) && ConsumeRecordFilter(record, notification)) {
            result = true;
            return ERR_OK;
        }
    }

    result = false;
    return ERR_OK;
}
#endif

void NotificationSubscriberManager::BatchNotifyConsumedInner(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, const std::shared_ptr<SubscriberRecord> &record)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notifications.empty() || notificationMap == nullptr || record == nullptr) {
        ANS_LOGE("Invalid input.");
        return;
    }
    if (!(record->subscribedFlags_ & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CONSUMED)) {
        ANS_LOGE("Subscriber does not implement OnConsumed method");
        return;
    }

    ANS_LOGD("Record->userId = <%{public}d>", record->userId);
    std::vector<sptr<Notification>> currNotifications;
    for (size_t i = 0; i < notifications.size(); i ++) {
        sptr<Notification> notification = notifications[i];
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
        AdvancedNotificationService::GetInstance()->UpdatePriorityType(notification->GetNotificationRequestPoint());
#endif
        if (notification == nullptr) {
            continue;
        }
        bool wearableFlag = false;
        bool headsetFlag = false;
        bool keyNodeFlag = false;
        if (IsSubscribedBysubscriber(record, notification) && ConsumeRecordFilter(record, notification)) {
            currNotifications.emplace_back(notification);
            if (record->subscriber != nullptr) {
                NotificationSubscriberManager::TrackCodeLog(notification);
            }
        }
    }
    if (!currNotifications.empty()) {
        ANS_LOGD("OnConsumedList currNotifications size = <%{public}zu>", currNotifications.size());
        if (record->subscriber != nullptr) {
            if (notificationMap != nullptr) {
                record->subscriber->OnConsumedList(currNotifications, notificationMap);
            } else {
                record->subscriber->OnConsumedList(currNotifications);
            }
        }
    }
}

void NotificationSubscriberManager::NotifyCanceledInner(
    const sptr<Notification> &notification, const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    if (notification == nullptr) {
        ANS_LOGE("null notification");
        return;
    }
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s notification->GetUserId <%{public}d>", __FUNCTION__, notification->GetUserId());
    std::shared_ptr<NotificationLiveViewContent> liveViewContent = nullptr;

    if (notification->GetNotificationRequestPoint() != nullptr) {
        bool liveView = notification->GetNotificationRequest().IsCommonLiveView();
        HaOperationMessage(liveView).SyncDelete(notification->GetKey());
    }

    if (IsSystemUser(notification->GetUserId())) {
        if ((notification->GetNotificationRequestPoint()->GetWantAgent() != nullptr) ||
            (notification->GetNotificationRequestPoint()->GetRemovalWantAgent() != nullptr) ||
            (notification->GetNotificationRequestPoint()->GetMaxScreenWantAgent() != nullptr)) {
                HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_11, EventBranchId::BRANCH_0);
                message.Message("User 0 ntf:" + notification->GetKey());
                NotificationAnalyticsUtil::ReportModifyEvent(message);
            }
    }
    ANS_LOGI("CancelNotification key=%{public}s", notification->GetKey().c_str());
    for (auto record : subscriberRecordList_) {
        ANS_LOGD("%{public}s record->userId = <%{public}d>", __FUNCTION__, record->userId);
        if (IsSubscribedBysubscriber(record, notification) &&
            (record->subscribedFlags_ & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CANCELED)) {
            if (notificationMap != nullptr && notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
                record->subscriber->OnCanceledWithMaxCapacity(notification, notificationMap, deleteReason);
            } else if (notificationMap != nullptr && !notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
                record->subscriber->OnCanceled(notification, notificationMap, deleteReason);
            } else if (notificationMap == nullptr && notification->GetNotificationRequestPoint()->IsCommonLiveView()) {
                record->subscriber->OnCanceledWithMaxCapacity(notification, deleteReason);
            } else {
                record->subscriber->OnCanceled(notification, deleteReason);
            }
        }
    }
}

bool NotificationSubscriberManager::IsSubscribedBysubscriber(
    const std::shared_ptr<SubscriberRecord> &record, const sptr<Notification> &notification)
{
    auto soltType = notification->GetNotificationRequestPoint()->GetSlotType();
    auto bundleNames = notification->GetBundleName();
    auto uid = notification->GetNotificationRequestPoint()->GetOwnerUid();
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
    if (!record->isSubscribeSelf &&
        EXTENTION_WRAPPER->IsSubscribeControl(record->subscriberBundleName_, soltType)) {
        ANS_LOGD("%{public}s cannot receive %{public}d notification", record->subscriberBundleName_.c_str(), soltType);
        return false;
    }
#endif
    auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), bundleNames);
    auto iterUid = std::find(record->uidList_.begin(), record->uidList_.end(), uid);
    bool isSubscribedTheNotification =
        record->subscribedAll || (iter != record->bundleList_.end()) || (iterUid != record->uidList_.end()) ||
        (notification->GetNotificationRequestPoint()->GetCreatorUid() == record->subscriberUid);
    if (!isSubscribedTheNotification) {
        return false;
    }
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
    ANS_LOGD("filterType = %{public}u", record->filterType);
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
        std::string bundleName = notification->GetBundleName();
        if (isQuickReply && record->deviceType == DEVICE_TYPE_WEARABLE &&
            !DelayedSingleton<NotificationConfigParse>::GetInstance()->IsDistributedReplyEnabled(bundleName)) {
            ANS_LOGI("ConsumeRecordFilter-filterType-im bundle %{public}s", bundleName.c_str());
            return false;
        }
    }

    return true;
}

void NotificationSubscriberManager::BatchNotifyCanceledInner(const std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    ANS_LOGD("notifications size = <%{public}zu>", notifications.size());

    std::string notificationKeys = "";
    for (auto notification : notifications) {
        notificationKeys.append(notification->GetKey()).append("-");
        if (notification->GetNotificationRequestPoint() != nullptr) {
            bool liveView = notification->GetNotificationRequestPoint()->IsCommonLiveView();
            HaOperationMessage(liveView).SyncDelete(notification->GetKey());
        }
    }
    ANS_LOGI("CancelNotification key = %{public}s", notificationKeys.c_str());

    for (auto record : subscriberRecordList_) {
        if (record == nullptr) {
            continue;
        }
        if (!(record->subscribedFlags_ & (NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_BATCHCANCELED |
            NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_CANCELED))) {
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
            if (record->subscriber == nullptr) {
                return;
            }
            if (notificationMap != nullptr) {
                record->subscriber->OnCanceledList(currNotifications, notificationMap, deleteReason);
            } else {
                record->subscriber->OnCanceledList(currNotifications, deleteReason);
            }
        }
    }
}

void NotificationSubscriberManager::NotifyUpdatedInner(const sptr<NotificationSortingMap> &notificationMap)
{
    if (notificationMap == nullptr) {
        ANS_LOGE("null notificationMap");
        return;
    }
    for (auto record : subscriberRecordList_) {
        if (record->subscribedFlags_ & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_UPDATE) {
            record->subscriber->OnUpdated(notificationMap);
        }
    }
}

template <typename... Args>
void NotificationSubscriberManager::NotifySubscribers(int32_t userId, const std::string& bundle,
    NotificationConstant::SubscribedFlag flags, ErrCode (IAnsSubscriber::*func)(Args...), Args&& ... args)
{
    for (auto& record : subscriberRecordList_) {
        if (IsNeedNotifySubscribers(record, userId, bundle) && (record->subscribedFlags_ & flags)) {
            (record->subscriber->*func)(std::forward<Args>(args)...);
        }
    }
}

bool NotificationSubscriberManager::IsNeedNotifySubscribers(const std::shared_ptr<SubscriberRecord> &record,
    const int32_t &userId, const std::string &bundle)
{
    if (record->userId == SUBSCRIBE_USER_ALL || IsSystemUser(record->userId) || IsSystemUser(userId)) {
        return true;
    }

    if (record->userId == userId) {
        if (record->isSubscribeSelf) {
            auto iter = std::find(record->bundleList_.begin(), record->bundleList_.end(), bundle);
            if (iter != record->bundleList_.end()) {
                return true;
            }
        } else {
            return true;
        }
    }
    return false;
}

void NotificationSubscriberManager::NotifyDoNotDisturbDateChangedInner(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date, const std::string &bundle)
{
    if (date == nullptr) {
        ANS_LOGE("null date");
        return;
    }
    NotifySubscribers(userId, bundle, NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_DONOTDISTURBDATA_CHANGED,
        &IAnsSubscriber::OnDoNotDisturbDateChange, date);
}

void NotificationSubscriberManager::NotifyBadgeEnabledChangedInner(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    if (callbackData == nullptr) {
        ANS_LOGE("null callbackData");
        return;
    }
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(callbackData->GetUid(), userId);
    std::string bundle = callbackData->GetBundle();
    NotifySubscribers(userId, bundle, NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_BADGEENABLE_CHANGED,
        &IAnsSubscriber::OnBadgeEnabledChanged, callbackData);
}

bool NotificationSubscriberManager::IsSystemUser(int32_t userId)
{
    return ((userId >= SUBSCRIBE_USER_SYSTEM_BEGIN) && (userId <= SUBSCRIBE_USER_SYSTEM_END));
}

void NotificationSubscriberManager::NotifyEnabledNotificationChangedInner(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    if (callbackData == nullptr) {
        ANS_LOGE("null callbackData");
        return;
    }
    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(callbackData->GetUid(), userId);
    std::string bundle = callbackData->GetBundle();
    NotifySubscribers(userId, bundle, NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_ENABLENOTIFICATION_CHANGED,
        &IAnsSubscriber::OnEnabledNotificationChanged, callbackData);
}

void NotificationSubscriberManager::SetBadgeNumber(const sptr<BadgeNumberCallbackData> &badgeData)
{
    if (notificationSubQueue_ == nullptr || badgeData == nullptr) {
        ANS_LOGE("null queue or badgeData");
        return;
    }
    std::function<void()> setBadgeNumberFunc = [this, badgeData] () {
        int32_t userId = SUBSCRIBE_USER_INIT;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(badgeData->GetUid(), userId);
        std::string bundle = badgeData->GetBundle();
        NotifySubscribers(userId, bundle, NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_BADGE_CHANGED,
            &IAnsSubscriber::OnBadgeChanged, badgeData);
        NotificationAnalyticsUtil::ReportBadgeChange(badgeData);
    };
    notificationSubQueue_->submit(setBadgeNumberFunc);
}

void NotificationSubscriberManager::RegisterOnSubscriberAddCallback(
    std::function<void(const std::shared_ptr<SubscriberRecord> &)> callback)
{
    if (callback == nullptr) {
        ANS_LOGE("null callback");
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

void NotificationSubscriberManager::TrackCodeLog(const sptr<Notification> &notification)
{
    if (notification == nullptr) {
        ANS_LOGE("null record or notification");
        return;
    }
    sptr<NotificationRequest> request = notification->GetNotificationRequestPoint();
    if (request == nullptr) {
        ANS_LOGE("null request");
        return;
    }
    auto flagsMap = request->GetDeviceFlags();
    if (flagsMap == nullptr || flagsMap->size() <= 0) {
        ANS_LOGE("null flagsMap or empty flagsMap");
        return;
    }

    bool keyNode = false;
    bool commonLiveView = request->IsCommonLiveView();
    std::shared_ptr<AAFwk::WantParams> extendInfo = request->GetExtendInfo();
    if (extendInfo != nullptr) {
        auto value = extendInfo->GetParam("collaboration_node");
        AAFwk::IBoolean* ao = AAFwk::IBoolean::Query(value);
        if (ao != nullptr) {
            keyNode = AAFwk::Boolean::Unbox(ao);
        }
    }

    std::string hashCode = notification->GetKey();
    std::vector<std::string> deviceTypes;
    for (auto& flag : *flagsMap) {
        deviceTypes.push_back(flag.first);
    }
    HaOperationMessage operation = HaOperationMessage(commonLiveView).KeyNode(keyNode)
        .SyncPublish(hashCode, deviceTypes);
    NotificationAnalyticsUtil::ReportOperationsDotEvent(operation);
}

ErrCode NotificationSubscriberManager::DistributeOperation(
    const sptr<NotificationOperationInfo>& operationInfo, const sptr<NotificationRequest>& request)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (notificationSubQueue_ == nullptr || operationInfo == nullptr) {
        ANS_LOGE("null queue");
        return ERR_ANS_TASK_ERR;
    }

    ErrCode result = ERR_OK;
    int32_t funcResult = -1;
    ffrt::task_handle handler = notificationSubQueue_->submit_h(std::bind([&]() {
        result = DistributeOperationTask(operationInfo, request, funcResult);
    }));
    notificationSubQueue_->wait(handler);
    ANS_LOGI("Subscriber manager operation %{public}s %{public}d", operationInfo->GetHashCode().c_str(), result);
    return result;
}

ErrCode NotificationSubscriberManager::DistributeOperationTask(const sptr<NotificationOperationInfo>& operationInfo,
    const sptr<NotificationRequest>& request, int32_t &funcResult)
{
    ErrCode result = ERR_OK;
    for (const auto& record : subscriberRecordList_) {
        if (record == nullptr) {
            continue;
        }
        if (!(record->subscribedFlags_ & NotificationConstant::SubscribedFlag::SUBSCRIBE_ON_OPERATIONRESPONSE)) {
            continue;
        }
        std::string notificationUdid = "";
        if (request != nullptr && request->GetExtendInfo() != nullptr) {
            notificationUdid = request->GetExtendInfo()->GetStringParam(EXTENDINFO_INFO_PRE + EXTENDINFO_DEVICE_ID);
        }
        if (record->needNotifyResponse && record->subscriber != nullptr) {
            operationInfo->SetNotificationUdid(notificationUdid);
            result = record->subscriber->OnOperationResponse(operationInfo, funcResult);
            if (result == ERR_OK) {
                return result;
            }
        }
        result = ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }
    return result;
}
}  // namespace Notification
}  // namespace OHOS
