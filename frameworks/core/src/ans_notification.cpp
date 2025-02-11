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

#include "ans_notification.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_manager_death_recipient.h"
#include "ans_manager_proxy.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "notification_button_option.h"
#include "notification_local_live_view_subscriber.h"
#include "reminder_request_alarm.h"
#include "reminder_request_calendar.h"
#include "reminder_request_timer.h"
#include "system_ability_definition.h"
#include "unique_fd.h"

#include <memory>
#include <thread>

namespace OHOS {
namespace Notification {
namespace {
const int32_t MAX_RETRY_TIME = 30;
const int32_t SLEEP_TIME = 1000;
const uint32_t MAX_PUBLISH_DELAY_TIME = 5;
const int32_t DEFAULT_INSTANCE_KEY = -1;
const std::string DOWNLOAD_TITLE = "title";
const std::string DOWNLOAD_FILENAME = "fileName";
}
ErrCode AnsNotification::AddNotificationSlot(const NotificationSlot &slot)
{
    std::vector<NotificationSlot> slots;
    slots.push_back(slot);
    return AddNotificationSlots(slots);
}

ErrCode AnsNotification::AddSlotByType(const NotificationConstant::SlotType &slotType)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddSlotByType(slotType);
}

ErrCode AnsNotification::AddNotificationSlots(const std::vector<NotificationSlot> &slots)
{
    if (slots.size() == 0) {
        ANS_LOGE("Failed to add notification slots because input slots size is 0.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationSlot>> slotsSptr;
    for (auto it = slots.begin(); it != slots.end(); ++it) {
        sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(*it);
        if (slot == nullptr) {
            ANS_LOGE("Failed to create NotificationSlot ptr.");
            return ERR_ANS_NO_MEMORY;
        }
        slotsSptr.emplace_back(slot);
    }

    return proxy->AddSlots(slotsSptr);
}

ErrCode AnsNotification::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGI("enter RemoveNotificationSlot，slotType:%{public}d", slotType);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveSlotByType(slotType);
}

ErrCode AnsNotification::RemoveAllSlots()
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveAllSlots();
}

ErrCode AnsNotification::GetNotificationSlot(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetSlotByType(slotType, slot);
}

ErrCode AnsNotification::GetNotificationSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetSlots(slots);
}

ErrCode AnsNotification::GetNotificationSlotNumAsBundle(const NotificationBundleOption &bundleOption, uint64_t &num)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->GetSlotNumAsBundle(bo, num);
}

ErrCode AnsNotification::GetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t &slotFlags)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->GetSlotFlagsAsBundle(bo, slotFlags);
}

ErrCode AnsNotification::SetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t slotFlags)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->SetSlotFlagsAsBundle(bo, slotFlags);
}

ErrCode AnsNotification::PublishNotification(const NotificationRequest &request)
{
    ANS_LOGD("enter");
    return PublishNotification(std::string(), request);
}

ErrCode AnsNotification::PublishNotification(const std::string &label, const NotificationRequest &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("enter");

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!IsValidTemplate(request) || !IsValidDelayTime(request)) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the series numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("Create notificationRequest ptr fail.");
        return ERR_ANS_NO_MEMORY;
    }

    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    reqPtr->SetCreatorInstanceKey(instanceKey);

    return proxy->Publish(label, reqPtr);
}

ErrCode AnsNotification::PublishNotificationForIndirectProxy(const NotificationRequest &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("enter");

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!IsValidTemplate(request) || !IsValidDelayTime(request)) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the series numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("Create notificationRequest ptr fail.");
        return ERR_ANS_NO_MEMORY;
    }

    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    reqPtr->SetCreatorInstanceKey(instanceKey);

    return proxy->PublishNotificationForIndirectProxy(reqPtr);
}

ErrCode AnsNotification::CancelNotification(int32_t notificationId)
{
    return CancelNotification("", notificationId);
}

ErrCode AnsNotification::CancelNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGI("enter CancelNotification,notificationId:%{public}d", notificationId);
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    return proxy->Cancel(notificationId, label, instanceKey);
}

ErrCode AnsNotification::CancelAllNotifications()
{
    ANS_LOGI("CancelAllNotifications called.");

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    return proxy->CancelAll(instanceKey);
}

ErrCode AnsNotification::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGI("enter CancelAsBundle,notificationId:%{public}d", notificationId);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelAsBundle(notificationId, representativeBundle, userId);
}

ErrCode AnsNotification::CancelAsBundle(
    const NotificationBundleOption &bundleOption, int32_t notificationId)
{
    ANS_LOGI("enter CancelAsBundle,notificationId:%{public}d", notificationId);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->CancelAsBundle(bo, notificationId);
}

ErrCode AnsNotification::GetActiveNotificationNums(uint64_t &num)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetActiveNotificationNums(num);
}

ErrCode AnsNotification::GetActiveNotifications(std::vector<sptr<NotificationRequest>> &request)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    return proxy->GetActiveNotifications(request, instanceKey);
}

ErrCode AnsNotification::SetNotificationAgent(const std::string &agent)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationAgent(agent);
}

ErrCode AnsNotification::GetNotificationAgent(std::string &agent)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetNotificationAgent(agent);
}

ErrCode AnsNotification::CanPublishNotificationAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    if (representativeBundle.empty()) {
        ANS_LOGW("Input representativeBundle is empty");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CanPublishAsBundle(representativeBundle, canPublish);
}

ErrCode AnsNotification::PublishNotificationAsBundle(
    const std::string &representativeBundle, const NotificationRequest &request)
{
    if (representativeBundle.empty()) {
        ANS_LOGE("Refuse to publish the notification whit invalid representativeBundle");
        return ERR_ANS_INVALID_PARAM;
    }

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without effective content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the sequence numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture overtake the limit");
        return checkErr;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("Failed to create NotificationRequest ptr");
        return ERR_ANS_NO_MEMORY;
    }
    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    return proxy->PublishAsBundle(reqPtr, representativeBundle);
}

ErrCode AnsNotification::SetNotificationBadgeNum()
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t num = -1;
    return proxy->SetNotificationBadgeNum(num);
}

ErrCode AnsNotification::SetNotificationBadgeNum(int32_t num)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationBadgeNum(num);
}

ErrCode AnsNotification::IsAllowedNotify(bool &allowed)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->IsAllowedNotify(allowed);
}

ErrCode AnsNotification::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->IsAllowedNotifySelf(allowed);
}

ErrCode AnsNotification::CanPopEnableNotificationDialog(sptr<AnsDialogHostClient> &hostClient,
    bool &canPop, std::string &bundleName)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CanPopEnableNotificationDialog(hostClient, canPop, bundleName);
}

ErrCode AnsNotification::RemoveEnableNotificationDialog()
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveEnableNotificationDialog();
}

ErrCode AnsNotification::RequestEnableNotification(std::string &deviceId,
    sptr<AnsDialogHostClient> &hostClient,
    sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RequestEnableNotification(deviceId, hostClient, callerToken);
}

ErrCode AnsNotification::HasNotificationPolicyAccessPermission(bool &hasPermission)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->HasNotificationPolicyAccessPermission(hasPermission);
}

ErrCode AnsNotification::GetBundleImportance(NotificationSlot::NotificationLevel &importance)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t importanceTemp;
    ErrCode ret = proxy->GetBundleImportance(importanceTemp);
    if ((NotificationSlot::LEVEL_NONE <= importanceTemp) && (importanceTemp <= NotificationSlot::LEVEL_HIGH)) {
        importance = static_cast<NotificationSlot::NotificationLevel>(importanceTemp);
    } else {
        importance = NotificationSlot::LEVEL_UNDEFINED;
    }
    return ret;
}

ErrCode AnsNotification::SubscribeNotification(const NotificationSubscriber &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("Failed to subscribe with SubscriberImpl null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->Subscribe(subscriberSptr, nullptr);
}

ErrCode AnsNotification::SubscribeNotificationSelf(const NotificationSubscriber &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("Failed to subscribeSelf with SubscriberImpl null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SubscribeSelf(subscriberSptr);
}

ErrCode AnsNotification::SubscribeLocalLiveViewNotification(const NotificationLocalLiveViewSubscriber &subscriber,
    const bool isNative)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("Failed to subscribe with SubscriberImpl null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->SubscribeLocalLiveView(subscriberSptr, nullptr, isNative);
}

ErrCode AnsNotification::SubscribeNotification(
    const NotificationSubscriber &subscriber, const NotificationSubscribeInfo &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo(subscribeInfo);
    if (sptrInfo == nullptr) {
        ANS_LOGE("Failed to create NotificationSubscribeInfo ptr.");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("Failed to subscribe with SubscriberImpl null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    subscriberSptr->subscriber_.SetDeviceType(subscribeInfo.GetDeviceType());
    return proxy->Subscribe(subscriberSptr, sptrInfo);
}

ErrCode AnsNotification::UnSubscribeNotification(NotificationSubscriber &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("Failed to unsubscribe with SubscriberImpl null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->Unsubscribe(subscriberSptr, nullptr);
}

ErrCode AnsNotification::UnSubscribeNotification(
    NotificationSubscriber &subscriber, NotificationSubscribeInfo subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo(subscribeInfo);
    if (sptrInfo == nullptr) {
        ANS_LOGE("Failed to create NotificationSubscribeInfo ptr.");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("Failed to unsubscribe with SubscriberImpl null ptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->Unsubscribe(subscriberSptr, sptrInfo);
}

ErrCode AnsNotification::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    return SubscribeNotification(subscriber, nullptr);
}

ErrCode AnsNotification::SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("Subscriber is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("Failed to subscribe due to create subscriber listener failed.");
        return ERR_ANS_NO_MEMORY;
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();
    return proxy->SubscribeSelf(listener);
}

ErrCode AnsNotification::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("Subscriber is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("Failed to subscribe due to create subscriber listener failed.");
        return ERR_ANS_NO_MEMORY;
    }
    if (subscribeInfo != nullptr) {
        subscriber->SetDeviceType(subscribeInfo->GetDeviceType());
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();
    return proxy->Subscribe(listener, subscribeInfo);
}

ErrCode AnsNotification::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    return UnSubscribeNotification(subscriber, nullptr);
}

ErrCode AnsNotification::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (subscriber == nullptr) {
        ANS_LOGE("Subscriber is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    auto item = subscribers_.find(subscriber);
    if (item != subscribers_.end()) {
        sptr<SubscriberListener> listener = item->second;
        int32_t ret = proxy->Unsubscribe(listener, subscribeInfo);
        if (ret == ERR_OK) {
            subscribers_.erase(item);
        }
        return ret;
    }
    ANS_LOGE("Failed to unsubscribe due to subscriber not found.");
    return ERR_ANS_INVALID_PARAM;
}

ErrCode AnsNotification::TriggerLocalLiveView(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const NotificationButtonOption &buttonOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);

    if (buttonOption.GetButtonName().empty()) {
        ANS_LOGE("Invalid button name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    sptr<NotificationButtonOption> button(new (std::nothrow) NotificationButtonOption(buttonOption));
    return proxy->TriggerLocalLiveView(bo, notificationId, button);
}

ErrCode AnsNotification::RemoveNotification(const std::string &key, int32_t removeReason)
{
    ANS_LOGI("enter RemoveNotification,key:%{public}s,removeReason:%{public}d",
        key.c_str(), removeReason);
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (key.empty()) {
        ANS_LOGW("Input key is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->Delete(key, removeReason);
}

ErrCode AnsNotification::RemoveNotification(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const std::string &label, int32_t removeReason)
{
    ANS_LOGI("enter RemoveNotification,bundle:%{public}s,Id:%{public}d,reason:%{public}d",
        bundleOption.GetBundleName().c_str(), notificationId, removeReason);
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->RemoveNotification(bo, notificationId, label, removeReason);
}

ErrCode AnsNotification::RemoveAllNotifications(const NotificationBundleOption &bundleOption)
{
    ANS_LOGI("enter RemoveAllNotifications,bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy defeat.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->RemoveAllNotifications(bo);
}

ErrCode AnsNotification::RemoveNotifications(const std::vector<std::string> hashcodes, int32_t removeReason)
{
    ANS_LOGI("enter RemoveNotifications,removeReason:%{public}d", removeReason);
    if (hashcodes.empty()) {
        ANS_LOGE("Hashcodes is empty");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->RemoveNotifications(hashcodes, removeReason);
}

ErrCode AnsNotification::RemoveNotificationsByBundle(const NotificationBundleOption &bundleOption)
{
    ANS_LOGI("enter RemoveNotificationsByBundle,bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Defeated to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->DeleteByBundle(bo);
}

ErrCode AnsNotification::RemoveNotifications()
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->DeleteAll();
}

ErrCode AnsNotification::GetNotificationSlotsForBundle(
    const NotificationBundleOption &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundleName is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->GetSlotsByBundle(bo, slots);
}

ErrCode AnsNotification::GetNotificationSlotForBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundleName is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->GetSlotByBundle(bo, slotType, slot);
}

ErrCode AnsNotification::UpdateNotificationSlots(
    const NotificationBundleOption &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy flop.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->UpdateSlots(bo, slots);
}

ErrCode AnsNotification::GetAllActiveNotifications(std::vector<sptr<Notification>> &notification)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllActiveNotifications(notification);
}

ErrCode AnsNotification::GetAllActiveNotifications(
    const std::vector<std::string> key, std::vector<sptr<Notification>> &notification)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetSpecialActiveNotifications(key, notification);
}

ErrCode AnsNotification::GetActiveNotificationByFilter(const LiveViewFilter &filter,
    sptr<NotificationRequest> &request)
{
    if (filter.bundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    ANS_LOGD("Bundle name %{public}s, uid %{public}d, notification id %{public}d, label %{public}s.",
        filter.bundle.GetBundleName().c_str(), filter.bundle.GetUid(), filter.notificationKey.id,
        filter.notificationKey.label.c_str());

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(filter.bundle));
    return proxy->GetActiveNotificationByFilter(bo, filter.notificationKey.id, filter.notificationKey.label,
        filter.extraInfoKeys, request);
}

ErrCode AnsNotification::IsAllowedNotify(const NotificationBundleOption &bundleOption, bool &allowed)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundle is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->IsSpecialBundleAllowedNotify(bo, allowed);
}

ErrCode AnsNotification::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationsEnabledForAllBundles(deviceId, enabled);
}

ErrCode AnsNotification::SetNotificationsEnabledForDefaultBundle(const std::string &deviceId, bool enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationsEnabledForBundle(deviceId, enabled);
}

ErrCode AnsNotification::SetNotificationsEnabledForSpecifiedBundle(
    const NotificationBundleOption &bundleOption, const std::string &deviceId, bool enabled)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->SetNotificationsEnabledForSpecialBundle(deviceId, bo, enabled);
}

ErrCode AnsNotification::SetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalidated bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->SetShowBadgeEnabledForBundle(bo, enabled);
}

ErrCode AnsNotification::GetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->GetShowBadgeEnabledForBundle(bo, enabled);
}

ErrCode AnsNotification::GetShowBadgeEnabled(bool &enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetShowBadgeEnabled(enabled);
}

ErrCode AnsNotification::CancelGroup(const std::string &groupName)
{
    ANS_LOGI("enter CancelGroup,groupName:%{public}s", groupName.c_str());
    if (groupName.empty()) {
        ANS_LOGE("Invalid group name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    return proxy->CancelGroup(groupName, instanceKey);
}

ErrCode AnsNotification::RemoveGroupByBundle(
    const NotificationBundleOption &bundleOption, const std::string &groupName)
{
    ANS_LOGI("enter RemoveGroupByBundle,bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty() || groupName.empty()) {
        ANS_LOGE("Invalid parameter.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->RemoveGroupByBundle(bo, groupName);
}

ErrCode AnsNotification::SetDoNotDisturbDate(const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    auto dndDatePtr = new (std::nothrow) NotificationDoNotDisturbDate(doNotDisturbDate);
    if (dndDatePtr == nullptr) {
        ANS_LOGE("Create notificationDoNotDisturbDate failed.");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationDoNotDisturbDate> dndDate(dndDatePtr);
    return proxy->SetDoNotDisturbDate(dndDate);
}

ErrCode AnsNotification::GetDoNotDisturbDate(NotificationDoNotDisturbDate &doNotDisturbDate)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationDoNotDisturbDate> dndDate = nullptr;
    auto ret = proxy->GetDoNotDisturbDate(dndDate);
    if (ret != ERR_OK) {
        ANS_LOGE("GetDoNotDisturbDate failed.");
        return ret;
    }

    if (!dndDate) {
        ANS_LOGE("Invalid DoNotDisturbDate.");
        return ERR_ANS_NO_MEMORY;
    }

    doNotDisturbDate = *dndDate;
    return ret;
}

ErrCode AnsNotification::AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddDoNotDisturbProfiles(profiles);
}

ErrCode AnsNotification::RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->RemoveDoNotDisturbProfiles(profiles);
}

ErrCode AnsNotification::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->DoesSupportDoNotDisturbMode(doesSupport);
}

ErrCode AnsNotification::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
}

ErrCode AnsNotification::PublishContinuousTaskNotification(const NotificationRequest &request)
{
    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the sequence numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    auto pReq = new (std::nothrow) NotificationRequest(request);
    if (pReq == nullptr) {
        ANS_LOGE("Failed to create NotificationRequest ptr.");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationRequest> sptrReq(pReq);
    if (IsNonDistributedNotificationType(sptrReq->GetNotificationType())) {
        sptrReq->SetDistributed(false);
    }
    return proxy->PublishContinuousTaskNotification(sptrReq);
}

ErrCode AnsNotification::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGI("enter CancelContinuousTaskNotification,notificationId:%{public}d", notificationId);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->CancelContinuousTaskNotification(label, notificationId);
}

ErrCode AnsNotification::IsDistributedEnabled(bool &enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsDistributedEnabled(enabled);
}

ErrCode AnsNotification::EnableDistributed(const bool enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->EnableDistributed(enabled);
}

ErrCode AnsNotification::EnableDistributedByBundle(const NotificationBundleOption &bundleOption, const bool enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->EnableDistributedByBundle(bo, enabled);
}

ErrCode AnsNotification::EnableDistributedSelf(const bool enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->EnableDistributedSelf(enabled);
}

ErrCode AnsNotification::IsDistributedEnableByBundle(const NotificationBundleOption &bundleOption, bool &enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->IsDistributedEnableByBundle(bo, enabled);
}

ErrCode AnsNotification::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetDeviceRemindType(remindType);
}

void AnsNotification::ResetAnsManagerProxy()
{}

void AnsNotification::Reconnect()
{
    ANS_LOGD("enter");
    for (int32_t i = 0; i < MAX_RETRY_TIME; i++) {
        // try to connect ans
        sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
        if (!proxy) {
            // Sleep 1000 milliseconds before reconnect.
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
            ANS_LOGE("get ans proxy fail, try again.");
            continue;
        }
        ANS_LOGD("get ans proxy success.");
        return;
    }
}

ErrCode AnsNotification::PublishReminder(ReminderRequest &reminder)
{
    sptr<ReminderRequest> tarReminder = nullptr;
    switch (reminder.GetReminderType()) {
        case (ReminderRequest::ReminderType::TIMER): {
            ANSR_LOGI("Publish timer");
            ReminderRequestTimer &timer = (ReminderRequestTimer &)reminder;
            tarReminder = new (std::nothrow) ReminderRequestTimer(timer);
            break;
        }
        case (ReminderRequest::ReminderType::ALARM): {
            ANSR_LOGI("Publish alarm");
            ReminderRequestAlarm &alarm = (ReminderRequestAlarm &)reminder;
            tarReminder = new (std::nothrow) ReminderRequestAlarm(alarm);
            break;
        }
        case (ReminderRequest::ReminderType::CALENDAR): {
            ANSR_LOGI("Publish calendar");
            ReminderRequestCalendar &calendar = (ReminderRequestCalendar &)reminder;
            tarReminder = new (std::nothrow) ReminderRequestCalendar(calendar);
            break;
        }
        default: {
            ANSR_LOGW("PublishReminder fail.");
            return ERR_ANS_INVALID_PARAM;
        }
    }
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    ErrCode code = proxy->PublishReminder(tarReminder);
    reminder.SetReminderId(tarReminder->GetReminderId());
    return code;
}

ErrCode AnsNotification::CancelReminder(const int32_t reminderId)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelReminder(reminderId);
}

ErrCode AnsNotification::CancelAllReminders()
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->CancelAllReminders();
}

ErrCode AnsNotification::GetValidReminders(std::vector<sptr<ReminderRequest>> &validReminders)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetValidReminders(validReminders);
}

ErrCode AnsNotification::AddExcludeDate(const int32_t reminderId, const uint64_t date)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->AddExcludeDate(reminderId, date);
}

ErrCode AnsNotification::DelExcludeDates(const int32_t reminderId)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->DelExcludeDates(reminderId);
}

ErrCode AnsNotification::GetExcludeDates(const int32_t reminderId, std::vector<uint64_t>& dates)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetExcludeDates(reminderId, dates);
}

sptr<AnsManagerInterface> AnsNotification::GetAnsManagerProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ANS_LOGE("Failed to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID);
    if (!remoteObject) {
        ANS_LOGE("Failed to get notification Manager.");
        return nullptr;
    }

    sptr<AnsManagerInterface> proxy = iface_cast<AnsManagerInterface>(remoteObject);
    if ((!proxy) || (!proxy->AsObject())) {
        ANS_LOGE("Failed to get notification Manager's proxy");
        return nullptr;
    }
    return proxy;
}

bool AnsNotification::CanPublishMediaContent(const NotificationRequest &request) const
{
    if (NotificationContent::Type::MEDIA != request.GetNotificationType()) {
        return true;
    }

    if (request.GetContent() == nullptr) {
        ANS_LOGE("Failed to publish notification with null content.");
        return false;
    }

    auto media = std::static_pointer_cast<NotificationMediaContent>(request.GetContent()->GetNotificationContent());
    if (media == nullptr) {
        ANS_LOGE("Failed to get media content.");
        return false;
    }

    auto showActions = media->GetShownActions();
    size_t size = request.GetActionButtons().size();
    for (auto it = showActions.begin(); it != showActions.end(); ++it) {
        if (*it > size) {
            ANS_LOGE("The sequence numbers actions is: %{public}d, the assigned to added action buttons size is: "
                     "%{public}zu.", *it, size);
            return false;
        }
    }

    return true;
}

bool AnsNotification::CanPublishLiveViewContent(const NotificationRequest &request) const
{
    if (!request.IsCommonLiveView()) {
        return true;
    }

    if (request.GetContent() == nullptr) {
        ANS_LOGE("Failed to publish notification with null content.");
        return false;
    }

    auto content = request.GetContent()->GetNotificationContent();
    auto liveView = std::static_pointer_cast<NotificationLiveViewContent>(content);
    if (liveView == nullptr) {
        ANS_LOGE("Failed to get live view content.");
        return false;
    }

    auto status = liveView->GetLiveViewStatus();
    if (status >= NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT) {
        ANS_LOGE("Invalid status %{public}u.", status);
        return false;
    }

    return true;
}

ErrCode AnsNotification::CheckImageSize(const NotificationRequest &request)
{
    auto littleIcon = request.GetLittleIcon();
    if (NotificationRequest::CheckImageOverSizeForPixelMap(littleIcon, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of little icon exceeds limit");
        return ERR_ANS_ICON_OVER_SIZE;
    }

    auto overlayIcon = request.GetOverlayIcon();
    if (overlayIcon && NotificationRequest::CheckImageOverSizeForPixelMap(overlayIcon, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of overlay icon exceeds limit");
        return ERR_ANS_ICON_OVER_SIZE;
    }

    ErrCode err = request.CheckImageSizeForContent();
    if (err != ERR_OK) {
        return err;
    }

    auto buttons = request.GetActionButtons();
    for (auto &btn : buttons) {
        if (!btn) {
            continue;
        }
        auto icon = btn->GetIcon();
        if (NotificationRequest::CheckImageOverSizeForPixelMap(icon, MAX_ICON_SIZE)) {
            ANS_LOGE("The size of icon in ActionButton exceeds limit");
            return ERR_ANS_ICON_OVER_SIZE;
        }
    }

    auto users = request.GetMessageUsers();
    for (auto &user : users) {
        if (!user) {
            continue;
        }
        auto icon = user->GetPixelMap();
        if (NotificationRequest::CheckImageOverSizeForPixelMap(icon, MAX_ICON_SIZE)) {
            ANS_LOGE("The size of picture in MessageUser exceeds limit");
            return ERR_ANS_ICON_OVER_SIZE;
        }
    }

    auto bigIcon = request.GetBigIcon();
    if (NotificationRequest::CheckImageOverSizeForPixelMap(bigIcon, MAX_ICON_SIZE)) {
        request.ResetBigIcon();
        ANS_LOGI("The size of big icon exceeds limit");
    }

    return ERR_OK;
}

ErrCode AnsNotification::IsSupportTemplate(const std::string &templateName, bool &support)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsSupportTemplate(templateName, support);
}

bool AnsNotification::IsNonDistributedNotificationType(const NotificationContent::Type &type)
{
    return ((type == NotificationContent::Type::CONVERSATION) ||
        (type == NotificationContent::Type::PICTURE) ||
        (type == NotificationContent::Type::LIVE_VIEW));
}

ErrCode AnsNotification::IsAllowedNotify(const int32_t &userId, bool &allowed)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsSpecialUserAllowedNotify(userId, allowed);
}

ErrCode AnsNotification::SetNotificationsEnabledForAllBundles(const int32_t &userId, bool enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetNotificationsEnabledByUser(userId, enabled);
}

ErrCode AnsNotification::RemoveNotifications(const int32_t &userId)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->DeleteAllByUser(userId);
}

ErrCode AnsNotification::SetDoNotDisturbDate(const int32_t &userId,
    const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    auto dndDatePtr = new (std::nothrow) NotificationDoNotDisturbDate(doNotDisturbDate);
    if (dndDatePtr == nullptr) {
        ANS_LOGE("create DoNotDisturbDate failed.");
        return ERR_ANS_NO_MEMORY;
    }

    sptr<NotificationDoNotDisturbDate> dndDate(dndDatePtr);
    return proxy->SetDoNotDisturbDate(dndDate);
}

ErrCode AnsNotification::GetDoNotDisturbDate(const int32_t &userId, NotificationDoNotDisturbDate &doNotDisturbDate)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationDoNotDisturbDate> dndDate = nullptr;
    auto ret = proxy->GetDoNotDisturbDate(dndDate);
    if (ret != ERR_OK) {
        ANS_LOGE("Get DoNotDisturbDate failed.");
        return ret;
    }

    if (!dndDate) {
        ANS_LOGE("Invalid DoNotDisturbDate.");
        return ERR_ANS_NO_MEMORY;
    }

    doNotDisturbDate = *dndDate;
    return ret;
}

ErrCode AnsNotification::SetEnabledForBundleSlot(const NotificationBundleOption &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetEnabledForBundleSlot fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->SetEnabledForBundleSlot(bo, slotType, enabled, isForceControl);
}

ErrCode AnsNotification::GetEnabledForBundleSlot(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetEnabledForBundleSlot fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->GetEnabledForBundleSlot(bo, slotType, enabled);
}

ErrCode AnsNotification::GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetEnabledForBundleSlotSelf fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetEnabledForBundleSlotSelf(slotType, enabled);
}

ErrCode AnsNotification::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->ShellDump(cmd, bundle, userId, recvUserId, dumpInfo);
}

ErrCode AnsNotification::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetSyncNotificationEnabledWithoutApp(userId, enabled);
}

ErrCode AnsNotification::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->GetSyncNotificationEnabledWithoutApp(userId, enabled);
}

ErrCode AnsNotification::SetBadgeNumber(int32_t badgeNumber)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetBadgeNumber fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    int32_t instanceKey = DEFAULT_INSTANCE_KEY;
    return proxy->SetBadgeNumber(badgeNumber, instanceKey);
}

ErrCode AnsNotification::SetBadgeNumberByBundle(const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Unable to connect to ANS service.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleInfo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundleInfo == nullptr) {
        ANS_LOGE("Unable to create new bundle info.");
        return ERR_ANS_NO_MEMORY;
    }
    return proxy->SetBadgeNumberByBundle(bundleInfo, badgeNumber);
}

ErrCode AnsNotification::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetAllNotificationEnabledBundles(bundleOption);
}

ErrCode AnsNotification::RegisterPushCallback(
    const sptr<IRemoteObject>& pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->RegisterPushCallback(pushCallback, notificationCheckRequest);
}

ErrCode AnsNotification::UnregisterPushCallback()
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->UnregisterPushCallback();
}

ErrCode AnsNotification::SetAdditionConfig(const std::string &key, const std::string &value)
{
    if (key.empty()) {
        ANS_LOGE("Set package config fail: key is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetAdditionConfig(key, value);
}

ErrCode AnsNotification::SetDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("enter");
    if (bundleOption.GetBundleName().empty() || deviceType.empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetDistributedEnabledByBundleCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->SetDistributedEnabledByBundle(bo, deviceType, enabled);
}

ErrCode AnsNotification::IsDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("enter");
    if (bundleOption.GetBundleName().empty() || deviceType.empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("IsDistributedEnabledByBundleCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->IsDistributedEnabledByBundle(bo, deviceType, enabled);
}

ErrCode AnsNotification::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetSmartReminderEnabled(deviceType, enabled);
}

ErrCode AnsNotification::CancelAsBundleWithAgent(const NotificationBundleOption &bundleOption, const int32_t id)
{
    ANS_LOGI("enter CancelAsBundleWithAgent,bundleName:%{public}s,id:%{public}d",
        bundleOption.GetBundleName().c_str(), id);
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundle(new (std::nothrow) NotificationBundleOption(bundleOption));
    return proxy->CancelAsBundleWithAgent(bundle, id);
}

ErrCode AnsNotification::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->IsSmartReminderEnabled(deviceType, enabled);
}

ErrCode AnsNotification::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    return proxy->SetTargetDeviceStatus(deviceType, status);
}


bool AnsNotification::IsValidTemplate(const NotificationRequest &request) const
{
    if (request.GetTemplate() == nullptr) {
        return true;
    }

    std::string name = request.GetTemplate()->GetTemplateName();
    if (strcmp(name.c_str(), DOWNLOAD_TEMPLATE_NAME.c_str()) == 0) {
        std::shared_ptr<AAFwk::WantParams> data = request.GetTemplate()->GetTemplateData();
        if (data ==nullptr || !data->HasParam(DOWNLOAD_FILENAME) || !data->HasParam(DOWNLOAD_TITLE)) {
            ANS_LOGE("No required parameters.");
            return false;
        }
    }

    return true;
}

bool AnsNotification::IsValidDelayTime(const NotificationRequest &request)  const
{
    return request.GetPublishDelayTime() <= MAX_PUBLISH_DELAY_TIME;
}

ErrCode AnsNotification::GetDoNotDisturbProfile(int32_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->GetDoNotDisturbProfile(id, profile);
}

void AnsNotification::CreateSubscribeListener(const std::shared_ptr<NotificationSubscriber> &subscriber,
    sptr<SubscriberListener> &listener)
{
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    auto item = subscribers_.find(subscriber);
    if (item != subscribers_.end()) {
        listener = item->second;
        ANS_LOGD("subscriber has listener");
        return;
    }
    listener = new (std::nothrow) SubscriberListener(subscriber);
    if (listener != nullptr) {
        subscribers_[subscriber] = listener;
        ANS_LOGD("CreateSubscribeListener success");
    }
}

void AnsNotification::OnServiceDied()
{
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    for (auto item : subscribers_) {
        item.first->OnDied();
    }
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
ErrCode AnsNotification::RegisterSwingCallback(const std::function<void(bool, int)> swingCbFunc)
{
    ANS_LOGD("enter");
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterSwingCallback fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    swingCallBackStub_ = new(std::nothrow) SwingCallBackStub(swingCbFunc);
    if (swingCallBackStub_ == nullptr) {
        ANS_LOGE("RegisterSwingCallback swingCallBackStub_ == null");
        return ERR_ANS_INVALID_PARAM;
    }
    return proxy->RegisterSwingCallback(swingCallBackStub_->AsObject());
}
#endif

ErrCode AnsNotification::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UpdateNotificationTimerByUid fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->UpdateNotificationTimerByUid(uid, isPaused);
}

ErrCode AnsNotification::SetHashCodeRule(
    const uint32_t type)
{
    ANS_LOGI("SetHashCodeRule type = %{public}d", type);
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);

    sptr<AnsManagerInterface> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    return proxy->SetHashCodeRule(type);
}
}  // namespace Notification
}  // namespace OHOS
