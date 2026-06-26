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

#include "ans_notification.h"
#include "ans_const_define.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_manager_death_recipient.h"
#include "ans_manager_proxy.h"
#include "ans_result_data_synchronizer.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "notification_button_option.h"
#include "notification_reminder_info.h"
#include "notification_local_live_view_subscriber.h"
#include "system_ability_definition.h"
#include "unique_fd.h"
#include "hitrace_util.h"

#include <memory>
#include <thread>

namespace OHOS {
namespace Notification {
namespace {
const int32_t MAX_RETRY_TIME = 30;
const int32_t SLEEP_TIME = 1000;
const uint32_t MAX_PUBLISH_DELAY_TIME = 5;
const std::string DOWNLOAD_TITLE = "title";
const std::string DOWNLOAD_FILENAME = "fileName";
const static int MAX_SLOT_FLAGS = 0b111111;
}

InnerErrorCode AnsNotification::AddNotificationSlot(const NotificationSlot &slot)
{
    std::vector<NotificationSlot> slots;
    slots.push_back(slot);
    return AddNotificationSlots(slots);
}

InnerErrorCode AnsNotification::AddSlotByType(const NotificationConstant::SlotType &slotType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->AddSlotByType(slotType));
}

InnerErrorCode AnsNotification::AddNotificationSlots(const std::vector<NotificationSlot> &slots)
{
    if (slots.size() == 0) {
        ANS_LOGE("Failed to add notification slots because input slots size is 0.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationSlot>> slotsSptr;
    for (auto it = slots.begin(); it != slots.end(); ++it) {
        sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(*it);
        if (slot == nullptr) {
            ANS_LOGE("null slot");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        slotsSptr.emplace_back(slot);
    }

    size_t slotsSize = slotsSptr.size();
    if (slotsSize > MAX_SLOT_NUM) {
        ANS_LOGE("slotsSize over max size");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    return static_cast<InnerErrorCode>(proxy->AddSlots(slotsSptr));
}

InnerErrorCode AnsNotification::RemoveNotificationSlot(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGI("remove slotType:%{public}d", slotType);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveSlotByType(slotType));
}

InnerErrorCode AnsNotification::RemoveAllSlots()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveAllSlots());
}

InnerErrorCode AnsNotification::GetNotificationSlot(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetSlotByType(slotType, slot));
}

InnerErrorCode AnsNotification::GetNotificationSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetSlots(slots));
}

InnerErrorCode AnsNotification::GetNotificationSlotNumAsBundle(
    const NotificationBundleOption &bundleOption, uint64_t &num)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetSlotNumAsBundle(bo, num));
}

InnerErrorCode AnsNotification::GetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t &slotFlags)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetSlotFlagsAsBundle(bo, slotFlags));
}

InnerErrorCode AnsNotification::GetNotificationSettings(uint32_t &slotFlags)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetNotificationSettings(slotFlags));
}

InnerErrorCode AnsNotification::SetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption,
    uint32_t slotFlags)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    ANS_LOGI("set slotFlags bundleName:%{public}s, %{public}d", bundleOption.GetBundleName().c_str(), (int)slotFlags);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));

    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (slotFlags > MAX_SLOT_FLAGS) {
        ANS_LOGE("Invalid slotFlags");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    // got the LSB 6 bits as slotflags;
    uint32_t validSlotFlag = MAX_SLOT_FLAGS & slotFlags;

    return static_cast<InnerErrorCode>(proxy->SetSlotFlagsAsBundle(bo, validSlotFlag));
}

InnerErrorCode AnsNotification::PublishNotification(
    const NotificationRequest &request, const std::string &instanceKey)
{
    ANS_LOGD("called");
    return PublishNotification(std::string(), request, instanceKey);
}

InnerErrorCode AnsNotification::PublishNotification(const std::string &label, const NotificationRequest &request,
    const std::string &instanceKey)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGI("publish id:%{public}u label:%{public}s", request.GetNotificationId(), label.c_str());

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!IsValidTemplate(request) || !IsValidDelayTime(request)) {
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the series numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    InnerErrorCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    reqPtr->SetAppInstanceKey(instanceKey);
    if (reqPtr->IsCommonLiveView()) {
        return static_cast<InnerErrorCode>(proxy->PublishWithMaxCapacity(label, reqPtr));
    }
    return static_cast<InnerErrorCode>(proxy->Publish(label, reqPtr));
}

InnerErrorCode AnsNotification::PublishNotificationForIndirectProxy(const NotificationRequest &request)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    TraceChainUtil traceChain = TraceChainUtil();
    ANS_LOGI("publish indirectProxy id:%{public}u", request.GetNotificationId());

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!IsValidTemplate(request) || !IsValidDelayTime(request)) {
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the series numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    InnerErrorCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    if (reqPtr->IsCommonLiveView()) {
        return static_cast<InnerErrorCode>(proxy->PublishNotificationForIndirectProxyWithMaxCapacity(reqPtr));
    }
    return static_cast<InnerErrorCode>(proxy->PublishNotificationForIndirectProxy(reqPtr));
}

InnerErrorCode AnsNotification::CancelNotificationNoBlockIPC(int32_t notificationId, const std::string &instanceKey)
{
    return CancelNotificationNoBlockIPC("", notificationId, instanceKey);
}

InnerErrorCode AnsNotification::CancelNotificationNoBlockIPC(const std::string &label, int32_t notificationId,
    const std::string &instanceKey)
{
    ANS_LOGI("cancel id:%{public}d label:%{public}s", notificationId, label.c_str());
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->Cancel(notificationId, label, instanceKey, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::CancelNotification(int32_t notificationId, const std::string &instanceKey)
{
    return CancelNotification("", notificationId, instanceKey);
}

InnerErrorCode AnsNotification::CancelNotification(const std::string &label, int32_t notificationId,
    const std::string &instanceKey)
{
    ANS_LOGI("cancel id:%{public}d label:%{public}s", notificationId, label.c_str());
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->Cancel(notificationId, label, instanceKey));
}

InnerErrorCode AnsNotification::CancelAllNotificationsNoBlockIPC(const std::string &instanceKey)
{
    ANS_LOGI("cancel all");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->CancelAll(instanceKey, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::CancelAllNotifications(const std::string &instanceKey)
{
    ANS_LOGI("cancel all");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->CancelAll(instanceKey));
}

InnerErrorCode AnsNotification::CancelAsBundleNoBlockIPC(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGI("cancel id:%{public}d, %{public}s %{public}d", notificationId, representativeBundle.c_str(), userId);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(
        proxy->CancelAsBundle(notificationId, representativeBundle, userId, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGI("cancel id:%{public}d, %{public}s %{public}d", notificationId, representativeBundle.c_str(), userId);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->CancelAsBundle(notificationId, representativeBundle, userId));
}

InnerErrorCode AnsNotification::CancelAsBundleNoBlockIPC(
    const NotificationBundleOption &bundleOption, int32_t notificationId)
{
    ANS_LOGI("cancel id:%{public}d %{public}s", notificationId, bundleOption.GetBundleName().c_str());
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->CancelAsBundle(bo, notificationId, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::CancelAsBundle(
    const NotificationBundleOption &bundleOption, int32_t notificationId)
{
    ANS_LOGI("cancel id:%{public}d %{public}s", notificationId, bundleOption.GetBundleName().c_str());
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return static_cast<InnerErrorCode>(proxy->CancelAsBundle(bo, notificationId));
}

InnerErrorCode AnsNotification::GetActiveNotificationNums(uint64_t &num)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetActiveNotificationNums(num));
}

InnerErrorCode AnsNotification::GetActiveNotificationsNoBlockIPC(std::vector<sptr<NotificationRequest>> &request,
    const std::string &instanceKey)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetActiveNotifications(instanceKey, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    request = synchronizer->GetNotificationRequests();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::GetActiveNotifications(std::vector<sptr<NotificationRequest>> &request,
    const std::string &instanceKey)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetActiveNotifications(request, instanceKey));
}

InnerErrorCode AnsNotification::CanPublishNotificationAsBundle(
    const std::string &representativeBundle, bool &canPublish)
{
    if (representativeBundle.empty()) {
        ANS_LOGW("Input representativeBundle is empty");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->CanPublishAsBundle(representativeBundle, canPublish));
}

InnerErrorCode AnsNotification::PublishNotificationAsBundle(
    const std::string &representativeBundle, const NotificationRequest &request)
{
    ANS_LOGI("publish Bundle:%{public}s, id:%{public}u",
        representativeBundle.c_str(), request.GetNotificationId());
    if (representativeBundle.empty()) {
        ANS_LOGE("Refuse to publish the notification whit invalid representativeBundle");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without effective content");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the sequence numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    InnerErrorCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture overtake the limit");
        return checkErr;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> reqPtr = new (std::nothrow) NotificationRequest(request);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    if (IsNonDistributedNotificationType(reqPtr->GetNotificationType())) {
        reqPtr->SetDistributed(false);
    }
    if (reqPtr->IsCommonLiveView()) {
        return static_cast<InnerErrorCode>(proxy->PublishAsBundleWithMaxCapacity(reqPtr, representativeBundle));
    }
    return static_cast<InnerErrorCode>(proxy->PublishAsBundle(reqPtr, representativeBundle));
}

InnerErrorCode AnsNotification::SetNotificationBadgeNum()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    int32_t num = -1;
    return static_cast<InnerErrorCode>(proxy->SetNotificationBadgeNum(num));
}

InnerErrorCode AnsNotification::SetNotificationBadgeNum(int32_t num)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetNotificationBadgeNum(num));
}

InnerErrorCode AnsNotification::IsAllowedNotify(bool &allowed)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->IsAllowedNotify(allowed));
}

InnerErrorCode AnsNotification::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->IsAllowedNotifySelf(allowed));
}

InnerErrorCode AnsNotification::CanPopEnableNotificationDialog(sptr<AnsDialogHostClient> &hostClient,
    bool &canPop, std::string &bundleName)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->CanPopEnableNotificationDialog(hostClient, canPop, bundleName));
}

InnerErrorCode AnsNotification::RemoveEnableNotificationDialog()
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveEnableNotificationDialog());
}

InnerErrorCode AnsNotification::RequestEnableNotification(std::string &deviceId,
    sptr<AnsDialogHostClient> &hostClient,
    sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    if (hostClient == nullptr) {
        ANS_LOGE("null hostClient");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    if (callerToken == nullptr) {
        return static_cast<InnerErrorCode>(proxy->RequestEnableNotification(deviceId, hostClient));
    }
    return static_cast<InnerErrorCode>(proxy->RequestEnableNotification(deviceId, hostClient, callerToken));
}

InnerErrorCode AnsNotification::RequestEnableNotification(const std::string bundleName, const int32_t uid)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->RequestEnableNotification(bundleName, uid));
}

InnerErrorCode AnsNotification::HasNotificationPolicyAccessPermission(bool &hasPermission)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->HasNotificationPolicyAccessPermission(hasPermission));
}

InnerErrorCode AnsNotification::GetBundleImportance(NotificationSlot::NotificationLevel &importance)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    int32_t importanceTemp;
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetBundleImportance(importanceTemp));
    if ((NotificationSlot::LEVEL_NONE <= importanceTemp) && (importanceTemp <= NotificationSlot::LEVEL_HIGH)) {
        importance = static_cast<NotificationSlot::NotificationLevel>(importanceTemp);
    } else {
        importance = NotificationSlot::LEVEL_UNDEFINED;
    }
    return ret;
}

InnerErrorCode AnsNotification::SubscribeNotificationV26(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("null listener");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    if (subscribeInfo != nullptr && !subscribeInfo->GetDeviceType().empty()) {
        subscriber->SetDeviceType(subscribeInfo->GetDeviceType());
    }
    if (subscribeInfo != nullptr && subscribeInfo->GetPictureOption() != nullptr) {
        subscriber->SetPictureOption(subscribeInfo->GetPictureOption());
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();

    return static_cast<InnerErrorCode>(
        proxy->SubscribeNotification(listener, subscribeInfo, subscriber->GetSubscribedFlags()));
}

InnerErrorCode AnsNotification::SubscribeNotification(const NotificationSubscriber &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->Subscribe(subscriberSptr, subscriber.GetSubscribedFlags()));
}

InnerErrorCode AnsNotification::SubscribeNotificationSelf(const NotificationSubscriber &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SubscribeSelf(subscriberSptr, subscriber.GetSubscribedFlags()));
}

InnerErrorCode AnsNotification::SubscribeLocalLiveViewNotification(
    const NotificationLocalLiveViewSubscriber &subscriber, const bool isNative)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationLocalLiveViewSubscriber::SubscriberLocalLiveViewImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SubscribeLocalLiveView(subscriberSptr, isNative));
}

InnerErrorCode AnsNotification::SubscribeNotification(
    const NotificationSubscriber &subscriber, const NotificationSubscribeInfo &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo(subscribeInfo);
    if (sptrInfo == nullptr) {
        ANS_LOGE("null sptrInfo");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    if (!subscribeInfo.GetDeviceType().empty()) {
        subscriberSptr->subscriber_.SetDeviceType(subscribeInfo.GetDeviceType());
    }
    if (subscribeInfo.GetPictureOption() != nullptr) {
        subscriberSptr->subscriber_.SetPictureOption(subscribeInfo.GetPictureOption());
    }
    return static_cast<InnerErrorCode>(proxy->Subscribe(subscriberSptr, sptrInfo, subscriber.GetSubscribedFlags()));
}

InnerErrorCode AnsNotification::UnSubscribeNotification(NotificationSubscriber &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->Unsubscribe(subscriberSptr));
}

InnerErrorCode AnsNotification::UnSubscribeNotification(
    NotificationSubscriber &subscriber, NotificationSubscribeInfo subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo(subscribeInfo);
    if (sptrInfo == nullptr) {
        ANS_LOGE("null sptrInfo");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    sptr<NotificationSubscriber::SubscriberImpl> subscriberSptr = subscriber.GetImpl();
    if (subscriberSptr == nullptr) {
        ANS_LOGE("null subscriberSptr");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->Unsubscribe(subscriberSptr, sptrInfo));
}

InnerErrorCode AnsNotification::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    return SubscribeNotification(subscriber, nullptr);
}

InnerErrorCode AnsNotification::SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("null listener");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();
    return static_cast<InnerErrorCode>(proxy->SubscribeSelf(listener, subscriber->GetSubscribedFlags()));
}

InnerErrorCode AnsNotification::SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Failed to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<SubscriberListener> listener = nullptr;
    CreateSubscribeListener(subscriber, listener);
    if (listener == nullptr) {
        ANS_LOGE("null listener");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    if (subscribeInfo != nullptr && !subscribeInfo->GetDeviceType().empty()) {
        subscriber->SetDeviceType(subscribeInfo->GetDeviceType());
    }
    if (subscribeInfo != nullptr && subscribeInfo->GetPictureOption() != nullptr) {
        subscriber->SetPictureOption(subscribeInfo->GetPictureOption());
    }
    DelayedSingleton<AnsManagerDeathRecipient>::GetInstance()->SubscribeSAManager();

    if (subscribeInfo == nullptr) {
        return static_cast<InnerErrorCode>(proxy->Subscribe(listener, subscriber->GetSubscribedFlags()));
    }
    return static_cast<InnerErrorCode>(proxy->Subscribe(listener, subscribeInfo, subscriber->GetSubscribedFlags()));
}

InnerErrorCode AnsNotification::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    return UnSubscribeNotification(subscriber, nullptr);
}

InnerErrorCode AnsNotification::UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
    const sptr<NotificationSubscribeInfo> &subscribeInfo)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    std::lock_guard<std::mutex> lock(subscriberMutex_);
    auto item = subscribers_.find(subscriber);
    if (item != subscribers_.end()) {
        sptr<SubscriberListener> listener = item->second;
        InnerErrorCode ret = ERR_ANS_INNER_INVALID_PARAM;
        if (subscribeInfo == nullptr) {
            ret = static_cast<InnerErrorCode>(proxy->Unsubscribe(listener));
        } else {
            ret = static_cast<InnerErrorCode>(proxy->Unsubscribe(listener, subscribeInfo));
        }
        if (ret == ERR_OK) {
            subscribers_.erase(item);
        }
        return ret;
    }
    ANS_LOGE("Failed to unsubscribe due to subscriber not found.");
    return ERR_ANS_INNER_INVALID_PARAM;
}

InnerErrorCode AnsNotification::TriggerLocalLiveView(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const NotificationButtonOption &buttonOption)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    if (buttonOption.GetButtonName().empty()) {
        ANS_LOGE("Invalid button name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    ANS_LOGI("trigger liveview id:%{public}u,bundleName:%{public}s,button:%{public}s",
        notificationId, bundleOption.GetBundleName().c_str(), buttonOption.GetButtonName().c_str());

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    sptr<NotificationButtonOption> button(new (std::nothrow) NotificationButtonOption(buttonOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->TriggerLocalLiveView(bo, notificationId, button));
}

InnerErrorCode AnsNotification::RemoveNotification(const std::string &key, int32_t removeReason)
{
    ANS_LOGI("remove key:%{public}s,reason:%{public}d", key.c_str(), removeReason);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (key.empty()) {
        ANS_LOGW("Input key is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->Delete(key, removeReason));
}

InnerErrorCode AnsNotification::RemoveNotification(const NotificationBundleOption &bundleOption,
    const int32_t notificationId, const std::string &label, int32_t removeReason)
{
    ANS_LOGI("remove id:%{public}d,bundle:%{public}s,reason:%{public}d label:%{public}s",
        notificationId, bundleOption.GetBundleName().c_str(), removeReason, label.c_str());
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveNotification(bo, notificationId, label, removeReason));
}

InnerErrorCode AnsNotification::RemoveAllNotifications(const NotificationBundleOption &bundleOption)
{
    ANS_LOGI("remove all bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy defeat.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveAllNotifications(bo));
}

InnerErrorCode AnsNotification::RemoveNotifications(const std::vector<std::string> hashcodes, int32_t removeReason)
{
    ANS_LOGI("remove removeReason:%{public}d", removeReason);
    if (hashcodes.empty()) {
        ANS_LOGE("Hashcodes is empty");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->RemoveNotifications(hashcodes, removeReason));
}

InnerErrorCode AnsNotification::RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
    const NotificationConstant::SlotType& slotType,
    const NotificationConstant::DistributedDeleteType& deleteType,
    const int32_t removeReason, const std::string& deviceId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->RemoveDistributedNotifications(hashcodes, slotType, deleteType,
        removeReason, deviceId));
}

InnerErrorCode AnsNotification::RemoveNotificationsByBundle(const NotificationBundleOption &bundleOption)
{
    ANS_LOGI("remove bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Defeated to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->DeleteByBundle(bo));
}

InnerErrorCode AnsNotification::RemoveNotifications()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->DeleteAll());
}

InnerErrorCode AnsNotification::GetNotificationSlotsForBundle(
    const NotificationBundleOption &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundleName is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetSlotsByBundle(bo, slots));
}

InnerErrorCode AnsNotification::GetNotificationSlotForBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType,
    sptr<NotificationSlot> &slot)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundleName is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetSlotByBundle(bo, slotType, slot));
}

InnerErrorCode AnsNotification::UpdateNotificationSlots(
    const NotificationBundleOption &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy flop.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));

    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (slots.empty()) {
        ANS_LOGE("empty slots");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    size_t slotSize = slots.size();
    if (slotSize > MAX_SLOT_NUM) {
        ANS_LOGE("slotSize over max size");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    return static_cast<InnerErrorCode>(proxy->UpdateSlots(bo, slots));
}

InnerErrorCode AnsNotification::GetAllActiveNotificationsNoBlockIPC(std::vector<sptr<Notification>> &notification)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetAllActiveNotifications(synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    notification = synchronizer->GetNotifications();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::GetAllActiveNotifications(std::vector<sptr<Notification>> &notification)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllActiveNotifications(notification));
}

InnerErrorCode AnsNotification::GetAllActiveNotifications(
    const std::vector<std::string> key, std::vector<sptr<Notification>> &notification)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    if (key.empty()) {
        ANS_LOGE("empty key");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetSpecialActiveNotifications(key, notification));
}

InnerErrorCode AnsNotification::GetActiveNotificationByFilter(const LiveViewFilter &filter,
    sptr<NotificationRequest> &request)
{
    if (filter.bundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    ANS_LOGD("Bundle name %{public}s, uid %{public}d, notification id %{public}d, label %{public}s.",
        filter.bundle.GetBundleName().c_str(), filter.bundle.GetUid(), filter.notificationKey.id,
        filter.notificationKey.label.c_str());

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(filter.bundle));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetActiveNotificationByFilter(bo, filter.notificationKey.id,
        filter.notificationKey.label, filter.userId, filter.extraInfoKeys, request));
}

InnerErrorCode AnsNotification::GetNotificationParameters(
    int32_t notificationId, const std::string &label, sptr<NotificationParameters> &parameters)
{
    ANS_LOGD("called");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetNotificationParameters(notificationId, label, parameters));
}

InnerErrorCode AnsNotification::IsAllowedNotify(const NotificationBundleOption &bundleOption, bool &allowed)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Input bundle is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->IsSpecialBundleAllowedNotify(bo, allowed));
}

InnerErrorCode AnsNotification::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetNotificationsEnabledForAllBundles(deviceId, enabled));
}

InnerErrorCode AnsNotification::SetNotificationsEnabledForDefaultBundle(const std::string &deviceId, bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetNotificationsEnabledForBundle(deviceId, enabled));
}

InnerErrorCode AnsNotification::SetNotificationsEnabledForSpecifiedBundle(
    const NotificationBundleOption &bundleOption, const std::string &deviceId, bool enabled)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetNotificationsEnabledForSpecialBundle(deviceId, bo, enabled, true));
}

InnerErrorCode AnsNotification::SetShowBadgeEnabledForBundle(
    const NotificationBundleOption &bundleOption, bool enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalidated bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetShowBadgeEnabledForBundle(bo, enabled));
}

InnerErrorCode AnsNotification::SetShowBadgeEnabledForBundles(
    const std::vector<std::pair<NotificationBundleOption, bool>> &bundleOptions)
{
    if (bundleOptions.empty()) {
        ANS_LOGE("The bundleOptions list is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::map<sptr<NotificationBundleOption>, bool> sptrBundleOptions;
    for (const auto &option : bundleOptions) {
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(option.first);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        sptrBundleOptions[bo] = option.second;
    }
    return static_cast<InnerErrorCode>(proxy->SetShowBadgeEnabledForBundles(sptrBundleOptions));
}

InnerErrorCode AnsNotification::GetShowBadgeEnabledForBundleNoBlockIPC(const NotificationBundleOption &bundleOption,
    bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetShowBadgeEnabledForBundle(bo, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    enabled = synchronizer->GetEnabled();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::GetShowBadgeEnabledForBundle(
    const NotificationBundleOption &bundleOption, bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetShowBadgeEnabledForBundle(bo, enabled));
}

InnerErrorCode AnsNotification::GetShowBadgeEnabledForBundles(
    const std::vector<NotificationBundleOption> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, bool> &bundleEnable)
{
    if (bundleOptions.empty()) {
        ANS_LOGE("Invalid bundle options.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> sptrBundleOptions;
    sptrBundleOptions.reserve(bundleOptions.size());
    for (const auto &option : bundleOptions) {
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(option);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        sptrBundleOptions.emplace_back(std::move(bo));
    }
    return static_cast<InnerErrorCode>(proxy->GetShowBadgeEnabledForBundles(sptrBundleOptions, bundleEnable));
}

InnerErrorCode AnsNotification::GetShowBadgeEnabledNoBlockIPC(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetShowBadgeEnabled(synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    enabled = synchronizer->GetEnabled();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::GetShowBadgeEnabled(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetShowBadgeEnabled(enabled));
}

InnerErrorCode AnsNotification::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    ANS_LOGI("cancel groupName:%{public}s", groupName.c_str());
    if (groupName.empty()) {
        ANS_LOGE("Invalid group name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->CancelGroup(groupName, instanceKey));
}

InnerErrorCode AnsNotification::RemoveGroupByBundle(
    const NotificationBundleOption &bundleOption, const std::string &groupName)
{
    ANS_LOGI("remove group bundleName:%{public}s", bundleOption.GetBundleName().c_str());
    if (bundleOption.GetBundleName().empty() || groupName.empty()) {
        ANS_LOGE("Invalid parameter.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    return static_cast<InnerErrorCode>(proxy->RemoveGroupByBundle(bo, groupName));
}

InnerErrorCode AnsNotification::SetDoNotDisturbDate(const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    auto dndDatePtr = new (std::nothrow) NotificationDoNotDisturbDate(doNotDisturbDate);
    if (dndDatePtr == nullptr) {
        ANS_LOGE("null dndDatePtr");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    sptr<NotificationDoNotDisturbDate> dndDate(dndDatePtr);
    if (dndDate == nullptr) {
        ANS_LOGE("null dndDate");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetDoNotDisturbDate(dndDate));
}

InnerErrorCode AnsNotification::GetDoNotDisturbDate(NotificationDoNotDisturbDate &doNotDisturbDate)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationDoNotDisturbDate> dndDate = nullptr;
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetDoNotDisturbDate(dndDate));
    if (ret != ERR_OK) {
        ANS_LOGE("GetDoNotDisturbDate failed.");
        return ret;
    }

    if (!dndDate) {
        ANS_LOGE("Invalid DoNotDisturbDate.");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    doNotDisturbDate = *dndDate;
    return ret;
}

InnerErrorCode AnsNotification::AddDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->AddDoNotDisturbProfiles(profiles));
}

InnerErrorCode AnsNotification::AddDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->AddDoNotDisturbProfiles(profiles, userId));
}

InnerErrorCode AnsNotification::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveDoNotDisturbProfiles(profiles));
}

InnerErrorCode AnsNotification::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles, const int32_t userId)
{
    if (profiles.empty()) {
        ANS_LOGW("The profiles is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGW("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    if (profiles.size() > MAX_STATUS_VECTOR_NUM) {
        ANS_LOGE("The profiles is exceeds limit.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->RemoveDoNotDisturbProfiles(profiles, userId));
}

InnerErrorCode AnsNotification::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->DoesSupportDoNotDisturbMode(doesSupport));
}

InnerErrorCode AnsNotification::IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType));
}

InnerErrorCode AnsNotification::IsNeedSilentInDoNotDisturbMode(
    const std::string &phoneNumber, int32_t callerType, const int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType, userId));
}

InnerErrorCode AnsNotification::PublishContinuousTaskNotification(const NotificationRequest &request)
{
    if (request.GetContent() == nullptr || request.GetNotificationType() == NotificationContent::Type::NONE) {
        ANS_LOGE("Refuse to publish the notification without valid content");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (!CanPublishMediaContent(request)) {
        ANS_LOGE("Refuse to publish the notification because the sequence numbers actions not match those assigned to "
                 "added action buttons.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    InnerErrorCode checkErr = CheckImageSize(request);
    if (checkErr != ERR_OK) {
        ANS_LOGE("The size of one picture exceeds the limit");
        return checkErr;
    }

    if (!CanPublishLiveViewContent(request)) {
        ANS_LOGE("Refuse to publish the notification without valid live view content.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    auto pReq = new (std::nothrow) NotificationRequest(request);
    if (pReq == nullptr) {
        ANS_LOGE("null pReq");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    sptr<NotificationRequest> sptrReq(pReq);
    if (IsNonDistributedNotificationType(sptrReq->GetNotificationType())) {
        sptrReq->SetDistributed(false);
    }
    if (sptrReq == nullptr) {
        ANS_LOGE("null sptrReq");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->PublishContinuousTaskNotification(sptrReq));
}

InnerErrorCode AnsNotification::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGI("cancel ContinuousTas id:%{public}d", notificationId);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->CancelContinuousTaskNotification(label, notificationId));
}

InnerErrorCode AnsNotification::IsDistributedEnabled(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsDistributedEnabled(enabled));
}

InnerErrorCode AnsNotification::EnableDistributed(const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->EnableDistributed(enabled));
}

InnerErrorCode AnsNotification::EnableDistributedByBundle(
    const NotificationBundleOption &bundleOption, const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->EnableDistributedByBundle(bo, enabled));
}

InnerErrorCode AnsNotification::EnableDistributedSelf(const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->EnableDistributedSelf(enabled));
}

InnerErrorCode AnsNotification::IsDistributedEnableByBundle(
    const NotificationBundleOption &bundleOption, bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->IsDistributedEnableByBundle(bo, enabled));
}

InnerErrorCode AnsNotification::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    int32_t remindTypeTemp = -1;
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetDeviceRemindType(remindTypeTemp));
    remindType = static_cast<NotificationConstant::RemindType>(remindTypeTemp);
    return ret;
}

void AnsNotification::ResetAnsManagerProxy()
{}

void AnsNotification::Reconnect()
{
    ANS_LOGD("called");
    for (int32_t i = 0; i < MAX_RETRY_TIME; i++) {
        // try to connect ans
        sptr<IAnsManager> proxy = GetAnsManagerProxy();
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

sptr<IAnsManager> AnsNotification::GetAnsManagerProxy()
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

    sptr<IAnsManager> proxy = iface_cast<IAnsManager>(remoteObject);
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
        ANS_LOGE("null media");
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
        ANS_LOGE("null liveView");
        return false;
    }

    auto status = liveView->GetLiveViewStatus();
    if (status >= NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_BUTT) {
        ANS_LOGE("Invalid status %{public}u.", status);
        return false;
    }

    return true;
}

InnerErrorCode AnsNotification::CheckImageSize(const NotificationRequest &request)
{
    auto littleIcon = request.GetLittleIcon();
    bool collaborateFlag = request.GetDistributedCollaborate();
    if (!collaborateFlag && NotificationRequest::CheckImageOverSizeForPixelMap(littleIcon, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of little icon exceeds limit");
        return ERR_ANS_INNER_ICON_OVER_SIZE;
    }

    auto overlayIcon = request.GetOverlayIcon();
    if (overlayIcon && NotificationRequest::CheckImageOverSizeForPixelMap(overlayIcon, MAX_ICON_SIZE)) {
        ANS_LOGE("The size of overlay icon exceeds limit");
        return ERR_ANS_INNER_ICON_OVER_SIZE;
    }

    InnerErrorCode err = static_cast<InnerErrorCode>(request.CheckImageSizeForContent(collaborateFlag));
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
            return ERR_ANS_INNER_ICON_OVER_SIZE;
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
            return ERR_ANS_INNER_ICON_OVER_SIZE;
        }
    }

    auto bigIcon = request.GetBigIcon();
    if (NotificationRequest::CheckImageOverSizeForPixelMap(bigIcon, MAX_ICON_SIZE)) {
        request.ResetBigIcon();
        ANS_LOGW("The size of big icon exceeds limit");
    }

    return ERR_ANS_INNER_OK;
}

InnerErrorCode AnsNotification::IsSupportTemplate(const std::string &templateName, bool &support)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsSupportTemplate(templateName, support));
}

bool AnsNotification::IsNonDistributedNotificationType(const NotificationContent::Type &type)
{
    return ((type == NotificationContent::Type::CONVERSATION) ||
        (type == NotificationContent::Type::PICTURE) ||
        (type == NotificationContent::Type::LIVE_VIEW));
}

InnerErrorCode AnsNotification::IsAllowedNotify(const int32_t &userId, bool &allowed)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsSpecialUserAllowedNotify(userId, allowed));
}

InnerErrorCode AnsNotification::SetNotificationsEnabledForAllBundles(const int32_t &userId, bool enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetNotificationsEnabledByUser(userId, enabled));
}

InnerErrorCode AnsNotification::RemoveNotifications(const int32_t &userId)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->DeleteAllByUser(userId));
}

InnerErrorCode AnsNotification::SetDoNotDisturbDate(const int32_t &userId,
    const NotificationDoNotDisturbDate &doNotDisturbDate)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    auto dndDatePtr = new (std::nothrow) NotificationDoNotDisturbDate(doNotDisturbDate);
    if (dndDatePtr == nullptr) {
        ANS_LOGE("null dndDatePtr");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    sptr<NotificationDoNotDisturbDate> dndDate(dndDatePtr);
    if (dndDate == nullptr) {
        ANS_LOGE("null dndDate");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetDoNotDisturbDate(dndDate));
}

InnerErrorCode AnsNotification::GetDoNotDisturbDate(
    const int32_t &userId, NotificationDoNotDisturbDate &doNotDisturbDate)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationDoNotDisturbDate> dndDate = nullptr;
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->GetDoNotDisturbDate(dndDate));
    if (ret != ERR_OK) {
        ANS_LOGE("Get DoNotDisturbDate failed.");
        return ret;
    }

    if (!dndDate) {
        ANS_LOGE("Invalid DoNotDisturbDate.");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    doNotDisturbDate = *dndDate;
    return ret;
}

InnerErrorCode AnsNotification::SetEnabledForBundleSlot(const NotificationBundleOption &bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetEnabledForBundleSlot fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetEnabledForBundleSlot(bo, slotType, enabled, isForceControl));
}

InnerErrorCode AnsNotification::GetEnabledForBundleSlot(
    const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetEnabledForBundleSlot fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetEnabledForBundleSlot(bo, slotType, enabled));
}

InnerErrorCode AnsNotification::GetEnabledForBundleSlotSelf(
    const NotificationConstant::SlotType &slotType, bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetEnabledForBundleSlotSelf fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetEnabledForBundleSlotSelf(slotType, enabled));
}

InnerErrorCode AnsNotification::GetEnabledForBundleSlots(const std::vector<NotificationBundleOption> &bundleOptions,
    const NotificationConstant::SlotType &slotType,
    std::map<sptr<NotificationBundleOption>, bool> &slotEnabled)
{
    if (bundleOptions.empty()) {
        ANS_LOGE("Invalid bundle options.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> sptrBundleOptions;
    sptrBundleOptions.reserve(bundleOptions.size());
    for (const auto &option : bundleOptions) {
        if (option.GetBundleName().empty()) {
            ANS_LOGE("Invalid bundle name in batch.");
            return ERR_ANS_INNER_INVALID_PARAM;
        }
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(option);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        sptrBundleOptions.emplace_back(std::move(bo));
    }

    return static_cast<InnerErrorCode>(proxy->GetEnabledForBundleSlots(
        sptrBundleOptions, static_cast<int32_t>(slotType), slotEnabled));
}
#ifdef ANM_SUPPORT_DUMP
InnerErrorCode AnsNotification::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->ShellDump(cmd, bundle, userId, recvUserId, dumpInfo));
}
#endif

InnerErrorCode AnsNotification::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetSyncNotificationEnabledWithoutApp(userId, enabled));
}

InnerErrorCode AnsNotification::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetSyncNotificationEnabledWithoutApp(userId, enabled));
}

InnerErrorCode AnsNotification::SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetBadgeNumber fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetBadgeNumber(badgeNumber, instanceKey));
}

InnerErrorCode AnsNotification::SetBadgeNumberByBundle(
    const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Unable to connect to ANS service.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleInfo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundleInfo == nullptr) {
        ANS_LOGE("null bundleInfo");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->SetBadgeNumberByBundle(bundleInfo, badgeNumber));
}

InnerErrorCode AnsNotification::SetBadgeNumberForDhByBundle(
    const NotificationBundleOption &bundleOption, int32_t badgeNumber)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    ANS_LOGI("set badgeNumber bundle:%{public}s %{public}d %{public}d",
        bundleOption.GetBundleName().c_str(), bundleOption.GetUid(), badgeNumber);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Unable to connect to ANS service.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleInfo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundleInfo == nullptr) {
        ANS_LOGE("null bundleInfo");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->SetBadgeNumberForDhByBundle(bundleInfo, badgeNumber));
}

InnerErrorCode AnsNotification::GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllNotificationEnabledBundles(bundleOption));
}

InnerErrorCode AnsNotification::GetAllNotificationEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption, const int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllNotificationEnabledBundles(bundleOption, userId));
}

InnerErrorCode AnsNotification::RegisterPushCallback(
    const sptr<IRemoteObject>& pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->RegisterPushCallback(pushCallback, notificationCheckRequest));
}

InnerErrorCode AnsNotification::UnregisterPushCallback()
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->UnregisterPushCallback());
}

InnerErrorCode AnsNotification::SetAdditionConfig(const std::string &key, const std::string &value)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetAdditionConfig(key, value));
}

InnerErrorCode AnsNotification::UpdateInnerConfig(const std::string &configKey, const std::string &configValue)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->UpdateInnerConfig(configKey, configValue));
}

InnerErrorCode AnsNotification::SetBundlePriorityConfig(
    const NotificationBundleOption &bundleOption, const std::string &value)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->SetBundlePriorityConfig(bo, value));
}

InnerErrorCode AnsNotification::GetBundlePriorityConfig(
    const NotificationBundleOption &bundleOption, std::string &value)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->GetBundlePriorityConfig(bo, value));
}

InnerErrorCode AnsNotification::SetPriorityEnabled(const bool enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetPriorityEnabled(enabled));
}

InnerErrorCode AnsNotification::SetPriorityEnabledByBundle(
    const NotificationBundleOption &bundleOption, const NotificationConstant::PriorityEnableStatus enableStatus)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->SetPriorityEnabledByBundle(bo, static_cast<int32_t>(enableStatus)));
}

InnerErrorCode AnsNotification::IsPriorityEnabled(bool &enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsPriorityEnabled(enabled));
}

InnerErrorCode AnsNotification::IsPriorityEnabledByBundle(
    const NotificationBundleOption &bundleOption, NotificationConstant::PriorityEnableStatus &enableStatus)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    int32_t enableStatusInt = static_cast<int32_t>(NotificationConstant::PriorityEnableStatus::ENABLE_BY_INTELLIGENT);
    InnerErrorCode result = static_cast<InnerErrorCode>(proxy->IsPriorityEnabledByBundle(bo, enableStatusInt));
    enableStatus = static_cast<NotificationConstant::PriorityEnableStatus>(enableStatusInt);
    return result;
}

InnerErrorCode AnsNotification::GetPriorityEnabledByBundles(
    const std::vector<NotificationBundleOption> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, bool> &priorityEnable)
{
    if (bundleOptions.empty()) {
        ANS_LOGE("Invalid bundleOptions.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> sptrBundleOptions;
    sptrBundleOptions.reserve(bundleOptions.size());
    for (const auto &option : bundleOptions) {
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(option);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        sptrBundleOptions.emplace_back(std::move(bo));
    }
    return static_cast<InnerErrorCode>(proxy->GetPriorityEnabledByBundles(sptrBundleOptions, priorityEnable));
}

InnerErrorCode AnsNotification::SetPriorityEnabledByBundles(
    const std::map<sptr<NotificationBundleOption>, bool> &priorityEnable)
{
    if (priorityEnable.empty()) {
        ANS_LOGE("Invalid priorityEnable.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetPriorityEnabledByBundles(priorityEnable));
}

InnerErrorCode AnsNotification::IsPriorityIntelligentEnabled(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsPriorityIntelligentEnabled(enabled));
}

InnerErrorCode AnsNotification::SetPriorityIntelligentEnabled(const bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetPriorityIntelligentEnabled(enabled));
}

InnerErrorCode AnsNotification::GetPriorityStrategyByBundles(
    const std::vector<NotificationBundleOption> &bundleOptions,
    std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    if (bundleOptions.empty()) {
        ANS_LOGE("Invalid bundleOptions.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> sptrBundleOptions;
    for (const auto &option : bundleOptions) {
        sptr<NotificationBundleOption> bo = new (std::nothrow) NotificationBundleOption(option);
        if (bo == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        sptrBundleOptions.emplace_back(std::move(bo));
    }
    return static_cast<InnerErrorCode>(proxy->GetPriorityStrategyByBundles(sptrBundleOptions, strategies));
}

InnerErrorCode AnsNotification::SetPriorityStrategyByBundles(
    const std::map<sptr<NotificationBundleOption>, int64_t> &strategies)
{
    if (strategies.empty()) {
        ANS_LOGE("Invalid strategies.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetPriorityStrategyByBundles(strategies));
}

InnerErrorCode AnsNotification::TriggerUpdatePriorityType(const NotificationRequest &request)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationRequest> notificationRequest = new (std::nothrow) NotificationRequest(request);
    if (notificationRequest == nullptr) {
        ANS_LOGE("null notificationRequest");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->TriggerUpdatePriorityType(notificationRequest));
}

InnerErrorCode AnsNotification::TriggerUpdateAiExtNotification(
    const sptr<NotificationRequest> &request,
    const sptr<NotificationClassification> &notificationClassification)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->TriggerUpdateAiExtNotification(request, notificationClassification));
}

InnerErrorCode AnsNotification::SetDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, const bool enabled, const bool isNotification)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty() || deviceType.empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetDistributedEnabledByBundleCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetDistributedEnabledByBundle(bo, deviceType, enabled, isNotification));
}

InnerErrorCode AnsNotification::GetDistributedBundleListByType(const bool isNotification,
    std::vector<DistributedBundleOption> &enableList)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetDistributedBundleListByType fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetDistributedBundleListByType(isNotification, enableList));
}

InnerErrorCode AnsNotification::GetDistributedBundleInfo(const std::vector<NotificationBundleOption>& bundleOption,
    std::vector<DistributedNotificationBundleInfo>& bundleInfoList)
{
    ANS_LOGD("called");
    if (bundleOption.empty()) {
        ANS_LOGE("bundleOption is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetDistributedBundleInfo fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> bundlesSptr;
    bundlesSptr.reserve(bundleOption.size());
    for (const auto &it : bundleOption) {
        sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(it);
        if (bundle == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        bundlesSptr.emplace_back(std::move(bundle));
    }
    return static_cast<InnerErrorCode>(proxy->GetDistributedBundleInfo(bundlesSptr, bundleInfoList));
}

InnerErrorCode AnsNotification::SetDistributedBundleOption(
    const std::vector<DistributedBundleOption> &bundles, const std::string &deviceType)
{
    ANS_LOGD("called");
    if (bundles.empty()) {
        ANS_LOGE("Invalid bundles.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<DistributedBundleOption>> bundleOptions;
    for (auto bundle : bundles) {
        sptr<DistributedBundleOption> distributedBundleOption(new (std::nothrow) DistributedBundleOption(bundle));
        if (!distributedBundleOption) {
            ANS_LOGE("Memory allocation failed for DistributedBundleOption.");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        bundleOptions.emplace_back(distributedBundleOption);
    }
    return static_cast<InnerErrorCode>(proxy->SetDistributedBundleOption(bundleOptions, deviceType));
}

InnerErrorCode AnsNotification::SetDistributedEnabled(const std::string &deviceType, const bool &enabled)
{
    ANS_LOGD("called");
    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetDistributedEnabled(deviceType, enabled));
}

InnerErrorCode AnsNotification::IsDistributedEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsDistributedEnabled(deviceType, enabled));
}

InnerErrorCode AnsNotification::GetDistributedAbility(int32_t &abilityId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetDistributedAbility(abilityId));
}

InnerErrorCode AnsNotification::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
{
    ANS_LOGD("called");
    if (deviceType.empty() || deviceId.empty()) {
        ANS_LOGE("Invalid deviceType or deviceId.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetDistributedAuthStatus(deviceType, deviceId, userId, isAuth));
}

InnerErrorCode AnsNotification::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
{
    ANS_LOGD("called");
    if (deviceType.empty() || deviceId.empty()) {
        ANS_LOGE("Invalid deviceType or deviceId.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetDistributedAuthStatus(deviceType, deviceId, userId, isAuth));
}

InnerErrorCode AnsNotification::UpdateDistributedDeviceList(const std::string &deviceType)
{
    ANS_LOGD("called");
    if (deviceType.empty()) {
        ANS_LOGE("Invalid deviceType.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->UpdateDistributedDeviceList(deviceType));
}

InnerErrorCode AnsNotification::IsDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, bool isNotification, int32_t &enabled)
{
    ANS_LOGD("called");
    if (bundleOption.GetBundleName().empty() || deviceType.empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("IsDistributedEnabledByBundleCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->IsDistributedEnabledByBundle(bo, deviceType, isNotification, enabled));
}

InnerErrorCode AnsNotification::SetSilentReminderEnabled(const NotificationBundleOption &bundleOption,
    const bool enabled)
{
    ANS_LOGD("enter");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetSilentReminderEnabledCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("Fail: bundleOption is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetSilentReminderEnabled(bo, enabled));
}

InnerErrorCode AnsNotification::IsSilentReminderEnabled(const NotificationBundleOption &bundleOption,
    int32_t &enableStatus)
{
    ANS_LOGD("enter");
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("IsSilentReminderEnabledCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("Fail: bundleOption is empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->IsSilentReminderEnabled(bo, enableStatus));
}

InnerErrorCode AnsNotification::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetSmartReminderEnabled(deviceType, enabled));
}

InnerErrorCode AnsNotification::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetDistributedEnabledBySlot(slotType, deviceType, enabled));
}

InnerErrorCode AnsNotification::IsDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsDistributedEnabledBySlot(slotType, deviceType, enabled));
}

InnerErrorCode AnsNotification::CancelAsBundleWithAgentNoBlockIPC(const NotificationBundleOption &bundleOption,
    const int32_t id)
{
    ANS_LOGI("cancelWithAgent bundleName:%{public}s,id:%{public}d",
        bundleOption.GetBundleName().c_str(), id);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundle(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundle == nullptr) {
        ANS_LOGE("null bundle");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    if (synchronizer == nullptr) {
        ANS_LOGE("null synchronizer");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    InnerErrorCode ret = static_cast<InnerErrorCode>(proxy->CancelAsBundleWithAgent(bundle, id, synchronizer));
    // ERR_OK means the task is put into the ffrt queue at service layer.
    if (ret != ERR_OK) {
        return ret;
    }
    synchronizer->Wait();
    return static_cast<InnerErrorCode>(synchronizer->GetResultCode());
}

InnerErrorCode AnsNotification::CancelAsBundleWithAgent(
    const NotificationBundleOption &bundleOption, const int32_t id)
{
    ANS_LOGI("cancelWithAgent bundleName:%{public}s,id:%{public}d",
        bundleOption.GetBundleName().c_str(), id);
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundle(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundle == nullptr) {
        ANS_LOGE("null bundle");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->CancelAsBundleWithAgent(bundle, id));
}

InnerErrorCode AnsNotification::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsSmartReminderEnabled(deviceType, enabled));
}

InnerErrorCode AnsNotification::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const std::string deviceId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetTargetDeviceStatus(deviceType, status, deviceId));
}

InnerErrorCode AnsNotification::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const uint32_t controlFlag, const std::string deviceId, int32_t userId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId));
}

InnerErrorCode AnsNotification::SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    int operatorType, const std::vector<std::string>& bundleList, const std::vector<std::string>& labelList)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(
        proxy->SetTargetDeviceBundleList(deviceType, deviceId, operatorType, bundleList, labelList));
}

InnerErrorCode AnsNotification::SetDeviceDistributedBundleList(DistributedBundleChangeType type,
    const std::vector<NotificationDistributedBundle>& bundles)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetDeviceDistributedBundleList(static_cast<int32_t>(type), bundles));
}
InnerErrorCode AnsNotification::SetTargetDeviceAbility(const std::string& deviceType, const int32_t ability)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetTargetDeviceAbility(deviceType, ability));
}

InnerErrorCode AnsNotification::GetLocalDistributedBundleList(const std::string& deviceType,
    std::vector<NotificationDistributedBundle>& bundles)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetLocalDistributedBundleList(deviceType, bundles));
}

InnerErrorCode AnsNotification::GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
    std::string& deviceId, int32_t& userId)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetMutilDeviceStatus fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetMutilDeviceStatus(deviceType, status, deviceId, userId));
}

InnerErrorCode AnsNotification::GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
    std::vector<std::string>& bundleList, std::vector<std::string>& labelList)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetTargetDeviceBundleList(deviceType, deviceId, bundleList, labelList));
}

InnerErrorCode AnsNotification::SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
    bool notificaitonEnable, bool liveViewEnable)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(
        proxy->SetTargetDeviceSwitch(deviceType, deviceId, notificaitonEnable, liveViewEnable));
}

InnerErrorCode AnsNotification::GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnregisterPushCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetTargetDeviceStatus(deviceType, status));
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

InnerErrorCode AnsNotification::GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetDoNotDisturbProfile(id, profile));
}

InnerErrorCode AnsNotification::GetDoNotDisturbProfile(
    int64_t id, sptr<NotificationDoNotDisturbProfile> &profile, const int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetDoNotDisturbProfile(id, profile, userId));
}

InnerErrorCode AnsNotification::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->AllowUseReminder(bundleName, isAllowUseReminder));
}

InnerErrorCode AnsNotification::AllowUseReminder(
    const std::string& bundleName, const int32_t userId, bool& isAllowUseReminder)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->AllowUseReminder(bundleName, userId, isAllowUseReminder));
}

InnerErrorCode AnsNotification::SetDefaultSlotForBundle(const NotificationBundleOption& bundleOption,
    const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("SetDefaultSlotForBundle fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetDefaultSlotForBundle(bo, slotType, enabled, isForceControl));
}

InnerErrorCode AnsNotification::SetCheckConfig(int32_t response, const std::string& requestId,
    const std::string& key, const std::string& value)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->SetCheckConfig(response, requestId, key, value));
}

InnerErrorCode AnsNotification::GetLiveViewConfig(const std::vector<std::string>& bundleList)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetLiveViewConfig(bundleList));
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
InnerErrorCode AnsNotification::RegisterSwingCallback(const std::function<void(bool, int)> swingCbFunc)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterSwingCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    swingCallBackService_ = new(std::nothrow) SwingCallBackService(swingCbFunc);
    if (swingCallBackService_ == nullptr) {
        ANS_LOGE("null swingCallBackService");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->RegisterSwingCallback(swingCallBackService_->AsObject()));
}
#endif

InnerErrorCode AnsNotification::UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UpdateNotificationTimerByUid fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->UpdateNotificationTimerByUid(uid, isPaused));
}

InnerErrorCode AnsNotification::DisableNotificationFeature(const NotificationDisable &notificationDisable)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("DisableNotificationFeature fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    sptr<NotificationDisable> reqPtr = new (std::nothrow) NotificationDisable(notificationDisable);
    if (reqPtr == nullptr) {
        ANS_LOGE("null reqPtr");
        return ERR_ANS_INNER_NO_MEMORY;
    }
    return static_cast<InnerErrorCode>(proxy->DisableNotificationFeature(reqPtr));
}

InnerErrorCode AnsNotification::GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllLiveViewEnabledBundles(bundleOption));
}

InnerErrorCode AnsNotification::GetAllLiveViewEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption, const int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllLiveViewEnabledBundles(bundleOption, userId));
}

InnerErrorCode AnsNotification::GetAllDistribuedEnabledBundles(const std::string& deviceType,
    std::vector<NotificationBundleOption> &bundleOption)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllDistribuedEnabledBundles(deviceType, bundleOption));
}

InnerErrorCode AnsNotification::DistributeOperation(sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (operationInfo == nullptr || callback == nullptr) {
        ANS_LOGE("null operationInfo or callback");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->DistributeOperation(operationInfo, callback));
}

InnerErrorCode AnsNotification::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->ReplyDistributeOperation(hashCode, result));
}

InnerErrorCode AnsNotification::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    ANS_LOGI("get by hashCode:%{public}s", hashCode.c_str());
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetNotificationRequestByHashCode(hashCode, notificationRequest));
}

InnerErrorCode AnsNotification::SetHashCodeRule(
    const uint32_t type)
{
    ANS_LOGI("setHashCodeRule type:%{public}d", type);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetHashCodeRule(type));
}

InnerErrorCode AnsNotification::SetHashCodeRule(const uint32_t type, const int32_t userId)
{
    ANS_LOGI("setHashCodeRule type:%{public}d", type);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetHashCodeRule(type, userId));
}

InnerErrorCode AnsNotification::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllNotificationsBySlotType(notifications, slotType));
}

InnerErrorCode AnsNotification::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    const NotificationConstant::SlotType slotType, int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllNotificationsBySlotType(notifications, slotType, userId));
}

InnerErrorCode AnsNotification::SetRingtoneInfoByBundle(const NotificationBundleOption &bundle,
    const NotificationRingtoneInfo &ringtoneInfo)
{
    ANS_LOGD("called");
    if (bundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleSptr(new (std::nothrow) NotificationBundleOption(bundle));
    if (bundleSptr == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<NotificationRingtoneInfo> ringtoneInfoSptr(new (std::nothrow) NotificationRingtoneInfo(ringtoneInfo));
    if (ringtoneInfoSptr == nullptr) {
        ANS_LOGE("null ringtoneInfo");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    return static_cast<InnerErrorCode>(proxy->SetRingtoneInfoByBundle(bundleSptr, ringtoneInfoSptr));
}

InnerErrorCode AnsNotification::GetRingtoneInfoByBundle(const NotificationBundleOption &bundle,
    NotificationRingtoneInfo &ringtoneInfo)
{
    ANS_LOGD("called");
    if (bundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleSptr(new (std::nothrow) NotificationBundleOption(bundle));
    if (bundleSptr == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<NotificationRingtoneInfo> ringtoneInfoSptr(new (std::nothrow) NotificationRingtoneInfo(ringtoneInfo));
    if (ringtoneInfoSptr == nullptr) {
        ANS_LOGE("null ringtoneInfo");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    InnerErrorCode errCode = static_cast<InnerErrorCode>(proxy->GetRingtoneInfoByBundle(bundleSptr, ringtoneInfoSptr));
    if (errCode == ERR_OK) {
        ringtoneInfo = *ringtoneInfoSptr;
    }
    return errCode;
}

InnerErrorCode AnsNotification::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetDistributedDevicelist(deviceTypes));
}

InnerErrorCode AnsNotification::ProxyForUnaware(const std::vector<int32_t>& uidList, bool isProxy)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->ProxyForUnaware(uidList, isProxy));
}

InnerErrorCode AnsNotification::GetReminderInfoByBundles(
    const std::vector<NotificationBundleOption> &bundles, std::vector<NotificationReminderInfo> &reminderInfo)
{
    if (bundles.empty()) {
        ANS_LOGE("Bundles is null.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> bundlesSptr;
    bundlesSptr.reserve(bundles.size());
    for (const auto &it : bundles) {
        sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(it);
        if (bundle == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        bundlesSptr.emplace_back(std::move(bundle));
    }
    return static_cast<InnerErrorCode>(proxy->GetReminderInfoByBundles(bundlesSptr, reminderInfo));
}

InnerErrorCode AnsNotification::SetReminderInfoByBundles(const std::vector<NotificationReminderInfo> &reminderInfo)
{
    if (reminderInfo.empty()) {
        ANS_LOGE("ReminderInfo is null.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Fail to GetAnsManagerProxy.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationReminderInfo>> reminderInfoSptr;
    reminderInfoSptr.reserve(reminderInfo.size());
    for (const auto &it : reminderInfo) {
        sptr<NotificationReminderInfo> reminder = new (std::nothrow) NotificationReminderInfo(it);
        if (reminder == nullptr) {
            ANS_LOGE("null reminderInfo");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        reminderInfoSptr.emplace_back(std::move(reminder));
    }
    return static_cast<InnerErrorCode>(proxy->SetReminderInfoByBundles(reminderInfoSptr));
}

InnerErrorCode AnsNotification::SetGeofenceEnabled(bool enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetGeofenceEnabled(enabled));
}

InnerErrorCode AnsNotification::IsGeofenceEnabled(bool &enabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->IsGeofenceEnabled(enabled));
}

InnerErrorCode AnsNotification::ClearDelayNotification(const std::vector<std::string> &triggerKeys,
    const std::vector<int32_t> &userIds)
{
    if (triggerKeys.empty() || userIds.empty()) {
        ANS_LOGE("Input parameters triggerKeys or userIds are empty.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    if (triggerKeys.size() != userIds.size()) {
        ANS_LOGE("TriggerKeys size not equal userIds size.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->ClearDelayNotification(triggerKeys, userIds));
}

InnerErrorCode AnsNotification::PublishDelayedNotification(const std::string &triggerKey, int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->PublishDelayedNotification(triggerKey, userId));
}

InnerErrorCode AnsNotification::NotificationExtensionSubscribe(
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("called");
    if (infos.empty()) {
        ANS_LOGE("Invalid infos.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->NotificationExtensionSubscribe(infos));
}

InnerErrorCode AnsNotification::NotificationExtensionUnsubscribe()
{
    ANS_LOGD("called");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->NotificationExtensionUnsubscribe());
}

InnerErrorCode AnsNotification::GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("called");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetSubscribeInfo(infos));
}

InnerErrorCode AnsNotification::IsUserGranted(bool& enabled)
{
    ANS_LOGD("AnsNotification::IsUserGranted called");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->IsUserGranted(enabled));
}

InnerErrorCode AnsNotification::GetUserGrantedState(const NotificationBundleOption& targetBundle, bool& enabled)
{
    ANS_LOGD("called");
    if (targetBundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(targetBundle));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetUserGrantedState(bo, enabled));
}

InnerErrorCode AnsNotification::SetUserGrantedState(const NotificationBundleOption& targetBundle, bool enabled)
{
    ANS_LOGD("called");
    if (targetBundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(targetBundle));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetUserGrantedState(bo, enabled));
}

InnerErrorCode AnsNotification::GetUserGrantedEnabledBundles(
    const NotificationBundleOption& targetBundle, std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    ANS_LOGD("called");
    if (targetBundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(targetBundle));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->GetUserGrantedEnabledBundles(bo, enabledBundles));
}

InnerErrorCode AnsNotification::GetUserGrantedEnabledBundlesForSelf(
    std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->GetUserGrantedEnabledBundlesForSelf(bundles));
}

InnerErrorCode AnsNotification::SetUserGrantedBundleState(const NotificationBundleOption& targetBundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled)
{
    ANS_LOGD("called");
    if (targetBundle.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    if (enabledBundles.empty()) {
        ANS_LOGE("Invalid enabledBundles.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bo(new (std::nothrow) NotificationBundleOption(targetBundle));
    if (bo == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return static_cast<InnerErrorCode>(proxy->SetUserGrantedBundleState(bo, enabledBundles, enabled));
}

InnerErrorCode AnsNotification::GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("called");

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get ans manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetAllSubscriptionBundles(bundles));
}

InnerErrorCode AnsNotification::CanOpenSubscribeSettings()
{
    ANS_LOGD("called");
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Get Extension Subscribe manager proxy fail");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    return static_cast<InnerErrorCode>(proxy->CanOpenSubscribeSettings());
}

InnerErrorCode AnsNotification::GetBadgeNumber(int32_t &badgeNumber)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->GetBadgeNumber(badgeNumber));
}

void AnsNotification::CreateBadgeQueryListener(const std::shared_ptr<IBadgeQueryCallback> &badgeQueryCallback,
    sptr<BadgeQueryListener> &listener)
{
    std::lock_guard<std::mutex> lock(badgeQueryMutex_);
    auto item = badgeQueryCallbacks_.find(badgeQueryCallback);
    if (item != badgeQueryCallbacks_.end()) {
        listener = item->second;
        ANS_LOGD("badgeQueryCallback has listener");
        return;
    }
    listener = new (std::nothrow) BadgeQueryListener(badgeQueryCallback);
    if (listener != nullptr) {
        badgeQueryCallbacks_[badgeQueryCallback] = listener;
        ANS_LOGD("CreateBadgeQueryListener success");
    }
    return;
}

InnerErrorCode AnsNotification::RegisterBadgeQueryCallback(
    const std::shared_ptr<IBadgeQueryCallback> &badgeQueryCallback)
{
    if (badgeQueryCallback == nullptr) {
        ANS_LOGE("null badgeQueryCallback");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("RegisterBadgeQueryCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<BadgeQueryListener> listener = nullptr;
    CreateBadgeQueryListener(badgeQueryCallback, listener);
    if (listener == nullptr) {
        ANS_LOGE("null listener");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    return static_cast<InnerErrorCode>(proxy->RegisterBadgeQueryCallback(listener));
}

InnerErrorCode AnsNotification::UnRegisterBadgeQueryCallback(
    const std::shared_ptr<IBadgeQueryCallback> &badgeQueryCallback)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("UnRegisterBadgeQueryCallback fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    {
        std::lock_guard<std::mutex> lock(badgeQueryMutex_);
        badgeQueryCallbacks_.erase(badgeQueryCallback);
    }
    return static_cast<InnerErrorCode>(proxy->UnRegisterBadgeQueryCallback());
}

InnerErrorCode AnsNotification::IsDoNotDisturbEnabled(int32_t userId, bool& isEnabled)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->IsDoNotDisturbEnabled(userId, isEnabled));
}

InnerErrorCode AnsNotification::IsNotifyAllowedInDoNotDisturb(int32_t userId, bool& isAllowed)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->IsNotifyAllowedInDoNotDisturb(userId, isAllowed));
}

InnerErrorCode AnsNotification::GetNotificationSwitch(
    const NotificationBundleOption &bundleOption, NotificationConstant::SWITCH_STATE &state)
{
    if (bundleOption.GetBundleName().empty()) {
        ANS_LOGE("Invalid bundle name.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }

    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("Unable to connect to ANS service.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    sptr<NotificationBundleOption> bundleInfo(new (std::nothrow) NotificationBundleOption(bundleOption));
    if (bundleInfo == nullptr) {
        ANS_LOGE("null bundleInfo");
        return ERR_ANS_INNER_NO_MEMORY;
    }

    int32_t intState = 0;
    InnerErrorCode result = static_cast<InnerErrorCode>(proxy->GetNotificationSwitch(bundleInfo, intState));
    state = static_cast<NotificationConstant::SWITCH_STATE>(intState);
    return result;
}

InnerErrorCode AnsNotification::GetStatisticsByBundle(const std::vector<NotificationBundleOption> &bundleOptions,
    std::vector<NotificationStatistics> &statistics)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    std::vector<sptr<NotificationBundleOption>> bundlesSptr;
    bundlesSptr.reserve(bundleOptions.size());
    for (const auto &it : bundleOptions) {
        sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(it);
        if (bundle == nullptr) {
            ANS_LOGE("null bundleOption");
            return ERR_ANS_INNER_NO_MEMORY;
        }
        bundlesSptr.emplace_back(std::move(bundle));
    }
    return static_cast<InnerErrorCode>(proxy->GetStatisticsByBundle(bundlesSptr, statistics));
}

InnerErrorCode AnsNotification::SnoozeNotification(const std::string &hashCode, const int64_t delayTime)
{
    if (hashCode.empty()) {
        ANS_LOGE("Invalid hashCode.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    if (delayTime <= 0 || delayTime > NotificationConstant::MAX_DELAY_TIME_S) {
        ANS_LOGE("Invalid delayTime.");
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SnoozeNotification(hashCode, delayTime));
}

InnerErrorCode AnsNotification::SetNotificationSwitch(const std::string &switchName, bool switchState, int32_t userId)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }
    return static_cast<InnerErrorCode>(proxy->SetNotificationSwitch(switchName, switchState, userId));
}

InnerErrorCode AnsNotification::GetNotificationSwitch(
    const std::string &switchName, int32_t userId, NotificationConstant::SWITCH_STATE &switchState)
{
    sptr<IAnsManager> proxy = GetAnsManagerProxy();
    if (!proxy) {
        ANS_LOGE("GetAnsManagerProxy fail.");
        return ERR_ANS_INNER_SERVICE_NOT_CONNECTED;
    }

    int32_t state = static_cast<int32_t>(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    InnerErrorCode result = static_cast<InnerErrorCode>(proxy->GetNotificationSwitch(switchName, userId, state));
    switchState = static_cast<NotificationConstant::SWITCH_STATE>(state);
    return result;
}
}  // namespace Notification
}  // namespace OHOS
