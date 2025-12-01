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

#include "advanced_notification_service.h"

#include <functional>
#include <iomanip>
#include <sstream>

#include "accesstoken_kit.h"
#include "ans_const_define.h"
#include "ans_convert_enum.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_unified_group_Info.h"
#include "os_account_manager.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_screen_status_manager.h"
#endif
#include "notification_extension_wrapper.h"
#include "notification_local_live_view_subscriber_manager.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_publish_info.h"
#include "os_account_manager_helper.h"
#include "want_params_wrapper.h"
#include "ans_convert_enum.h"
#include "notification_analytics_util.h"

#include "advanced_notification_inline.h"
#include "notification_analytics_util.h"
#include "advanced_datashare_helper.h"
#include "advanced_datashare_helper_ext.h"
#include "datashare_result_set.h"
#include "parameter.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "datashare_predicates.h"
#include "notification_config_parse.h"
#include "advanced_notification_flow_control_service.h"
#include "notification_operation_info.h"
#include "notification_operation_service.h"
#include "bool_wrapper.h"
#ifdef ALL_SCENARIO_COLLABORATION
#include "distributed_collaboration_service.h"
#endif

namespace OHOS {
namespace Notification {

constexpr uint32_t SECONDS_IN_ONE_DAY = 24 * 60 * 60;
const static std::string NOTIFICATION_EVENT_PUSH_AGENT = "notification.event.PUSH_AGENT";
const static std::string NOTIFICATION_EVENT_SUBSCRIBER_STATUS = "notification.event.SUBSCRIBER_STATUS";
constexpr int32_t RSS_PID = 3051;
constexpr int32_t AVSEESAION_PID = 6700;
constexpr int32_t TYPE_CODE_DOWNLOAD = 8;
constexpr const char *FOCUS_MODE_REPEAT_CALLERS_ENABLE = "1";
constexpr const char *CONTACT_DATA = "datashare:///com.ohos.contactsdataability/contacts/contact_data?Proxy=true";
constexpr const char *SUPPORT_INTEGELLIGENT_SCENE = "true";
constexpr int32_t CLEAR_SLOT_FROM_AVSEESAION = 1;
constexpr int32_t CLEAR_SLOT_FROM_RSS = 2;
constexpr const char *PERSIST_EDM_NOTIFICATION_DISABLE =  "persist.edm.notification_disable";

ErrCode AdvancedNotificationService::SetDefaultNotificationEnabled(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    sptr<EnabledNotificationCallbackData> bundleData =
        new (std::nothrow) EnabledNotificationCallbackData(bundle->GetBundleName(), bundle->GetUid(), enabled);
    if (bundleData == nullptr) {
        ANS_LOGE("Failed to create EnabledNotificationCallbackData instance");
        return ERR_NO_MEMORY;
    }
    SetSlotFlagsTrustlistsAsBundle(bundle);
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state = enabled ? NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON
                                                        : NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    result = NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundle, state);
    if (result == ERR_OK) {
        NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
        PublishSlotChangeCommonEvent(bundle);
    }

    SendEnableNotificationHiSysEvent(bundleOption, enabled, result);
    return result;
}

void AdvancedNotificationService::SetCollaborateReminderFlag(const sptr<NotificationRequest> &request)
{
    auto flags = std::make_shared<NotificationFlags>();
    flags->SetReminderFlags(request->GetCollaboratedReminderFlag());
    request->SetFlags(flags);
    ANS_LOGI("CollaborateReminder %{public}s SetFlags %{public}d %{public}d", request->GetKey().c_str(),
        flags->GetReminderFlags(), request->GetCollaboratedReminderFlag());
}

void AdvancedNotificationService::UpdateCollaborateTimerInfo(const std::shared_ptr<NotificationRecord> &record)
{
    if (!record->request->IsCommonLiveView()) {
        if ((record->request->GetAutoDeletedTime() > GetCurrentTime())) {
            StartAutoDeletedTimer(record);
        }
        return;
    }

    auto content = record->request->GetContent()->GetNotificationContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto status = liveViewContent->GetLiveViewStatus();
    switch (status) {
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE: {
            if (record->notification->GetFinishTimer() == NotificationConstant::INVALID_TIMER_ID) {
                SetFinishTimer(record);
            }
            if (record->notification->GetUpdateTimer() == NotificationConstant::INVALID_TIMER_ID) {
                SetUpdateTimer(record);
            }
            CancelArchiveTimer(record);
            return;
        }
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE:
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE: {
            if (record->notification->GetFinishTimer() == NotificationConstant::INVALID_TIMER_ID) {
                int64_t finishedTime = record->request->GetFinishDeadLine();
                StartFinishTimer(record, finishedTime,
                    NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE);
            }
            CancelUpdateTimer(record);
            SetUpdateTimer(record);
            CancelArchiveTimer(record);
            return;
        }
        case NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END:
            CancelUpdateTimer(record);
            CancelFinishTimer(record);
            StartArchiveTimer(record);
            break;
        default:
            ANS_LOGE("Invalid status %{public}d.", status);
    }
}

ErrCode AdvancedNotificationService::SetCollaborateRequest(const sptr<NotificationRequest> &request)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    if (request->GetCreatorPid() == 0) {
        request->SetCreatorPid(pid);
    }
    if (request->GetOwnerUid() == DEFAULT_UID) {
        request->SetOwnerUid(uid);
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    request->SetCreatorUserId(userId);
    request->SetCreateTime(GetCurrentTime());
    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }
    SetCollaborateReminderFlag(request);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::CollaborateFilter(const sptr<NotificationRequest> &request)
{
    auto params = request->GetExtendInfo();
    if (params == nullptr) {
        ANS_LOGI("Collaborate filter extend info is null.");
        return ERR_OK;
    }

    auto value = params->GetParam("notification_collaboration_check");
    AAFwk::IBoolean* ao = AAFwk::IBoolean::Query(value);
    if (ao == nullptr) {
        ANS_LOGI("Collaborate filter invalid extend info.");
        return ERR_OK;
    }
    if (!AAFwk::Boolean::Unbox(ao)) {
        ANS_LOGI("Collaborate filter check is false.");
        return ERR_OK;
    }
    NotificationConstant::SWITCH_STATE switchEnabled = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    std::string localType = params->GetStringParam("notification_collaboration_localType");
    NotificationConstant::SlotType slotType = request->GetSlotType();
    ErrCode result = ERR_OK;
    if (slotType == NotificationConstant::SlotType::LIVE_VIEW) {
        result = NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(
            NotificationConstant::SlotType::LIVE_VIEW, localType, switchEnabled);
        if (result != ERR_OK ||
            (switchEnabled != NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON &&
            switchEnabled != NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON)) {
            ANS_LOGW("Get live view distributed failed %{public}d %{public}d.",
                result, static_cast<int32_t>(switchEnabled));
            return ERR_ANS_NOT_ALLOWED;
        }
        return ERR_OK;
    }
    NotificationConstant::SWITCH_STATE enable;
    result = NotificationPreferences::GetInstance()->IsDistributedEnabled(localType, enable);
    if (result != ERR_OK ||
        (enable != NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON &&
        enable != NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON)) {
        ANS_LOGW("Get notification distributed failed %{public}d %{public}d.", result, enable);
        return ERR_ANS_NOT_ALLOWED;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::CollaboratePublish(const sptr<NotificationRequest> &request)
{
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (!AccessTokenHelper::VerifyNativeToken(tokenCaller) ||
        !AccessTokenHelper::VerifyCallerPermission(tokenCaller, OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Collaborate publish cheak permission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    SetCollaborateRequest(request);
    record->request = request;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot(request->GetSlotType());
    if (slot == nullptr) {
        ANS_LOGE("Failed to create NotificationSlot instance");
        return ERR_NO_MEMORY;
    }
    slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
    record->slot = slot;
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        return ERR_ANS_NO_MEMORY;
    }
    record->bundleOption = new (std::nothrow) NotificationBundleOption(request->GetCreatorBundleName(), 0);
    record->notification->SetKey("ans_distributed" + request->GetDistributedHashCode());
    if (CollaborateFilter(request) != ERR_OK) {
        return ERR_ANS_NOT_ALLOWED;
    }
    if (notificationSvrQueue_ == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (DuplicateMsgControl(record->request) == ERR_ANS_DUPLICATE_MSG) {
            (void)PublishRemoveDuplicateEvent(record);
            return;
        }
#ifdef ALL_SCENARIO_COLLABORATION
        if (!DistributedCollaborationService::GetInstance().CheckCollaborativePublish(record->notification)) {
            return;
        }
#endif
        if (AssignToNotificationList(record) != ERR_OK) {
            return;
        }
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
        UpdateCollaborateTimerInfo(record);
    });
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

bool AdvancedNotificationService::InitPublishProcess()
{
    if (publishProcess_.size() > 0) {
        return true;
    }

    std::shared_ptr<LivePublishProcess> livePublishProcess = LivePublishProcess::GetInstance();
    if (livePublishProcess == nullptr) {
        ANS_LOGE("InitPublishProcess fail as livePublishProcess is nullptr.");
        return false;
    }
    publishProcess_.insert_or_assign(NotificationConstant::SlotType::LIVE_VIEW, livePublishProcess);
    std::shared_ptr<CommonNotificationPublishProcess> commonNotificationPublishProcess =
        CommonNotificationPublishProcess::GetInstance();
    if (commonNotificationPublishProcess == nullptr) {
        ANS_LOGE("InitPublishProcess fail as commonNotificationPublishProcess is nullptr.");
        publishProcess_.clear();
        return false;
    }
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::SOCIAL_COMMUNICATION, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::SERVICE_REMINDER, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::CONTENT_INFORMATION, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::OTHER, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::CUSTOM, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::CUSTOMER_SERVICE, commonNotificationPublishProcess);
    publishProcess_.insert_or_assign(
        NotificationConstant::SlotType::EMERGENCY_INFORMATION, commonNotificationPublishProcess);
    return true;
}

ErrCode AdvancedNotificationService::IsAllowedNotifyForBundle(const sptr<NotificationBundleOption>
    &bundleOption, bool &allowed)
{
    ANS_LOGD("called");
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    allowed = false;
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundleOption, state);
        if (result == ERR_OK) {
            allowed = (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
                state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        }
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            // FA model app can publish notification without user confirm
            allowed = CheckApiCompatibility(bundleOption);
        }
    }
    return result;
}

ErrCode AdvancedNotificationService::IsNeedSilentInDoNotDisturbMode(
    const std::string &phoneNumber, int32_t callerType)
{
    ANS_LOGD("called");

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != NotificationConstant::ANS_UID &&
        !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("IsNeedSilentInDoNotDisturbMode CheckPermission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    return CheckNeedSilent(phoneNumber, callerType, userId);
}

ErrCode AdvancedNotificationService::CheckNeedSilent(
    const std::string &phoneNumber, int32_t callerType, int32_t userId)
{
    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return -1;
    }
    int isNeedSilent = 0;
    std::string policy;
    Uri policyUri(datashareHelper->GetFocusModeCallPolicyUri(userId));
    bool ret = datashareHelper->Query(policyUri, KEY_FOCUS_MODE_CALL_MESSAGE_POLICY, policy);
    if (!ret) {
        ANS_LOGE("Query focus mode call message policy fail.");
        return -1;
    }
    std::string repeat_call;
    Uri repeatUri(datashareHelper->GetFocusModeRepeatCallUri(userId));
    bool repeat_ret = datashareHelper->Query(repeatUri, KEY_FOCUS_MODE_REPEAT_CALLERS_ENABLE, repeat_call);
    if (!repeat_ret) {
        ANS_LOGE("Query focus mode repeat callers enable fail.");
    }
    ANS_LOGI("IsNeedSilent policy:%{public}s,repeat:%{public}s,callerType:%{public}d",
        policy.c_str(), repeat_call.c_str(), callerType);
    if (repeat_call == FOCUS_MODE_REPEAT_CALLERS_ENABLE && callerType == 0 &&
        atoi(policy.c_str()) != ContactPolicy::ALLOW_EVERYONE && datashareHelper->isRepeatCall(phoneNumber)) {
        return 1;
    }
    bool isAccountVerified = true;
    ErrCode account_ret = OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(userId, isAccountVerified);
    if (account_ret != ERR_OK) {
        ANS_LOGE("IsOsAccountVerified fail.");
    }
    switch (atoi(policy.c_str())) {
        case ContactPolicy::FORBID_EVERYONE:
            break;
        case ContactPolicy::ALLOW_EVERYONE:
            isNeedSilent = 1;
            break;
        case ContactPolicy::ALLOW_EXISTING_CONTACTS:
        case ContactPolicy::ALLOW_FAVORITE_CONTACTS:
        case ContactPolicy::ALLOW_SPECIFIED_CONTACTS:
            isNeedSilent = isAccountVerified ? QueryContactByProfileId(phoneNumber, policy, userId) : 0;
            break;
        case ContactPolicy::FORBID_SPECIFIED_CONTACTS:
            isNeedSilent = isAccountVerified ? QueryContactByProfileId(phoneNumber, policy, userId) : 1;
            break;
    }
    ANS_LOGI("CheckNeedSilent isNeedSilent:%{public}d,isAccountVerified:%{public}d", isNeedSilent, isAccountVerified);
    return isNeedSilent;
}

ErrCode AdvancedNotificationService::QueryContactByProfileId(const std::string &phoneNumber,
    const std::string &policy, int32_t userId)
{
    char buf[256] = { 0 };
    const std::string &paramName = "const.intelligentscene.enable";
    std::string isSupportIntelligentScene = "false";
    const std::string defaultValue = "false";

    auto res = GetParameter(paramName.c_str(), defaultValue.c_str(), buf, sizeof(buf));
    if (res <= 0) {
        ANS_LOGD("isSupportIntelligentScene GetParameter is false");
    } else {
        isSupportIntelligentScene = buf;
    }
    ANS_LOGI("isSupportIntelligentScene is %{public}s", isSupportIntelligentScene.c_str());

    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return -1;
    }

    std::string uri = CONTACT_DATA;
    if (isSupportIntelligentScene == SUPPORT_INTEGELLIGENT_SCENE &&
        (atoi(policy.c_str()) == ContactPolicy::ALLOW_SPECIFIED_CONTACTS ||
        atoi(policy.c_str()) == ContactPolicy::FORBID_SPECIFIED_CONTACTS)) {
        uri = datashareHelper->GetIntelligentUri();
    }
    ANS_LOGI("QueryContactByProfileId uri is %{public}s", uri.c_str());

    std::string profileId;
    Uri profileIdUri(datashareHelper->GetFocusModeProfileUri(userId));
    bool profile_ret = datashareHelper->Query(profileIdUri, KEY_FOCUS_MODE_PROFILE, profileId);
    if (!profile_ret) {
        ANS_LOGE("Query profile id fail.");
        return -1;
    }

    Uri contactUri(uri);
    return datashareHelper->QueryContact(contactUri, phoneNumber, policy, profileId, isSupportIntelligentScene);
}

ErrCode AdvancedNotificationService::CancelGroup(const std::string &groupName, const std::string &instanceKey)
{
    ANS_LOGD("called");

    int32_t reason = NotificationConstant::APP_CANCEL_GROPU_REASON_DELETE;
    if (groupName.empty()) {
        std::string message = "groupName empty.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(3, 1)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        std::string message = "bundle is nullptr.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(3, 2)
            .ErrorCode(ERR_ANS_INVALID_BUNDLE);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetAppInstanceKey(instanceKey);

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalid.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    ExcuteCancelGroupCancel(bundleOption, groupName, reason);
    return ERR_OK;
}

void AdvancedNotificationService::ExcuteCancelGroupCancel(
    const sptr<NotificationBundleOption>& bundleOption,
    const std::string &groupName, const int32_t reason)
{
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        for (auto record : notificationList_) {
            ANS_LOGD("ExcuteCancelGroupCancel instanceKey(%{public}s, %{public}s).",
                record->notification->GetInstanceKey().c_str(), bundleOption->GetAppInstanceKey().c_str());
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
                (record->notification->GetInstanceKey() == bundleOption->GetAppInstanceKey()) &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                record->deviceId.empty() &&
#endif
                (record->request->GetGroupName() == groupName)) {
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, reason);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));
}

ErrCode AdvancedNotificationService::RemoveGroupByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName)
{
    ANS_LOGD("called");
    const int32_t reason = NotificationConstant::APP_REMOVE_GROUP_REASON_DELETE;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not systemApp.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 1)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        std::string message = "no acl permission";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 2)
            .ErrorCode(ERR_ANS_PERMISSION_DENIED);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (bundleOption == nullptr || groupName.empty()) {
        std::string message = "groupName empty";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 3)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        std::string message = "bundle is nullptr";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(5, 4)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalid.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
        for (auto record : notificationList_) {
            if (!record->notification->IsRemoveAllowed()) {
                continue;
            }
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid()) && !record->request->IsUnremovable() &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                record->deviceId.empty() &&
#endif
                (record->request->GetGroupName() == groupName)) {
                ANS_LOGD("RemoveList push enter.");
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            notificationList_.remove(record);
            ProcForDeleteLiveView(record);

            if (record->notification != nullptr) {
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                SendNotificationsOnCanceled(notifications, nullptr, reason);
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));

    return ERR_OK;
}

void AdvancedNotificationService::UpdateUnifiedGroupInfo(const std::string &key,
    std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([=]() {
        for (const auto& item : notificationList_) {
            if (item->notification->GetKey() == key) {
                ANS_LOGD("update group info matched key %s", key.c_str());
                item->notification->GetNotificationRequestPoint()->SetUnifiedGroupInfo(groupInfo);

                CloseAlert(item);

                UpdateRecentNotification(item->notification, false, 0);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyConsumed(item->notification, sortingMap);
                break;
            }
        }
    });
}

void AdvancedNotificationService::ClearSlotTypeData(const sptr<NotificationRequest> &request, int32_t callingUid,
    int32_t sourceType)
{
    if (request == nullptr || (sourceType != CLEAR_SLOT_FROM_AVSEESAION && sourceType != CLEAR_SLOT_FROM_RSS)) {
        return;
    }

    if (sourceType == CLEAR_SLOT_FROM_AVSEESAION) {
        if (callingUid != AVSEESAION_PID ||
            request->GetSlotType() != NotificationConstant::SlotType::LIVE_VIEW) {
            return;
        }
    }
    if (sourceType == CLEAR_SLOT_FROM_RSS) {
        if (request->GetCreatorUid() != RSS_PID || !request->IsSystemLiveView()) {
            return;
        }
    }

    int32_t uid = request->GetOwnerUid();
    std::string bundleName = BundleManagerHelper::GetInstance()->GetBundleNameByUid(uid);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption == nullptr) {
        ANS_LOGW("Notification get bundle failed %{public}d", uid);
        return;
    }

    if (NotificationPreferences::GetInstance()->GetBundleRemoveFlag(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW, sourceType)) {
        return;
    }
    NotificationPreferences::GetInstance()->RemoveNotificationSlot(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW);
    NotificationPreferences::GetInstance()->SetBundleRemoveFlag(bundleOption,
        NotificationConstant::SlotType::LIVE_VIEW, sourceType);
}

ErrCode AdvancedNotificationService::PublishNotificationBySa(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("called");

    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool isSystemApp = AccessTokenHelper::IsSystemApp();
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(tokenCaller);
    bool isThirdparty;
    if (isSystemApp || isSubsystem) {
        isThirdparty = false;
    } else {
        isThirdparty = true;
    }
    bool isAgentController = AccessTokenHelper::VerifyCallerPermission(tokenCaller,
        OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_4, EventBranchId::BRANCH_1);
    int32_t uid = request->GetCreatorUid();
    if (request->GetOwnerUid() != DEFAULT_UID) {
        std::shared_ptr<NotificationBundleOption> agentBundle =
        std::make_shared<NotificationBundleOption>("", uid);
        request->SetAgentBundle(agentBundle);
    }
    bool directAgency = false;

    if (request->IsAgentNotification()) {
        uid = request->GetOwnerUid();
        request->SetIsAgentNotification(false);
        directAgency = true;
    }
    if (uid <= 0) {
        message.ErrorCode(ERR_ANS_INVALID_UID).Message("createUid failed" + std::to_string(uid), true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_INVALID_UID;
    }
    std::string bundle = "";
    ErrCode result = PrePublishNotificationBySa(request, uid, bundle);
    if (request->GetCreatorUid() == RSS_PID && request->IsSystemLiveView() &&
        (std::static_pointer_cast<OHOS::Notification::NotificationLocalLiveViewContent>(
        request->GetContent()->GetNotificationContent())->GetType() != TYPE_CODE_DOWNLOAD)) {
        request->SetSlotType(NotificationConstant::SlotType::OTHER);
        request->GetContent()->ResetToBasicContent();
        request->SetUnremovable(true);
        request->SetTapDismissed(false);
    }
    if (result != ERR_OK) {
        return result;
    }

    // SA not support sound
    if (!request->GetSound().empty()) {
        request->SetSound("");
    }
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->isThirdparty = isThirdparty;
    if (directAgency) {
        record->bundleOption = new (std::nothrow) NotificationBundleOption("", request->GetCreatorUid());
    } else {
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
        int32_t ctrlResult = EXTENTION_WRAPPER->LocalControl(request);
        if (ctrlResult != ERR_OK) {
            message.ErrorCode(ctrlResult);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            return ctrlResult;
        }
#endif
        record->bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (record->bundleOption == nullptr || bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption");
        return ERR_ANS_NO_MEMORY;
    }
    record->bundleOption->SetAppInstanceKey(request->GetAppInstanceKey());
    int32_t ipcUid = IPCSkeleton::GetCallingUid();
    uint32_t hashCodeGeneratetype = NotificationPreferences::GetInstance()->GetHashCodeRule(ipcUid);
    request->SetHashCodeGenerateType(hashCodeGeneratetype);
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        return ERR_ANS_NO_MEMORY;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    SetRequestBySlotType(record->request, bundleOption);
#ifdef ENABLE_ANS_AGGREGATION
    EXTENTION_WRAPPER->GetUnifiedGroupInfo(request);
#endif

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([&]() {
        if (!bundle.empty() && IsDisableNotification(bundle)) {
            ANS_LOGE("bundle in Disable Notification list, bundleName=%{public}s", bundle.c_str());
            result = ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION;
            return;
        }
        if (IsDisableNotificationForSaByKiosk(bundle, directAgency)) {
            ANS_LOGE("bundle not in kiosk trust list, bundleName=%{public}s", bundle.c_str());
            result = ERR_ANS_REJECTED_WITH_DISABLE_NOTIFICATION;
            return;
        }
        if (!bundleOption->GetBundleName().empty() &&
            !(request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW && directAgency)) {
            ErrCode ret = AssignValidNotificationSlot(record, bundleOption);
            if (ret != ERR_OK) {
                ANS_LOGE("PublishNotificationBySA Can not assign valid slot!");
            }
            if (!directAgency) {
                result = Filter(record);
                if (result != ERR_OK) {
                    ANS_LOGE("PublishNotificationBySA Reject by filters: %{public}d", result);
                    return;
                }
            }
        }

        NotificationAnalyticsUtil::ReportSAPublishSuccessEvent(record->request, ipcUid);
        if (!request->IsDoNotDisturbByPassed()) {
            CheckDoNotDisturbProfile(record);
        }
        ChangeNotificationByControlFlags(record, isAgentController);
        if (IsSaCreateSystemLiveViewAsBundle(record, ipcUid) &&
        (std::static_pointer_cast<OHOS::Notification::NotificationLocalLiveViewContent>(
        record->request->GetContent()->GetNotificationContent())->GetType() == TYPE_CODE_DOWNLOAD)) {
            result = SaPublishSystemLiveViewAsBundle(record);
            if (result == ERR_OK) {
                SendLiveViewUploadHiSysEvent(record, UploadStatus::CREATE);
            }
            ClearSlotTypeData(record->request, ipcUid, CLEAR_SLOT_FROM_RSS);
            return;
        }
        bool isNotificationExists = IsNotificationExists(record->notification->GetKey());
        result = FlowControlService::GetInstance().FlowControl(record, ipcUid, isNotificationExists);
        if (result != ERR_OK) {
            return;
        }
        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            return;
        }

        ClearSlotTypeData(record->request, ipcUid, CLEAR_SLOT_FROM_AVSEESAION);
        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
        if ((record->request->GetAutoDeletedTime() > GetCurrentTime()) && !record->request->IsCommonLiveView()) {
            StartAutoDeletedTimer(record);
        }
    });
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK) {
        return result;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::DuplicateMsgControl(const sptr<NotificationRequest> &request)
{
    if (request->IsCommonLiveView() || request->GetAppMessageId().empty()) {
        return ERR_OK;
    }

    RemoveExpiredUniqueKey();
    RemoveExpiredDistributedUniqueKey();
    RemoveExpiredLocalUniqueKey();
    std::string uniqueKey = request->GenerateUniqueKey();
    std::string distributedUniqueKey = request->GenerateDistributedUniqueKey();
    std::string localUniqueKey = distributedUniqueKey;

    if (request->GetDistributedCollaborate()) {
        if (IsDuplicateMsg(distributedUniqueKeyList_, distributedUniqueKey)) {
            ANS_LOGE("Distributed duplicate msg, no need to notify, key is %{public}s, appmessageId is %{public}s",
                request->GetKey().c_str(), request->GetAppMessageId().c_str());
            return ERR_ANS_DUPLICATE_MSG;
        }
        localUniqueKeyList_.emplace_back(std::make_pair(std::chrono::system_clock::now(), localUniqueKey));
        distributedUniqueKeyList_.emplace_back(std::make_pair(std::chrono::system_clock::now(), distributedUniqueKey));
    } else {
        if (IsDuplicateMsg(uniqueKeyList_, uniqueKey) || IsDuplicateMsg(localUniqueKeyList_, localUniqueKey)) {
            ANS_LOGE("Duplicate msg, no need to notify, key is %{public}s, appmessageId is %{public}s",
                request->GetKey().c_str(), request->GetAppMessageId().c_str());
            return ERR_ANS_DUPLICATE_MSG;
        }
        uniqueKeyList_.emplace_back(std::make_pair(std::chrono::system_clock::now(), uniqueKey));
        distributedUniqueKeyList_.emplace_back(std::make_pair(std::chrono::system_clock::now(), distributedUniqueKey));
    }
    return ERR_OK;
}

void AdvancedNotificationService::DeleteDuplicateMsgs(const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr");
        return;
    }
    const char *keySpliter = "_";
    std::stringstream stream;
    stream << bundleOption->GetUid() << keySpliter << bundleOption->GetBundleName() << keySpliter;
    std::string uniqueKeyHead = stream.str();
    for (auto iter = uniqueKeyList_.begin(); iter != uniqueKeyList_.end();) {
        if ((*iter).second.find(uniqueKeyHead) == 0) {
            iter = uniqueKeyList_.erase(iter);
        } else {
            ++iter;
        }
    }

    stream.str(std::string());
    stream.clear();
    stream << bundleOption->GetBundleName() << keySpliter;
    std::string distributedUniqueKeyHead = stream.str();
    for (auto iter = distributedUniqueKeyList_.begin(); iter != distributedUniqueKeyList_.end();) {
        if ((*iter).second.find(distributedUniqueKeyHead) == 0) {
            iter = distributedUniqueKeyList_.erase(iter);
        } else {
            ++iter;
        }
    }

    stream.str(std::string());
    stream.clear();
    stream << bundleOption->GetBundleName() << keySpliter;
    std::string localUniqueKeyHead = stream.str();
    for (auto iter = localUniqueKeyList_.begin(); iter != localUniqueKeyList_.end();) {
        if ((*iter).second.find(localUniqueKeyHead) == 0) {
            iter = localUniqueKeyList_.erase(iter);
        } else {
            ++iter;
        }
    }
}

void AdvancedNotificationService::RemoveExpiredUniqueKey()
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    auto iter = uniqueKeyList_.begin();
    while (iter != uniqueKeyList_.end()) {
        uint32_t duration = std::chrono::duration_cast<std::chrono::seconds>(abs(now - (*iter).first)).count();
        ANS_LOGD("RemoveExpiredUniqueKey duration is %{public}u", duration);
        if (duration > SECONDS_IN_ONE_DAY) {
            ANS_LOGI("RemoveExpiredUniqueKey end duration is %{public}u", duration);
            iter = uniqueKeyList_.erase(iter);
        } else {
            break;
        }
    }
}

void AdvancedNotificationService::RemoveExpiredDistributedUniqueKey()
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    auto iter = distributedUniqueKeyList_.begin();
    while (iter != distributedUniqueKeyList_.end()) {
        uint32_t duration = std::chrono::duration_cast<std::chrono::seconds>(abs(now - (*iter).first)).count();
        ANS_LOGD("RemoveExpired distributedUniqueKeyList_ duration is %{public}u", duration);
        if (duration > SECONDS_IN_ONE_DAY) {
            ANS_LOGI("RemoveExpired distributedUniqueKeyList_ end duration is %{public}u", duration);
            iter = distributedUniqueKeyList_.erase(iter);
        } else {
            break;
        }
    }
}

void AdvancedNotificationService::RemoveExpiredLocalUniqueKey()
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    auto iter = localUniqueKeyList_.begin();
    while (iter != localUniqueKeyList_.end()) {
        uint32_t duration = std::chrono::duration_cast<std::chrono::seconds>(abs(now - (*iter).first)).count();
        ANS_LOGD("RemoveExpired localUniqueKeyList_ duration is %{public}u", duration);
        if (duration > SECONDS_IN_ONE_DAY) {
            ANS_LOGI("RemoveExpired localUniqueKeyList_ end duration is %{public}u", duration);
            iter = localUniqueKeyList_.erase(iter);
        } else {
            break;
        }
    }
}

bool AdvancedNotificationService::IsDuplicateMsg(const std::list<std::pair<std::chrono::system_clock::time_point,
    std::string>> &msglist, const std::string &key)
{
    for (auto record : msglist) {
        if (strcmp(record.second.c_str(), key.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
void AdvancedNotificationService::SetDialogPoppedUnEnableTime(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("SetDialogPoppedRefuseTime called.");
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    EXTENTION_WRAPPER->SetDialogOpenSuccessTimeStamp(bundleOption, userId);
    ANS_LOGD("SetDialogPoppedRefuseTime end.");
}
#endif

ErrCode AdvancedNotificationService::PublishRemoveDuplicateEvent(const std::shared_ptr<NotificationRecord> &record)
{
    if (record == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!record->request->IsAgentNotification()) {
        ANS_LOGD("Only push agent need remove duplicate event");
        return ERR_OK;
    }

    std::string extraStr;
    if (record->request->GetUnifiedGroupInfo() != nullptr) {
        auto extraInfo = record->request->GetUnifiedGroupInfo()->GetExtraInfo();
        if (extraInfo != nullptr) {
            AAFwk::WantParamWrapper wWrapper(*extraInfo);
            extraStr = wWrapper.ToString();
        }
    }

    NotificationNapi::SlotType slotType;
    NotificationNapi::ContentType contentType;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(
        static_cast<NotificationContent::Type>(record->request->GetNotificationType()), contentType);
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(
        static_cast<NotificationConstant::SlotType>(record->request->GetSlotType()), slotType);

    EventFwk::Want want;
    want.SetParam("bundleName", record->bundleOption->GetBundleName());
    want.SetParam("uid", record->request->GetOwnerUid());
    want.SetParam("id", record->request->GetNotificationId());
    want.SetParam("slotType", static_cast<int32_t>(slotType));
    want.SetParam("contentType", static_cast<int32_t>(contentType));
    want.SetParam("appMessageId", record->request->GetAppMessageId());
    want.SetParam("extraInfo", extraStr);
    want.SetAction(NOTIFICATION_EVENT_PUSH_AGENT);
    EventFwk::CommonEventData commonData {want, 1, ""};
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER});
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo)) {
        ANS_LOGE("PublishCommonEvent failed");
        return ERR_ANS_TASK_ERR;
    }

    return ERR_OK;
}

ErrCode AdvancedNotificationService::PublishExtensionServiceStateChange(
    NotificationConstant::EventCodeType eventCode,
    const sptr<NotificationBundleOption> &bundleOption, bool state,
    const std::vector<sptr<NotificationBundleOption>> &enabledBundles)
{
    ANS_LOGD("%{public}s: code=%{public}d, bundle=%{public}s, state=%{public}d",
        __FUNCTION__, eventCode, bundleOption->GetBundleName().c_str(), state);

    if (bundleOption == nullptr) {
        ANS_LOGE("Invalid bundle option");
        return ERR_ANS_INVALID_PARAM;
    }

    if (eventCode < NotificationConstant::USER_GRANTED_STATE ||
        eventCode > NotificationConstant::EXTENSION_ABILITY_REMOVED) {
        ANS_LOGE("Invalid event code: %{public}d", eventCode);
        return ERR_ANS_INVALID_PARAM;
    }

    EventFwk::Want want;
    want.SetAction("usual.event.notification.EXTENSION_SUBSCRIBE_STATE_CHANGE");
    want.SetParam("state", state);
    if (eventCode == NotificationConstant::USER_GRANTED_BUNDLE_STATE) {
        nlohmann::json enabledBundlesJson = nlohmann::json::array();
        for (const auto &bundle : enabledBundles) {
            if (bundle != nullptr) {
                enabledBundlesJson.push_back({
                    {"bundle", bundle->GetBundleName()},
                    {"uid", bundle->GetUid()}
                });
            }
        }
        want.SetParam("enabledBundles", enabledBundlesJson.dump());
    }
    
    nlohmann::json targetBundle = {{"bundle", bundleOption->GetBundleName()}, {"uid", bundleOption->GetUid()}};
    want.SetParam("targetBundle", targetBundle.dump());

    EventFwk::CommonEventData commonData;
    commonData.SetWant(want);
    commonData.SetCode(static_cast<int32_t>(eventCode));
    commonData.SetData(bundleOption->GetBundleName());
    std::vector<std::string> permission { OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions(permission);
    bool publishResult = EventFwk::CommonEventManager::PublishCommonEvent(commonData, publishInfo);
    if (!publishResult) {
        ANS_LOGE("PublishCommonEvent failed for bundle: %{public}s, code: %{public}d",
            bundleOption->GetBundleName().c_str(), eventCode);
        return ERR_ANS_TASK_ERR;
    }
    ANS_LOGI("Publish event code=%{public}d for bundle: %{public}s, state: %{public}d",
        eventCode, bundleOption->GetBundleName().c_str(), state);
    return ERR_OK;
}

void AdvancedNotificationService::ClearAllNotificationGroupInfo(std::string localSwitch)
{
    ANS_LOGD("ClearNotification enter.");
    bool status = (localSwitch == "true");
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("ClearNotification Serial queue is invalid.");
        return;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h([=]() {
        if (aggregateLocalSwitch_ && !status) {
            for (const auto& item : notificationList_) {
                item->notification->GetNotificationRequestPoint()->SetUnifiedGroupInfo(nullptr);
            }
        }
        aggregateLocalSwitch_ = status;
    });
}

bool AdvancedNotificationService::IsDisableNotification(const std::string &bundleName)
{
    if (system::GetBoolParameter(PERSIST_EDM_NOTIFICATION_DISABLE, false)) {
        return true;
    }
    NotificationDisable notificationDisable;
    if (NotificationPreferences::GetInstance()->GetDisableNotificationInfo(notificationDisable)) {
        if (notificationDisable.GetDisabled()) {
            ANS_LOGD("get disabled is open");
            std::vector<std::string> bundleList = notificationDisable.GetBundleList();
            auto it = std::find(bundleList.begin(), bundleList.end(), bundleName);
            if (it != bundleList.end()) {
                return true;
            }
        }
    }
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetCurrentActiveUserId failed");
        return false;
    }
    if (NotificationPreferences::GetInstance()->GetUserDisableNotificationInfo(userId, notificationDisable)) {
        if (notificationDisable.GetDisabled()) {
            ANS_LOGD("get disabled is open");
            std::vector<std::string> bundleList = notificationDisable.GetBundleList();
            auto it = std::find(bundleList.begin(), bundleList.end(), bundleName);
            if (it != bundleList.end()) {
                return true;
            }
        }
    } else {
        ANS_LOGD("no disabled has been set up or set disabled to close");
    }
    return false;
}

bool AdvancedNotificationService::IsDisableNotificationByKiosk(const std::string &bundleName)
{
    bool isKioskMode = NotificationPreferences::GetInstance()->IsKioskMode();
    if (isKioskMode && !IsEnableNotificationByKioskAppTrustList(bundleName)) {
        return true;
    }
    return false;
}

bool AdvancedNotificationService::IsDisableNotificationForSaByKiosk(
    const std::string &bundleName, bool directAgency)
{
    bool isAppAgent = false;
    if (!directAgency && !bundleName.empty()) {
        isAppAgent = true;
    }
    bool isKioskMode = NotificationPreferences::GetInstance()->IsKioskMode();
    if (isKioskMode && isAppAgent && !IsEnableNotificationByKioskAppTrustList(bundleName)) {
        return true;
    }
    return false;
}

bool AdvancedNotificationService::IsEnableNotificationByKioskAppTrustList(const std::string &bundleName)
{
    std::vector<std::string> kioskAppTrustList;
    if (NotificationPreferences::GetInstance()->GetkioskAppTrustList(kioskAppTrustList)) {
        auto it = std::find(kioskAppTrustList.begin(), kioskAppTrustList.end(), bundleName);
        if (it != kioskAppTrustList.end()) {
            return true;
        }
    } else {
        ANS_LOGD("no kiosk app trust list has been set up");
    }
    return false;
}

bool AdvancedNotificationService::IsNeedToControllerByDisableNotification(const sptr<NotificationRequest> &request)
{
    if (request == nullptr) {
        ANS_LOGE("request is nullptr");
        return false;
    }
    if (request->IsAgentNotification()) {
        return true;
    }
    std::string bundleName = "";
    auto agentBundle = request->GetAgentBundle();
    if (agentBundle != nullptr) {
        bundleName = agentBundle->GetBundleName();
    }
    if (!(request->GetOwnerBundleName().empty()) && !bundleName.empty() &&
        NotificationPreferences::GetInstance()->IsAgentRelationship(bundleName, request->GetOwnerBundleName()) &&
        AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        return false;
    }
    return true;
}

void AdvancedNotificationService::SetAndPublishSubscriberExistFlag(const std::string& deviceType, bool existFlag)
{
    ANS_LOGD("called");
    if (deviceType.empty()) {
        ANS_LOGE("deviceType is empty");
        return;
    }

    auto result = NotificationPreferences::GetInstance()->SetSubscriberExistFlag(deviceType, existFlag);
    if (result != ERR_OK) {
        ANS_LOGE("SetSubscriberExistFlag failed");
        return;
    }

    bool headsetExistFlag = false;
    bool wearableExistFlag = false;
    if (deviceType == DEVICE_TYPE_HEADSET) {
        headsetExistFlag = existFlag;
        result =
            NotificationPreferences::GetInstance()->GetSubscriberExistFlag(DEVICE_TYPE_WEARABLE, wearableExistFlag);
        if (result != ERR_OK) {
            ANS_LOGE("GetSubscriberExistFlag failed");
            return;
        }
    } else if (deviceType == DEVICE_TYPE_WEARABLE) {
        wearableExistFlag = existFlag;
        result = NotificationPreferences::GetInstance()->GetSubscriberExistFlag(DEVICE_TYPE_HEADSET, headsetExistFlag);
        if (result != ERR_OK) {
            ANS_LOGE("GetSubscriberExistFlag failed");
            return;
        }
    }
    PublishSubscriberExistFlagEvent(headsetExistFlag, wearableExistFlag);
}

void AdvancedNotificationService::PublishSubscriberExistFlagEvent(bool headsetExistFlag, bool wearableExistFlag)
{
    ANS_LOGD("%{public}s, headsetExistFlag = %{public}d, wearableExistFlag = %{public}d", __FUNCTION__,
        headsetExistFlag, wearableExistFlag);
    EventFwk::Want want;
    want.SetParam("SUBSCRIBER_EXISTED_HEADSET", headsetExistFlag);
    want.SetParam("SUBSCRIBER_EXISTED_WEARABLE", wearableExistFlag);
    want.SetAction(NOTIFICATION_EVENT_SUBSCRIBER_STATUS);
    EventFwk::CommonEventData commonData { want, 0, "" };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    publishInfo.SetSubscriberType(EventFwk::SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetCurrentActiveUserId failed");
        return;
    }
    if (!EventFwk::CommonEventManager::PublishCommonEventAsUser(commonData, publishInfo, userId)) {
        ANS_LOGE("PublishCommonEventAsUser failed");
    }
}

ErrCode AdvancedNotificationService::RemoveAllNotificationsByBundleName(const std::string &bundleName, int32_t reason)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("called");

    if (bundleName.empty()) {
        std::string message = "bundle name is empty.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(8, 1).ErrorCode(ERR_ANS_INVALID_BUNDLE);
        ReportDeleteFailedEventPush(haMetaMessage, reason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is nullptr.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        ANS_LOGD("ffrt enter!");
        for (auto record : notificationList_) {
            if (record == nullptr) {
                ANS_LOGE("record is nullptr");
                continue;
            }
            if ((record->bundleOption->GetBundleName() == bundleName)
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                && record->deviceId.empty()
#endif
            ) {
                ProcForDeleteLiveView(record);
                removeList.push_back(record);
            }
        }

        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto record : removeList) {
            if (record == nullptr) {
                ANS_LOGE("record is nullptr");
                continue;
            }
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                ANS_LOGD("record->notification is not nullptr.");
                UpdateRecentNotification(record->notification, true, reason);
                notifications.emplace_back(record->notification);
                timerIds.emplace_back(record->notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                SendNotificationsOnCanceled(notifications, nullptr, reason);
            }

            TriggerRemoveWantAgent(record->request, reason, record->isThirdparty);
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, reason);
        }
        BatchCancelTimer(timerIds);
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetHashCodeRule(const uint32_t type)
{
    ANS_LOGD("called");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_8);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append("Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid != AVSEESAION_PID) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append("No permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }
    ErrCode result = NotificationPreferences::GetInstance()->SetHashCodeRule(uid, type);
    ANS_LOGI("SetHashCodeRule uid=%{public}d,type=%{public}d,result=%{public}d", uid, type, result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);

    return result;
}
}  // namespace Notification
}  // namespace OHOS
