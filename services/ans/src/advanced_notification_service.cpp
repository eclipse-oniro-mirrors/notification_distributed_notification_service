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

#include "advanced_notification_service.h"

#include <functional>
#include <iomanip>
#include <sstream>

#include "ability_context.h"
#include "ability_info.h"
#include "access_token_helper.h"
#include "accesstoken_kit.h"
#include "advanced_datashare_helper.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_watchdog.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "notification_extension_wrapper.h"
#include "notification_record.h"
#include "os_account_manager_helper.h"
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
#include "bundle_active_client.h"
#endif
#include "common_event_manager.h"
#include "common_event_support.h"
#include "event_report.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "notification_constant.h"
#include "notification_dialog_manager.h"
#include "notification_filter.h"
#include "notification_preferences.h"
#include "notification_request.h"
#include "notification_slot.h"
#include "notification_slot_filter.h"
#include "notification_subscriber_manager.h"
#include "notification_local_live_view_subscriber_manager.h"
#include "os_account_manager_helper.h"
#include "parameters.h"
#include "permission_filter.h"
#include "push_callback_proxy.h"
#include "trigger_info.h"
#include "want_agent_helper.h"
#include "notification_timer_info.h"
#include "time_service_client.h"
#include "notification_config_parse.h"
#include "want_params_wrapper.h"
#include "reminder_swing_decision_center.h"
#include "notification_extension_wrapper.h"

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

#include "advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {
namespace {

constexpr int32_t DEFAULT_RECENT_COUNT = 16;
constexpr int32_t DIALOG_DEFAULT_WIDTH = 400;
constexpr int32_t DIALOG_DEFAULT_HEIGHT = 240;
constexpr int32_t WINDOW_DEFAULT_WIDTH = 720;
constexpr int32_t WINDOW_DEFAULT_HEIGHT = 1280;
constexpr int32_t UI_HALF = 2;
constexpr int32_t MAX_LIVEVIEW_HINT_COUNT = 1;
constexpr int32_t MAX_SOUND_ITEM_LENGTH = 2048;
constexpr int32_t BUNDLE_OPTION_UID_DEFAULT_VALUE = 0;

const std::string NOTIFICATION_ANS_CHECK_SA_PERMISSION = "notification.ans.check.sa.permission";
const std::string MMS_BUNDLE_NAME = "com.ohos.mms";
const std::string CONTACTS_BUNDLE_NAME = "com.ohos.contacts";
const std::string DO_NOT_DISTURB_MODE = "1";
constexpr const char *KEY_UNIFIED_GROUP_ENABLE = "unified_group_enable";
}  // namespace

sptr<AdvancedNotificationService> AdvancedNotificationService::instance_;
std::mutex AdvancedNotificationService::instanceMutex_;
std::mutex AdvancedNotificationService::pushMutex_;
std::mutex AdvancedNotificationService::flowControlMutex_;
std::map<std::string, uint32_t> slotFlagsDefaultMap_;

std::map<NotificationConstant::SlotType, sptr<IPushCallBack>> AdvancedNotificationService::pushCallBacks_;
std::map<NotificationConstant::SlotType, sptr<NotificationCheckRequest>> AdvancedNotificationService::checkRequests_;
std::string AdvancedNotificationService::supportCheckSaPermission_ = "false";

ErrCode AdvancedNotificationService::PrepareNotificationRequest(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    std::string bundle = GetClientBundleName();
    if (bundle.empty()) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    if (request == nullptr) {
        ANSR_LOGE("NotificationRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }

    if (request->IsAgentNotification()) {
        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
            return ERR_ANS_NON_SYSTEM_APP;
        }

        if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) ||
            !CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
            return ERR_ANS_PERMISSION_DENIED;
        }

        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        int32_t uid = -1;
        if (request->GetOwnerUserId() != SUBSCRIBE_USER_INIT) {
            if (bundleManager != nullptr) {
                uid = bundleManager->GetDefaultUidByBundleName(request->GetOwnerBundleName(),
                request->GetOwnerUserId());
            }
            if (uid < 0) {
                return ERR_ANS_INVALID_UID;
            }
        } else {
            int32_t userId = SUBSCRIBE_USER_INIT;
            if (request->GetOwnerUid() < DEFAULT_UID) {
                return ERR_ANS_GET_ACTIVE_USER_FAILED;
            }
            if (request->GetOwnerUid() == DEFAULT_UID) {
                GetActiveUserId(userId);
                uid = bundleManager->GetDefaultUidByBundleName(request->GetOwnerBundleName(), userId);
            } else {
                uid = request->GetOwnerUid();
            }
        }
        request->SetOwnerUid(uid);
        // set agentBundle
        std::string bundle = "";
        if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
            bundle = GetClientBundleName();
            if (bundle.empty()) {
                ANS_LOGE("Failed to GetClientBundleName");
                return ERR_ANS_INVALID_BUNDLE;
            }
        }

        int32_t agentUid = IPCSkeleton::GetCallingUid();
        std::shared_ptr<NotificationBundleOption> agentBundle =
            std::make_shared<NotificationBundleOption>(bundle, agentUid);
        if (agentBundle == nullptr) {
            ANS_LOGE("Failed to create agentBundle instance");
            return ERR_ANS_INVALID_BUNDLE;
        }
        request->SetAgentBundle(agentBundle);
    } else {
        std::string sourceBundleName =
            request->GetBundleOption() == nullptr ? "" : request->GetBundleOption()->GetBundleName();
        if (!sourceBundleName.empty() && NotificationPreferences::GetInstance().IsAgentRelationship(
            bundle, sourceBundleName)) {
            ANS_LOGD("There is agent relationship between %{public}s and %{public}s",
                bundle.c_str(), sourceBundleName.c_str());
            if (request->GetBundleOption()->GetUid() < DEFAULT_UID) {
                return ERR_ANS_INVALID_UID;
            }
            int32_t uid = -1;
            if (request->GetBundleOption()->GetUid() == DEFAULT_UID) {
                int32_t userId = 0;
                GetActiveUserId(userId);
                std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
                if (bundleManager != nullptr) {
                    uid = bundleManager->GetDefaultUidByBundleName(sourceBundleName, userId);
                }
            } else {
                uid = request->GetBundleOption()->GetUid();
            }
            if (uid < 0) {
                return ERR_ANS_INVALID_UID;
            }
            request->SetOwnerUid(uid);
            bundle = sourceBundleName;
        }
        request->SetOwnerBundleName(bundle);
    }
    
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    request->SetCreatorPid(pid);
    if (request->GetOwnerUid() == DEFAULT_UID) {
        request->SetOwnerUid(uid);
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId);
    request->SetCreatorUserId(userId);
    request->SetCreatorBundleName(bundle);
    if (request->GetOwnerUserId() == SUBSCRIBE_USER_INIT) {
        int32_t ownerUserId = SUBSCRIBE_USER_INIT;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(request->GetOwnerUid(), ownerUserId);
        request->SetOwnerUserId(ownerUserId);
    }

    ErrCode result = CheckPictureSize(request);

    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }

    FillActionButtons(request);

#ifdef ENABLE_ANS_EXT_WRAPPER
    EXTENTION_WRAPPER->GetUnifiedGroupInfo(request);
#endif
    return result;
}

sptr<AdvancedNotificationService> AdvancedNotificationService::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);

    if (instance_ == nullptr) {
        instance_ = new (std::nothrow) AdvancedNotificationService();
        if (instance_ == nullptr) {
            ANS_LOGE("Failed to create AdvancedNotificationService instance");
            return nullptr;
        }
    }

    return instance_;
}

std::map<std::string, uint32_t>& AdvancedNotificationService::GetDefaultSlotConfig()
{
    return slotFlagsDefaultMap_;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
void AdvancedNotificationService::InitDistributeCallBack()
{
    DistributedNotificationManager::IDistributedCallback distributedCallback = {
        .OnPublish = std::bind(&AdvancedNotificationService::OnDistributedPublish,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnUpdate = std::bind(&AdvancedNotificationService::OnDistributedUpdate,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3),
        .OnDelete = std::bind(&AdvancedNotificationService::OnDistributedDelete,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            std::placeholders::_3,
            std::placeholders::_4),
    };
    DistributedNotificationManager::GetInstance()->RegisterCallback(distributedCallback);
}
#endif

AdvancedNotificationService::AdvancedNotificationService()
{
    ANS_LOGI("constructor");
    notificationSvrQueue_ = std::make_shared<ffrt::queue>("NotificationSvrMain");
    if (!notificationSvrQueue_) {
        ANS_LOGE("ffrt create failed!");
        return;
    }
    soundPermissionInfo_ = std::make_shared<SoundPermissionInfo>();
    recentInfo_ = std::make_shared<RecentInfo>();
    distributedKvStoreDeathRecipient_ = std::make_shared<DistributedKvStoreDeathRecipient>(
        std::bind(&AdvancedNotificationService::OnDistributedKvStoreDeathRecipient, this));
    permissonFilter_ = std::make_shared<PermissionFilter>();
    notificationSlotFilter_ = std::make_shared<NotificationSlotFilter>();
    StartFilters();

    std::function<void(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &)> callback =
        std::bind(&AdvancedNotificationService::OnSubscriberAdd, this, std::placeholders::_1);
    NotificationSubscriberManager::GetInstance()->RegisterOnSubscriberAddCallback(callback);

    std::function<void()> recoverFunc = std::bind(&AdvancedNotificationService::RecoverLiveViewFromDb, this);
    notificationSvrQueue_->submit(recoverFunc);
    
    ISystemEvent iSystemEvent = {
        std::bind(&AdvancedNotificationService::OnBundleRemoved, this, std::placeholders::_1),
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::bind(&AdvancedNotificationService::OnScreenOn, this),
        std::bind(&AdvancedNotificationService::OnScreenOff, this),
#endif
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
        std::bind(&AdvancedNotificationService::OnScreenLock, this),
        std::bind(&AdvancedNotificationService::OnScreenUnlock, this),
#endif
        std::bind(&AdvancedNotificationService::OnResourceRemove, this, std::placeholders::_1),
        std::bind(&AdvancedNotificationService::OnBundleDataCleared, this, std::placeholders::_1),
        std::bind(&AdvancedNotificationService::OnBundleDataAdd, this, std::placeholders::_1),
        std::bind(&AdvancedNotificationService::OnBundleDataUpdate, this, std::placeholders::_1),
        std::bind(&AdvancedNotificationService::OnBootSystemCompleted, this),
    };
    systemEventObserver_ = std::make_shared<SystemEventObserver>(iSystemEvent);

    dataManager_.RegisterKvStoreServiceDeathRecipient(distributedKvStoreDeathRecipient_);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    InitDistributeCallBack();
#endif
    supportCheckSaPermission_ = OHOS::system::GetParameter(NOTIFICATION_ANS_CHECK_SA_PERMISSION, "false");
}

AdvancedNotificationService::~AdvancedNotificationService()
{
    ANS_LOGI("deconstructor");
    dataManager_.UnRegisterKvStoreServiceDeathRecipient(distributedKvStoreDeathRecipient_);
    NotificationSubscriberManager::GetInstance()->UnRegisterOnSubscriberAddCallback();

    StopFilters();
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    DistributedNotificationManager::GetInstance()->UngegisterCallback();
#endif
    SelfClean();
    slotFlagsDefaultMap_.clear();
}

void AdvancedNotificationService::SelfClean()
{
    if (notificationSvrQueue_ != nullptr) {
        notificationSvrQueue_.reset();
    }

    NotificationSubscriberManager::GetInstance()->ResetFfrtQueue();
    DistributedNotificationManager::GetInstance()->ResetFfrtQueue();
    NotificationLocalLiveViewSubscriberManager::GetInstance()->ResetFfrtQueue();
}

ErrCode AdvancedNotificationService::AssignToNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    ErrCode result = ERR_OK;
    if (!IsNotificationExists(record->notification->GetKey())) {
        result = PublishFlowControl(record);
    } else {
        if (record->request->IsAlertOneTime()) {
            CloseAlert(record);
        }
        result = UpdateInNotificationList(record);
    }
    return result;
}

ErrCode AdvancedNotificationService::CancelPreparedNotification(
    int32_t notificationId, const std::string &label, const sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;
        result = RemoveFromNotificationList(bundleOption, label, notificationId, notification, true);
        if (result != ERR_OK) {
            return;
        }

        if (notification != nullptr) {
            int32_t reason = NotificationConstant::APP_CANCEL_REASON_DELETE;
            UpdateRecentNotification(notification, true, reason);
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete("", "", notification);
#endif
        }
    }));
    notificationSvrQueue_->wait(handler);
    SendCancelHiSysEvent(notificationId, label, bundleOption, result);
    return result;
}

ErrCode AdvancedNotificationService::PrepareNotificationInfo(
    const sptr<NotificationRequest> &request, sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (request == nullptr) {
        ANS_LOGE("request is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if ((request->GetSlotType() == NotificationConstant::SlotType::CUSTOM) &&
        !AccessTokenHelper::IsSystemApp() && !isSubsystem) {
        return ERR_ANS_NON_SYSTEM_APP;
    }
    ErrCode result = PrepareNotificationRequest(request);
    if (result != ERR_OK) {
        return result;
    }

    if (request->IsAgentNotification()) {
        bundleOption = new (std::nothrow) NotificationBundleOption(request->GetOwnerBundleName(),
            request->GetOwnerUid());
    } else {
        std::string sourceBundleName =
            request->GetBundleOption() == nullptr ? "" : request->GetBundleOption()->GetBundleName();
        if (!sourceBundleName.empty() && NotificationPreferences::GetInstance().IsAgentRelationship(
            GetClientBundleName(), sourceBundleName)) {
            ANS_LOGD("There is agent relationship between %{public}s and %{public}s",
                GetClientBundleName().c_str(), sourceBundleName.c_str());
            request->SetCreatorBundleName(request->GetOwnerBundleName());
            request->SetCreatorUid(request->GetOwnerUid());
            bundleOption = new (std::nothrow) NotificationBundleOption(request->GetOwnerBundleName(),
                request->GetOwnerUid());
        } else {
            bundleOption = GenerateBundleOption();
        }
    }

    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    ANS_LOGI(
        "bundleName=%{public}s, uid=%{public}d", (bundleOption->GetBundleName()).c_str(), bundleOption->GetUid());

    SetRequestBySlotType(request, bundleOption);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::StartFinishTimer(
    const std::shared_ptr<NotificationRecord> &record, int64_t expiredTimePoint)
{
    uint64_t timerId = StartAutoDelete(record->notification->GetKey(),
        expiredTimePoint, NotificationConstant::APP_CANCEL_REASON_OTHER);
    if (timerId == NotificationConstant::INVALID_TIMER_ID) {
        ANS_LOGE("Start finish auto delete timer failed.");
        return ERR_ANS_TASK_ERR;
    }
    record->notification->SetFinishTimer(timerId);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetFinishTimer(const std::shared_ptr<NotificationRecord> &record)
{
    int64_t maxExpiredTime = GetCurrentTime() + NotificationConstant::MAX_FINISH_TIME;
    auto result = StartFinishTimer(record, maxExpiredTime);
    if (result != ERR_OK) {
        return result;
    }
    record->request->SetFinishDeadLine(maxExpiredTime);
    return ERR_OK;
}

void AdvancedNotificationService::CancelFinishTimer(const std::shared_ptr<NotificationRecord> &record)
{
    record->request->SetFinishDeadLine(0);
    CancelTimer(record->notification->GetFinishTimer());
    record->notification->SetFinishTimer(NotificationConstant::INVALID_TIMER_ID);
}

ErrCode AdvancedNotificationService::StartUpdateTimer(
    const std::shared_ptr<NotificationRecord> &record, int64_t expireTimePoint)
{
    uint64_t timerId = StartAutoDelete(record->notification->GetKey(),
        expireTimePoint, NotificationConstant::APP_CANCEL_REASON_OTHER);
    if (timerId == NotificationConstant::INVALID_TIMER_ID) {
        ANS_LOGE("Start update auto delete timer failed.");
        return ERR_ANS_TASK_ERR;
    }
    record->notification->SetUpdateTimer(timerId);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetUpdateTimer(const std::shared_ptr<NotificationRecord> &record)
{
    int64_t maxExpiredTime = GetCurrentTime() + NotificationConstant::MAX_UPDATE_TIME;
    ErrCode result = StartUpdateTimer(record, maxExpiredTime);
    if (result != ERR_OK) {
        return result;
    }
    record->request->SetUpdateDeadLine(maxExpiredTime);
    return ERR_OK;
}

void AdvancedNotificationService::CancelUpdateTimer(const std::shared_ptr<NotificationRecord> &record)
{
    record->request->SetUpdateDeadLine(0);
    CancelTimer(record->notification->GetUpdateTimer());
    record->notification->SetUpdateTimer(NotificationConstant::INVALID_TIMER_ID);
}

void AdvancedNotificationService::StartArchiveTimer(const std::shared_ptr<NotificationRecord> &record)
{
    auto deleteTime = record->request->GetAutoDeletedTime();
    if (deleteTime == NotificationConstant::NO_DELAY_DELETE_TIME) {
        TriggerAutoDelete(record->notification->GetKey(), NotificationConstant::APP_CANCEL_REASON_DELETE);
        return;
    }
    if (deleteTime <= NotificationConstant::INVALID_AUTO_DELETE_TIME) {
        deleteTime = NotificationConstant::DEFAULT_AUTO_DELETE_TIME;
    }
    int64_t maxExpiredTime = GetCurrentTime() +
        NotificationConstant::SECOND_TO_MS * deleteTime;
    uint64_t timerId = StartAutoDelete(record->notification->GetKey(),
        maxExpiredTime, NotificationConstant::APP_CANCEL_REASON_DELETE);
    if (timerId == NotificationConstant::INVALID_TIMER_ID) {
        ANS_LOGE("Start archive auto delete timer failed.");
    }
    record->notification->SetArchiveTimer(timerId);
}

void AdvancedNotificationService::CancelArchiveTimer(const std::shared_ptr<NotificationRecord> &record)
{
    record->request->SetArchiveDeadLine(0);
    CancelTimer(record->notification->GetArchiveTimer());
    record->notification->SetArchiveTimer(NotificationConstant::INVALID_TIMER_ID);
}

ErrCode AdvancedNotificationService::FillNotificationRecord(
    const NotificationRequestDb &requestdbObj, std::shared_ptr<NotificationRecord> record)
{
    if (requestdbObj.request == nullptr || requestdbObj.bundleOption == nullptr || record == nullptr) {
        ANS_LOGE("Invalid param.");
        return ERR_ANS_INVALID_PARAM;
    }

    record->request = requestdbObj.request;
    record->notification = new (std::nothrow) Notification(requestdbObj.request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification.");
        return ERR_ANS_NO_MEMORY;
    }
    SetNotificationRemindType(record->notification, true);

    record->bundleOption = requestdbObj.bundleOption;
    ErrCode ret = AssignValidNotificationSlot(record, record->bundleOption);
    if (ret != ERR_OK) {
        ANS_LOGE("Assign valid notification slot failed!");
        return ret;
    }

    return ERR_OK;
}

std::shared_ptr<NotificationRecord> AdvancedNotificationService::MakeNotificationRecord(
    const sptr<NotificationRequest> &request, const sptr<NotificationBundleOption> &bundleOption)
{
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification.");
        return nullptr;
    }
    record->bundleOption = bundleOption;
    SetNotificationRemindType(record->notification, true);
    return record;
}

ErrCode AdvancedNotificationService::PublishPreparedNotification(const sptr<NotificationRequest> &request,
    const sptr<NotificationBundleOption> &bundleOption, bool isUpdateByOwner)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGI("PublishPreparedNotification");

    auto record = MakeNotificationRecord(request, bundleOption);
    bool isSystemApp = AccessTokenHelper::IsSystemApp();
    ErrCode result = CheckPublishPreparedNotification(record, isSystemApp);
    if (result != ERR_OK) {
        return result;
    }

    result = FlowControl(record);
    if (result != ERR_OK) {
        return result;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (DuplicateMsgControl(record->request) == ERR_ANS_DUPLICATE_MSG) {
            (void)PublishRemoveDuplicateEvent(record);
            return;
        }

        result = AddRecordToMemory(record, isSystemApp, isUpdateByOwner);
        if (result != ERR_OK) {
            return;
        }

        UpdateRecentNotification(record->notification, false, 0);
        UpdateSlotAuthInfo(record);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        ReportInfoToResourceSchedule(request->GetCreatorUserId(), bundleOption->GetBundleName());
        if (IsNeedNotifyConsumed(record->request)) {
            NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
        }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        if (!request->IsAgentNotification()) {
            DoDistributedPublish(bundleOption, record);
        }
#endif
        NotificationRequestDb requestDb = { .request = record->request, .bundleOption = bundleOption};
        UpdateNotificationTimerInfo(record);
        result = SetNotificationRequestToDb(requestDb);
        if (result != ERR_OK) {
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    // live view handled in UpdateNotificationTimerInfo, ignore here.
    if ((record->request->GetAutoDeletedTime() > GetCurrentTime()) && !record->request->IsCommonLiveView()) {
        StartAutoDelete(record->notification->GetKey(),
            record->request->GetAutoDeletedTime(), NotificationConstant::APP_CANCEL_REASON_DELETE);
    }
    return result;
}

void AdvancedNotificationService::QueryDoNotDisturbProfile(std::string &enable, std::string &profileId)
{
    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return;
    }
    Uri enableUri(datashareHelper->GetFocusModeEnableUri());
    bool ret = datashareHelper->Query(enableUri, KEY_FOCUS_MODE_ENABLE, enable);
    if (!ret) {
        ANS_LOGE("Query focus mode enable fail.");
        return;
    }
    if (enable != DO_NOT_DISTURB_MODE) {
        ANS_LOGI("Currently not is do not disturb mode.");
        return;
    }
    Uri idUri(datashareHelper->GetFocusModeProfileUri());
    ret = datashareHelper->Query(idUri, KEY_FOCUS_MODE_PROFILE, profileId);
    if (!ret) {
        ANS_LOGE("Query focus mode id fail.");
        return;
    }
}

void AdvancedNotificationService::CheckDoNotDisturbProfile(const std::shared_ptr<NotificationRecord> &record)
{
    ANS_LOGD("Called.");
    if (record == nullptr || record->notification == nullptr || record->bundleOption == nullptr) {
        ANS_LOGE("Make notification record failed.");
        return;
    }
    std::string enable;
    std::string profileId;
    QueryDoNotDisturbProfile(enable, profileId);
    if (enable != DO_NOT_DISTURB_MODE) {
        ANS_LOGD("Currently not is do not disturb mode.");
        return;
    }
    std::string bundleName = record->bundleOption->GetBundleName();
    ANS_LOGD("The bundle name is %{public}s", bundleName.c_str());
    if (bundleName == MMS_BUNDLE_NAME || bundleName == CONTACTS_BUNDLE_NAME) {
        ANS_LOGI("Currently in do not disturb mode, the bundle name is mms or contacts, keep reminder method.");
        return;
    }
    sptr<NotificationDoNotDisturbProfile> profile = new (std::nothrow) NotificationDoNotDisturbProfile();
    int32_t userId = record->notification->GetUserId();
    if (NotificationPreferences::GetInstance().GetDoNotDisturbProfile(atoi(profileId.c_str()), userId, profile) !=
        ERR_OK) {
        ANS_LOGE("Get do not disturb profile failed.");
        return;
    }
    if (profile == nullptr) {
        ANS_LOGE("The do not disturb profile is nullptr.");
        return;
    }
    auto uid = record->bundleOption->GetUid();
    ANS_LOGD("The uid is %{public}d", uid);
    std::vector<NotificationBundleOption> trustlist = profile->GetProfileTrustList();
    for (auto &trust : trustlist) {
        if ((bundleName == trust.GetBundleName()) &&
            (trust.GetUid() == BUNDLE_OPTION_UID_DEFAULT_VALUE || trust.GetUid() == uid)) {
            ANS_LOGW("Do not disturb profile bundle name is in trust.");
            return;
        }
    }
    DoNotDisturbUpdataReminderFlags(record);
}

void AdvancedNotificationService::DoNotDisturbUpdataReminderFlags(const std::shared_ptr<NotificationRecord> &record)
{
    ANS_LOGD("Called.");
    if (record == nullptr || record->request == nullptr || record->notification == nullptr) {
        ANS_LOGE("Make notification record failed.");
        return;
    }
    auto flags = record->request->GetFlags();
    if (flags == nullptr) {
        ANS_LOGE("The flags is nullptr.");
        return;
    }
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::CLOSE);
    record->notification->SetEnableSound(false);
    flags->SetLockScreenVisblenessEnabled(false);
    record->request->SetVisibleness(NotificationConstant::VisiblenessType::SECRET);
    flags->SetBannerEnabled(false);
    flags->SetLightScreenEnabled(false);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::CLOSE);
    record->notification->SetEnableVibration(false);
    flags->SetStatusIconEnabled(false);
}

ErrCode AdvancedNotificationService::UpdateSlotAuthInfo(const std::shared_ptr<NotificationRecord> &record)
{
    ErrCode result = ERR_OK;
    // only update auth info for LIVE_VIEW notification
    if (record->request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW) {
        sptr<NotificationSlot> slot = record->slot;
        // update authHintCnt when authorizedStatus is NOT_AUTHORIZED
        if (slot->GetAuthorizedStatus() == NotificationSlot::AuthorizedStatus::NOT_AUTHORIZED) {
            slot->AddAuthHintCnt();
        }
        // change authorizedStatus to AUTHORIZED when authHintCnt exceeds MAX_LIVEVIEW_HINT_COUNT
        if (slot->GetAuthHintCnt() > MAX_LIVEVIEW_HINT_COUNT) {
            slot->SetAuthorizedStatus(NotificationSlot::AuthorizedStatus::AUTHORIZED);
        }
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance().AddNotificationSlots(record->bundleOption, slots);
        ANS_LOGD("UpdateSlotAuthInfo status: %{public}d), cnt: %{public}d, res: %{public}d.",
            slot->GetAuthorizedStatus(), slot->GetAuthHintCnt(), result);
        if (result != ERR_OK) {
            ANS_LOGE("UpdateSlotAuthInfo failed result: %{public}d.", result);
        }
    }
    return result;
}

void AdvancedNotificationService::ReportInfoToResourceSchedule(const int32_t userId, const std::string &bundleName)
{
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    DeviceUsageStats::BundleActiveEvent event(DeviceUsageStats::BundleActiveEvent::NOTIFICATION_SEEN, bundleName);
    DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, userId);
#endif
}

bool AdvancedNotificationService::IsNotificationExists(const std::string &key)
{
    bool isExists = false;

    for (auto item : notificationList_) {
        if (item->notification->GetKey() == key) {
            isExists = true;
            break;
        }
    }

    return isExists;
}

ErrCode AdvancedNotificationService::Filter(const std::shared_ptr<NotificationRecord> &record, bool isRecover)
{
    ErrCode result = ERR_OK;

    if (!isRecover) {
        auto oldRecord = GetFromNotificationList(record->notification->GetKey());
        result = record->request->CheckNotificationRequest((oldRecord == nullptr) ? nullptr : oldRecord->request);
        if (result != ERR_OK) {
            ANS_LOGE("Notification(key %{public}s) isn't ready on publish failed with %{public}d.",
                record->notification->GetKey().c_str(), result);
            return result;
        }
    }

    if (permissonFilter_ == nullptr || notificationSlotFilter_ == nullptr) {
        ANS_LOGE("Filter is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    result = permissonFilter_->OnPublish(record);
    if (result != ERR_OK) {
        ANS_LOGE("Permission filter on publish failed with %{public}d.", result);
        return result;
    }

    result = notificationSlotFilter_->OnPublish(record);
    if (result != ERR_OK) {
        ANS_LOGE("Notification slot filter on publish failed with %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

void AdvancedNotificationService::ChangeNotificationByControlFlags(const std::shared_ptr<NotificationRecord> &record)
{
    ANS_LOGD("Called.");
    if (record == nullptr || record->request == nullptr || record->notification == nullptr) {
        ANS_LOGE("Make notification record failed.");
        return;
    }
    uint32_t notificationControlFlags = record->request->GetNotificationControlFlags();
    if (notificationControlFlags == 0) {
        ANS_LOGD("The notificationControlFlags is undefined.");
        return;
    }

    auto flags = record->request->GetFlags();
    if (flags == nullptr) {
        ANS_LOGE("The flags is nullptr.");
        return;
    }

    if (flags->IsSoundEnabled() == NotificationConstant::FlagStatus::OPEN &&
        (notificationControlFlags & NotificationConstant::ReminderFlag::SOUND_FLAG) != 0) {
        flags->SetSoundEnabled(NotificationConstant::FlagStatus::CLOSE);
        record->notification->SetEnableSound(false);
    }

    if (flags->IsLockScreenVisblenessEnabled() &&
        (notificationControlFlags & NotificationConstant::ReminderFlag::LOCKSCREEN_FLAG) != 0) {
        flags->SetLockScreenVisblenessEnabled(false);
        record->request->SetVisibleness(NotificationConstant::VisiblenessType::SECRET);
    }

    if (flags->IsBannerEnabled() && (notificationControlFlags & NotificationConstant::ReminderFlag::BANNER_FLAG) != 0) {
        flags->SetBannerEnabled(false);
    }

    if (flags->IsLightScreenEnabled() &&
        (notificationControlFlags & NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG) != 0) {
        flags->SetLightScreenEnabled(false);
    }

    if (flags->IsVibrationEnabled() == NotificationConstant::FlagStatus::OPEN &&
        (notificationControlFlags & NotificationConstant::ReminderFlag::VIBRATION_FLAG) != 0) {
        flags->SetVibrationEnabled(NotificationConstant::FlagStatus::CLOSE);
        record->notification->SetEnableVibration(false);
    }

    if (flags->IsStatusIconEnabled() &&
        (notificationControlFlags & NotificationConstant::ReminderFlag::STATUSBAR_ICON_FLAG) != 0) {
        flags->SetStatusIconEnabled(false);
    }
}

ErrCode AdvancedNotificationService::CheckPublishPreparedNotification(
    const std::shared_ptr<NotificationRecord> &record, bool isSystemApp)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (record == nullptr || record->request == nullptr) {
        ANS_LOGE("Make notification record failed.");
        return ERR_ANS_NO_MEMORY;
    }

    if (!isSystemApp && record->request->GetSlotType() == NotificationConstant::SlotType::EMERGENCY_INFORMATION) {
        ANS_LOGE("Non system app used illegal slot type.");
        return ERR_ANS_INVALID_PARAM;
    }

    return ERR_OK;
}

void AdvancedNotificationService::AddToNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    notificationList_.push_back(record);
    SortNotificationList();
}

ErrCode AdvancedNotificationService::UpdateInNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    RemoveExpired(flowControlUpdateTimestampList_, now);
    if (flowControlUpdateTimestampList_.size() >= MAX_UPDATE_NUM_PERSECOND) {
        return ERR_ANS_OVER_MAX_UPDATE_PERSECOND;
    }

    flowControlUpdateTimestampList_.push_back(now);
    auto iter = notificationList_.begin();
    while (iter != notificationList_.end()) {
        if ((*iter)->notification->GetKey() == record->notification->GetKey()) {
            record->request->FillMissingParameters((*iter)->request);
            FillLockScreenPicture(record->request, (*iter)->request);
            record->notification->SetUpdateTimer((*iter)->notification->GetUpdateTimer());
            record->notification->SetFinishTimer((*iter)->notification->GetFinishTimer());
            *iter = record;
            break;
        }
        iter++;
    }

    SortNotificationList();
    return ERR_OK;
}

void AdvancedNotificationService::SortNotificationList()
{
    notificationList_.sort(AdvancedNotificationService::NotificationCompare);
}

bool AdvancedNotificationService::NotificationCompare(
    const std::shared_ptr<NotificationRecord> &first, const std::shared_ptr<NotificationRecord> &second)
{
    // sorting notifications by create time
    return (first->request->GetCreateTime() < second->request->GetCreateTime());
}

void AdvancedNotificationService::StartFilters()
{
    if (permissonFilter_ != nullptr) {
        permissonFilter_->OnStart();
    }

    if (notificationSlotFilter_ != nullptr) {
        notificationSlotFilter_->OnStart();
    }
}

void AdvancedNotificationService::StopFilters()
{
    if (permissonFilter_ != nullptr) {
        permissonFilter_->OnStop();
    }

    if (notificationSlotFilter_ != nullptr) {
        notificationSlotFilter_->OnStop();
    }
}

ErrCode AdvancedNotificationService::GetActiveNotifications(std::vector<sptr<NotificationRequest>> &notifications)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        notifications.clear();
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid())) {
                notifications.push_back(record->request);
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetActiveNotificationNums(uint64_t &num)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("BundleOption is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        size_t count = 0;
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid())) {
                count += 1;
            }
        }
        num = static_cast<uint64_t>(count);
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetNotificationAgent(const std::string &agent)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::GetNotificationAgent(std::string &agent)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::GetBundleImportance(int32_t &importance)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("GenerateBundleOption failed.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = NotificationPreferences::GetInstance().GetImportance(bundleOption, importance);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::HasNotificationPolicyAccessPermission(bool &granted)
{
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetUnifiedGroupInfoFromDb(std::string &enable)
{
    auto datashareHelper = DelayedSingleton<AdvancedDatashareHelper>::GetInstance();
    if (datashareHelper == nullptr) {
        ANS_LOGE("The data share helper is nullptr.");
        return -1;
    }
    Uri enableUri(datashareHelper->GetUnifiedGroupEnableUri());
    bool ret = datashareHelper->Query(enableUri, KEY_UNIFIED_GROUP_ENABLE, enable);
    if (!ret) {
        ANS_LOGE("Query focus mode enable fail.");
        return -1;
    }

    return ERR_OK;
}

std::vector<std::string> AdvancedNotificationService::GetNotificationKeys(
    const sptr<NotificationBundleOption> &bundleOption)
{
    std::vector<std::string> keys;

    for (auto record : notificationList_) {
        if ((bundleOption != nullptr) && (record->bundleOption->GetUid() != bundleOption->GetUid())) {
            continue;
        }
        keys.push_back(record->notification->GetKey());
    }

    std::lock_guard<std::mutex> lock(delayNotificationMutext_);
    for (auto delayNotification : delayNotificationList_) {
        auto delayRequest = delayNotification.first->notification->GetNotificationRequest();
        if (delayRequest.GetOwnerUid() == bundleOption->GetUid()) {
            keys.push_back(delayNotification.first->notification->GetKey());
        }
    }

    return keys;
}

ErrCode AdvancedNotificationService::RemoveFromNotificationList(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &label, int32_t notificationId, sptr<Notification> &notification, bool isCancel)
{
    for (auto record : notificationList_) {
        if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
            (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
            (record->notification->GetLabel() == label) &&
            (record->notification->GetId() == notificationId)
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            && record->deviceId.empty()
#endif
        ) {
            if (!isCancel && !record->notification->IsRemoveAllowed()) {
                return ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED;
            }
            notification = record->notification;
            // delete or delete all, call the function
            if (!isCancel) {
                TriggerRemoveWantAgent(record->request);
            }

            ProcForDeleteLiveView(record);
            notificationList_.remove(record);
            return ERR_OK;
        }
    }

    std::lock_guard<std::mutex> lock(delayNotificationMutext_);
    for (auto delayNotification : delayNotificationList_) {
        if ((delayNotification.first->bundleOption->GetUid() == bundleOption->GetUid()) &&
            (delayNotification.first->notification->GetLabel() == label) &&
            (delayNotification.first->notification->GetId() == notificationId)) {
            CancelTimer(delayNotification.second);
            delayNotificationList_.remove(delayNotification);
            return ERR_OK;
        }
    }
    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

ErrCode AdvancedNotificationService::RemoveFromNotificationList(
    const std::string &key, sptr<Notification> &notification, bool isCancel, int32_t removeReason)
{
    for (auto record : notificationList_) {
        if (record->notification->GetKey() != key) {
            continue;
        }

        if (!isCancel && !record->notification->IsRemoveAllowed()) {
            return ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED;
        }
        notification = record->notification;
        // delete or delete all, call the function
        if (removeReason != NotificationConstant::CLICK_REASON_DELETE) {
            ProcForDeleteLiveView(record);
            if (!isCancel) {
                TriggerRemoveWantAgent(record->request);
            }
        }

        notificationList_.remove(record);
        return ERR_OK;
    }
    RemoveFromDelayedNotificationList(key);

    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

ErrCode AdvancedNotificationService::RemoveFromNotificationListForDeleteAll(
    const std::string &key, const int32_t &userId, sptr<Notification> &notification)
{
    for (auto record : notificationList_) {
        if ((record->notification->GetKey() == key) && (record->notification->GetUserId() == userId)) {
            if (!record->notification->IsRemoveAllowed()) {
                return ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED;
            }
            if (record->request->IsUnremovable()) {
                return ERR_ANS_NOTIFICATION_IS_UNREMOVABLE;
            }

            ProcForDeleteLiveView(record);

            notification = record->notification;
            notificationList_.remove(record);
            return ERR_OK;
        }
    }

    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

void AdvancedNotificationService::RemoveFromDelayedNotificationList(const std::string &key)
{
    std::lock_guard<std::mutex> lock(delayNotificationMutext_);
    for (auto delayNotification : delayNotificationList_) {
        if (delayNotification.first->notification->GetKey() == key) {
            CancelTimer(delayNotification.second);
            delayNotificationList_.remove(delayNotification);
            return;
        }
    }
}

std::shared_ptr<NotificationRecord> AdvancedNotificationService::GetFromNotificationList(const std::string &key)
{
    for (auto item : notificationList_) {
        if (item->notification->GetKey() == key) {
            return item;
        }
    }
    return nullptr;
}

std::shared_ptr<NotificationRecord> AdvancedNotificationService::GetFromNotificationList(
    const int32_t ownerUid, const int32_t notificationId)
{
    for (auto item : notificationList_) {
        auto oldRequest = item->notification->GetNotificationRequest();
        if (oldRequest.GetOwnerUid() == ownerUid &&
            oldRequest.GetNotificationId() == notificationId &&
            oldRequest.IsSystemLiveView() && oldRequest.IsUpdateByOwnerAllowed()) {
            return item;
        }
    }

    return nullptr;
}

std::shared_ptr<NotificationRecord> AdvancedNotificationService::GetFromDelayedNotificationList(
    const int32_t ownerUid, const int32_t notificationId)
{
    std::lock_guard<std::mutex> lock(delayNotificationMutext_);
    for (auto delayNotification : delayNotificationList_) {
        auto delayRequest = delayNotification.first->notification->GetNotificationRequest();
        if (delayRequest.GetOwnerUid() == ownerUid &&
            delayRequest.GetNotificationId() == notificationId &&
            delayRequest.IsSystemLiveView() && delayRequest.IsUpdateByOwnerAllowed()) {
            return delayNotification.first;
        }
    }

    return nullptr;
}

ErrCode AdvancedNotificationService::GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        notifications.clear();
        for (auto record : notificationList_) {
            if (record->notification != nullptr && record->notification->request_ != nullptr) {
                notifications.push_back(record->notification);
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

inline bool IsContained(const std::vector<std::string> &vec, const std::string &target)
{
    bool isContained = false;

    auto iter = vec.begin();
    while (iter != vec.end()) {
        if (*iter == target) {
            isContained = true;
            break;
        }
        iter++;
    }

    return isContained;
}

ErrCode AdvancedNotificationService::GetSpecialActiveNotifications(
    const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        for (auto record : notificationList_) {
            if (IsContained(key, record->notification->GetKey())) {
                notifications.push_back(record->notification);
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

std::shared_ptr<NotificationRecord> AdvancedNotificationService::GetRecordFromNotificationList(
    int32_t notificationId, int32_t uid, const std::string &label, const std::string &bundleName)
{
    for (auto &record : notificationList_) {
        if ((record->notification->GetLabel() == label) &&
            (record->notification->GetId() == notificationId) &&
            (record->bundleOption->GetUid() == uid) &&
            (record->bundleOption->GetBundleName() == bundleName)) {
            return record;
        }
    }
    return nullptr;
}

ErrCode AdvancedNotificationService::SetRecentNotificationCount(const std::string arg)
{
    ANS_LOGD("%{public}s arg = %{public}s", __FUNCTION__, arg.c_str());
    int32_t count = atoi(arg.c_str());
    if ((count < NOTIFICATION_MIN_COUNT) || (count > NOTIFICATION_MAX_COUNT)) {
        return ERR_ANS_INVALID_PARAM;
    }

    recentInfo_->recentCount = count;
    while (recentInfo_->list.size() > recentInfo_->recentCount) {
        recentInfo_->list.pop_back();
    }
    return ERR_OK;
}

void AdvancedNotificationService::UpdateRecentNotification(sptr<Notification> &notification,
    bool isDelete, int32_t reason)
{
    for (auto recentNotification : recentInfo_->list) {
        if (recentNotification->notification->GetKey() == notification->GetKey()) {
            if (!isDelete) {
                recentInfo_->list.remove(recentNotification);
                recentNotification->isActive = true;
                recentNotification->notification = notification;
                recentInfo_->list.emplace_front(recentNotification);
            } else {
                recentNotification->isActive = false;
                recentNotification->deleteReason = reason;
                recentNotification->deleteTime = GetNowSysTime();
            }
            return;
        }
    }

    if (!isDelete) {
        if (recentInfo_->list.size() >= recentInfo_->recentCount) {
            recentInfo_->list.pop_back();
        }
        auto recentNotification = std::make_shared<RecentNotification>();
        recentNotification->isActive = true;
        recentNotification->notification = notification;
        recentInfo_->list.emplace_front(recentNotification);
    }
}
static bool SortNotificationsByLevelAndTime(
    const std::shared_ptr<NotificationRecord> &first, const std::shared_ptr<NotificationRecord> &second)
{
    if (first->slot->GetLevel() != second->slot->GetLevel()) {
        return (first->slot->GetLevel() < second->slot->GetLevel());
    }
    return (first->request->GetCreateTime() < second->request->GetCreateTime());
}

ErrCode AdvancedNotificationService::FlowControl(const std::shared_ptr<NotificationRecord> &record)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(flowControlMutex_);
    RemoveExpired(flowControlTimestampList_, now);
    if (flowControlTimestampList_.size() >= MAX_ACTIVE_NUM_PERSECOND + MAX_UPDATE_NUM_PERSECOND) {
        return ERR_ANS_OVER_MAX_ACTIVE_PERSECOND;
    }
    flowControlTimestampList_.push_back(now);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::PublishFlowControl(const std::shared_ptr<NotificationRecord> &record)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    RemoveExpired(flowControlPublishTimestampList_, now);
    if (flowControlPublishTimestampList_.size() >= MAX_ACTIVE_NUM_PERSECOND) {
        return ERR_ANS_OVER_MAX_ACTIVE_PERSECOND;
    }

    flowControlPublishTimestampList_.push_back(now);

    std::list<std::shared_ptr<NotificationRecord>> bundleList;
    for (auto item : notificationList_) {
        if (record->notification->GetBundleName() == item->notification->GetBundleName()) {
            bundleList.push_back(item);
        }
    }

    std::shared_ptr<NotificationRecord> recordToRemove;
    if (bundleList.size() >= MAX_ACTIVE_NUM_PERAPP) {
        bundleList.sort(SortNotificationsByLevelAndTime);
        recordToRemove = bundleList.front();
        SendFlowControlOccurHiSysEvent(recordToRemove);
        RemoveNotificationList(bundleList.front());
    }

    if (notificationList_.size() >= MAX_ACTIVE_NUM) {
        if (bundleList.size() > 0) {
            bundleList.sort(SortNotificationsByLevelAndTime);
            recordToRemove = bundleList.front();
            SendFlowControlOccurHiSysEvent(recordToRemove);
            RemoveNotificationList(bundleList.front());
        } else {
            std::list<std::shared_ptr<NotificationRecord>> sorted = notificationList_;
            sorted.sort(SortNotificationsByLevelAndTime);
            recordToRemove = sorted.front();
            SendFlowControlOccurHiSysEvent(recordToRemove);
            RemoveNotificationList(sorted.front());
        }
    }

    AddToNotificationList(record);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::IsDistributedEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = DistributedPreferences::GetInstance()->GetDistributedEnable(enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::EnableDistributed(bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            result = DistributedPreferences::GetInstance()->SetDistributedEnable(enabled);
            ANS_LOGE("ffrt enter!");
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::EnableDistributedByBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Create bundle failed.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundle, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = DistributedPreferences::GetInstance()->SetDistributedBundleEnable(bundle, enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::EnableDistributedSelf(const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundleOption, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind(
        [&]() {
            ANS_LOGD("ffrt enter!");
            result = DistributedPreferences::GetInstance()->SetDistributedBundleEnable(bundleOption, enabled);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::IsDistributedEnableByBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Failed to create bundle.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundle, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        enabled = appInfoEnable;
        return ERR_OK;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = DistributedPreferences::GetInstance()->GetDistributedBundleEnable(bundle, enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDate(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    return SetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::GetDoNotDisturbDate(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    return GetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::GetHasPoppedDialog(
    const sptr<NotificationBundleOption> bundleOption, bool &hasPopped)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        result = NotificationPreferences::GetInstance().GetHasPoppedDialog(bundleOption, hasPopped);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    ANS_LOGD("userId: %{public}d, enabled: %{public}d", userId, enabled);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = DistributedPreferences::GetInstance()->SetSyncEnabledWithoutApp(userId, enabled);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    ANS_LOGD("userId: %{public}d", userId);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = DistributedPreferences::GetInstance()->GetSyncEnabledWithoutApp(userId, enabled);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

void AdvancedNotificationService::ResetPushCallbackProxy()
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> lock(pushMutex_);
    if (pushCallBacks_.empty()) {
        ANS_LOGE("invalid proxy state");
        return;
    }
    for (auto it = pushCallBacks_.begin(); it != pushCallBacks_.end(); it++) {
        if (it->second->AsObject() == nullptr) {
            ANS_LOGE("invalid proxy state");
        } else {
            it->second->AsObject()->RemoveDeathRecipient(pushRecipient_);
        }
    }
    pushCallBacks_.clear();
}

ErrCode AdvancedNotificationService::RegisterPushCallback(
    const sptr<IRemoteObject> &pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest)
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGW("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        ANS_LOGW("Not have OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER approval!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGW("Not have OHOS_PERMISSION_NOTIFICATION_CONTROLLER Permission!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (pushCallback == nullptr) {
        ANS_LOGW("pushCallback is null.");
        return ERR_INVALID_VALUE;
    }

    if (notificationCheckRequest == nullptr) {
        ANS_LOGW("notificationCheckRequest is null.");
        return ERR_INVALID_VALUE;
    }

    pushRecipient_ = new (std::nothrow) PushCallbackRecipient();
    if (!pushRecipient_) {
        ANS_LOGE("Failed to create death Recipient ptr PushCallbackRecipient!");
        return ERR_NO_INIT;
    }
    pushCallback->AddDeathRecipient(pushRecipient_);

    sptr<IPushCallBack> pushCallBack = iface_cast<IPushCallBack>(pushCallback);
    NotificationConstant::SlotType slotType = notificationCheckRequest->GetSlotType();
    int32_t uid = IPCSkeleton::GetCallingUid();

    if (pushCallBacks_.find(slotType) != pushCallBacks_.end()) {
        if (checkRequests_[slotType]->GetUid() != uid) {
            return ERROR_INTERNAL_ERROR;
        }
    }

    pushCallBacks_.insert_or_assign(slotType, pushCallBack);
    ANS_LOGD("insert pushCallBack, slot type %{public}d", slotType);
    notificationCheckRequest->SetUid(uid);
    checkRequests_.insert_or_assign(slotType, notificationCheckRequest);
    ANS_LOGD("insert notificationCheckRequest, slot type %{public}d, content type %{public}d",
        slotType, notificationCheckRequest->GetContentType());

    ANS_LOGD("end");
    return ERR_OK;
}

ErrCode AdvancedNotificationService::UnregisterPushCallback()
{
    if (!AccessTokenHelper::IsSystemApp()) {
        ANS_LOGW("Not system app!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        ANS_LOGW("Not have OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER Permission!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGW("Not have OHOS_PERMISSION_NOTIFICATION_CONTROLLER Permission!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (pushCallBacks_.empty()) {
        ANS_LOGE("The registration callback has not been processed yet.");
        return ERR_INVALID_OPERATION;
    }

    pushCallBacks_.clear();

    ANS_LOGD("end");
    return ERR_OK;
}

bool AdvancedNotificationService::IsNeedPushCheck(const sptr<NotificationRequest> &request)
{
    NotificationConstant::SlotType slotType = request->GetSlotType();
    NotificationContent::Type contentType = request->GetNotificationType();
    ANS_LOGD("NotificationRequest slotType:%{public}d, contentType:%{public}d", slotType, contentType);

    if (request->IsCommonLiveView()) {
        if (CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) &&
            CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
            ANS_LOGI("The creator has the permission, no need to check.");
            return false;
        }
        std::shared_ptr<NotificationContent> content = request->GetContent();
        auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
        auto status = liveViewContent->GetLiveViewStatus();
        if (status != NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE) {
            ANS_LOGI("Status of common live view is not create, no need to check.");
            return false;
        }
        ANS_LOGI("Common live view requires push check.");
        return true;
    }

    if (pushCallBacks_.find(slotType) == pushCallBacks_.end()) {
        ANS_LOGI("pushCallback Unregistered, no need to check.");
        return false;
    }

    if (contentType == checkRequests_[slotType]->GetContentType()) {
        ANS_LOGI("Need push check.");
        return true;
    }
    return false;
}

void AdvancedNotificationService::FillExtraInfoToJson(
    const sptr<NotificationRequest> &request, sptr<NotificationCheckRequest> &checkRequest, nlohmann::json &jsonObject)
{
    std::shared_ptr<NotificationContent> content = request->GetContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content->GetNotificationContent());
    auto extraInfo = liveViewContent->GetExtraInfo();
    if (extraInfo == nullptr) {
        return;
    }

    std::shared_ptr<AAFwk::WantParams> checkExtraInfo = std::make_shared<AAFwk::WantParams>();
    if (checkExtraInfo == nullptr) {
        return;
    }

    if (checkRequest->GetExtraKeys().size() == 0) {
        checkExtraInfo = extraInfo;
    } else {
        for (auto key : checkRequest->GetExtraKeys()) {
            if (extraInfo->HasParam(key)) {
                checkExtraInfo->SetParam(key, extraInfo->GetParam(key));
            }
        }
    }

    if (checkExtraInfo) {
        AAFwk::WantParamWrapper wWrapper(*checkExtraInfo);
        jsonObject["extraInfo"] = wWrapper.ToString();
    }
}

ErrCode AdvancedNotificationService::PushCheck(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("start.");
    if (pushCallBacks_.find(request->GetSlotType()) == pushCallBacks_.end()) {
        return ERR_ANS_PUSH_CHECK_UNREGISTERED;
    }
    sptr<IPushCallBack> pushCallBack = pushCallBacks_[request->GetSlotType()];
    sptr<NotificationCheckRequest> checkRequest = checkRequests_[request->GetSlotType()];
    if (request->GetCreatorUid() == checkRequest->GetUid()) {
        return ERR_OK;
    }

    nlohmann::json jsonObject;
    jsonObject["pkgName"] = request->GetCreatorBundleName();
    jsonObject["notifyId"] = request->GetNotificationId();
    jsonObject["contentType"] = static_cast<int32_t>(request->GetNotificationType());
    jsonObject["creatorUserId"] = request->GetCreatorUserId();
    jsonObject["slotType"] = static_cast<int32_t>(request->GetSlotType());
    jsonObject["label"] = request->GetLabel();
    if (request->IsCommonLiveView()) {
        FillExtraInfoToJson(request, checkRequest, jsonObject);
    }

    ErrCode result = pushCallBack->OnCheckNotification(jsonObject.dump(), nullptr);
    return result;
}

void AdvancedNotificationService::TriggerAutoDelete(const std::string &hashCode, int32_t reason)
{
    ANS_LOGD("Enter");

    for (const auto &record : notificationList_) {
        if (!record->request) {
            continue;
        }

        if (record->notification->GetKey() == hashCode) {
            UpdateRecentNotification(record->notification, true, reason);
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(record->notification, nullptr, reason);
            ProcForDeleteLiveView(record);
            notificationList_.remove(record);
            break;
        }
    }
}

bool AdvancedNotificationService::CreateDialogManager()
{
    static std::mutex dialogManagerMutex_;
    std::lock_guard<std::mutex> lock(dialogManagerMutex_);
    if (dialogManager_ == nullptr) {
        dialogManager_ = std::make_unique<NotificationDialogManager>(*this);
        if (!dialogManager_->Init()) {
            dialogManager_ = nullptr;
            return false;
        }
    }
    return true;
}

void AdvancedNotificationService::FillActionButtons(const sptr<NotificationRequest> &request)
{
    if (request->IsCoverActionButtons()) {
        ANS_LOGD("Cover old action buttons.");
        return;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        auto iter = notificationList_.begin();
        while (iter != notificationList_.end()) {
            if ((*iter)->request->GetKey() == request->GetKey()) {
                break;
            }
            iter++;
        }

        if (iter == notificationList_.end()) {
            ANS_LOGD("No old action buttons.");
            return;
        }

        for (auto actionButton : (*iter)->request->GetActionButtons()) {
            request->AddActionButton(actionButton);
        }
    }));
    notificationSvrQueue_->wait(handler);
}

bool AdvancedNotificationService::IsNeedNotifyConsumed(const sptr<NotificationRequest> &request)
{
    if (!request->IsCommonLiveView()) {
        return true;
    }

    auto content = request->GetContent()->GetNotificationContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    auto status = liveViewContent->GetLiveViewStatus();
    if (status != NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END) {
        return true;
    }

    auto deleteTime = request->GetAutoDeletedTime();
    return deleteTime != NotificationConstant::NO_DELAY_DELETE_TIME;
}

ErrCode AdvancedNotificationService::CheckSoundPermission(const sptr<NotificationRequest> &request,
    std::string bundleName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (request->GetSound().empty()) {
        ANS_LOGD("request sound length empty");
        return ERR_OK;
    }

    int32_t length = request->GetSound().length();
    if (length > MAX_SOUND_ITEM_LENGTH) {
        ANS_LOGE("Check sound length failed: %{public}d", length);
        return ERR_ANS_INVALID_PARAM;
    }

    // Update sound permission info cache
    ANS_LOGD("Check sound permission: %{public}d, %{public}s, %{public}d", length, bundleName.c_str(),
        soundPermissionInfo_->needUpdateCache_.load());
    if (soundPermissionInfo_->needUpdateCache_.load()) {
        std::lock_guard<std::mutex> lock(soundPermissionInfo_->dbMutex_);
        if (soundPermissionInfo_->needUpdateCache_.load()) {
            soundPermissionInfo_->allPackage_ = false;
            soundPermissionInfo_->bundleName_.clear();
            NotificationPreferences::GetInstance().GetBundleSoundPermission(
                soundPermissionInfo_->allPackage_, soundPermissionInfo_->bundleName_);
            soundPermissionInfo_->needUpdateCache_ = false;
        }
    }

    if (!soundPermissionInfo_->allPackage_ && soundPermissionInfo_->bundleName_.count(bundleName) == 0) {
        request->SetSound("");
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::AddRecordToMemory(
    const std::shared_ptr<NotificationRecord> &record, bool isSystemApp, bool isUpdateByOwner)
{
    auto result = AssignValidNotificationSlot(record, record->bundleOption);
    if (result != ERR_OK) {
        ANS_LOGE("Can not assign valid slot!");
        return result;
    }

    result = Filter(record);
    if (result != ERR_OK) {
        ANS_LOGE("Reject by filters: %{public}d", result);
        return result;
    }

    if (isSystemApp) {
        ChangeNotificationByControlFlags(record);
    }
    CheckDoNotDisturbProfile(record);

    if (isUpdateByOwner) {
        UpdateRecordByOwner(record, isSystemApp);
        RemoveFromDelayedNotificationList(record->notification->GetKey());
    }

    result = AssignToNotificationList(record);
    if (result != ERR_OK) {
        return result;
    }

    return ERR_OK;
}

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
ErrCode AdvancedNotificationService::RegisterSwingCallback(const sptr<IRemoteObject> &swingCallback)
{
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem) {
        ANS_LOGW("Not SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGW("Not have OHOS_PERMISSION_NOTIFICATION_CONTROLLER Permission!");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ReminderSwingDecisionCenter::GetInstance().RegisterSwingCallback(swingCallback);
}
#endif

void PushCallbackRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ANS_LOGI("Push Callback died, remove the proxy object");
    AdvancedNotificationService::GetInstance()->ResetPushCallbackProxy();
}

void AdvancedNotificationService::RemoveNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
#ifdef ENABLE_ANS_EXT_WRAPPER
    std::vector<sptr<Notification>> notifications;
    notifications.emplace_back(record->notification);
    EXTENTION_WRAPPER->UpdateByCancel(notifications, NotificationConstant::FLOW_CONTROL_REASON_DELETE);
#endif
    notificationList_.remove(record);
}

PushCallbackRecipient::PushCallbackRecipient() {}

PushCallbackRecipient::~PushCallbackRecipient() {}
}  // namespace Notification
}  // namespace OHOS
