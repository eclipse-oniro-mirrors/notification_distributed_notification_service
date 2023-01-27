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

#include "advanced_notification_service.h"

#include <functional>
#include <iomanip>
#include <sstream>

#include "ability_context.h"
#include "ability_info.h"
#include "access_token_helper.h"
#include "accesstoken_kit.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_watchdog.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
#include "bundle_active_client.h"
#endif
#include "common_event_manager.h"
#include "common_event_support.h"
#include "display_manager.h"
#include "event_report.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "notification_dialog.h"
#include "notification_filter.h"
#include "notification_preferences.h"
#include "notification_slot.h"
#include "notification_slot_filter.h"
#include "notification_subscriber_manager.h"
#include "os_account_manager.h"
#include "permission_filter.h"
#include "reminder_data_manager.h"
#include "trigger_info.h"
#include "ui_service_mgr_client.h"
#include "want_agent_helper.h"

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

namespace OHOS {
namespace Notification {
namespace {
constexpr char ACTIVE_NOTIFICATION_OPTION[] = "active";
constexpr char RECENT_NOTIFICATION_OPTION[] = "recent";
constexpr char HELP_NOTIFICATION_OPTION[] = "help";
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
constexpr char DISTRIBUTED_NOTIFICATION_OPTION[] = "distributed";
#endif
constexpr char SET_RECENT_COUNT_OPTION[] = "setRecentCount";
constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";

constexpr int32_t DEFAULT_RECENT_COUNT = 16;

constexpr int32_t HOURS_IN_ONE_DAY = 24;

constexpr int32_t DIALOG_DEFAULT_WIDTH = 400;
constexpr int32_t DIALOG_DEFAULT_HEIGHT = 240;
constexpr int32_t WINDOW_DEFAULT_WIDTH = 720;
constexpr int32_t WINDOW_DEFAULT_HEIGHT = 1280;
constexpr int32_t UI_HALF = 2;

constexpr char HIDUMPER_HELP_MSG[] =
    "Usage:dump <command> [options]\n"
    "Description::\n"
    "  --active, -a                 list all active notifications\n"
    "  --recent, -r                 list recent notifications\n";

constexpr char HIDUMPER_ERR_MSG[] =
    "error: unknown option.\nThe arguments are illegal and you can enter '-h' for help.";

const std::unordered_map<std::string, std::string> HIDUMPER_CMD_MAP = {
    { "--help", HELP_NOTIFICATION_OPTION },
    { "--active", ACTIVE_NOTIFICATION_OPTION },
    { "--recent", RECENT_NOTIFICATION_OPTION },
    { "-h", HELP_NOTIFICATION_OPTION },
    { "-a", ACTIVE_NOTIFICATION_OPTION },
    { "-r", RECENT_NOTIFICATION_OPTION },
};

struct RecentNotification {
    sptr<Notification> notification = nullptr;
    bool isActive = false;
    int32_t deleteReason = 0;
    int64_t deleteTime = 0;
};
}  // namespace

struct AdvancedNotificationService::RecentInfo {
    std::list<std::shared_ptr<RecentNotification>> list;
    size_t recentCount = DEFAULT_RECENT_COUNT;
};

sptr<AdvancedNotificationService> AdvancedNotificationService::instance_;
std::mutex AdvancedNotificationService::instanceMutex_;

static const std::shared_ptr<INotificationFilter> NOTIFICATION_FILTERS[] = {
    std::make_shared<PermissionFilter>(),
    std::make_shared<NotificationSlotFilter>(),
};

inline std::string GetClientBundleName()
{
    std::string bundle;

    int32_t callingUid = IPCSkeleton::GetCallingUid();

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        bundle = bundleManager->GetBundleNameByUid(callingUid);
    }

    return bundle;
}

inline bool IsSystemApp()
{
    bool isSystemApp = false;

    int32_t callingUid = IPCSkeleton::GetCallingUid();

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        isSystemApp = bundleManager->IsSystemApp(callingUid);
    }

    return isSystemApp || AccessTokenHelper::IsSystemHap();
}

inline int64_t ResetSeconds(int64_t date)
{
    auto milliseconds = std::chrono::milliseconds(date);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(milliseconds);
    auto tp_minutes = std::chrono::time_point_cast<std::chrono::minutes>(tp);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(tp_minutes.time_since_epoch());
    return duration.count();
}

inline int64_t GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

inline tm GetLocalTime(time_t time)
{
    struct tm ret = {0};
    localtime_r(&time, &ret);
    return ret;
}

inline ErrCode AssignValidNotificationSlot(const std::shared_ptr<NotificationRecord> &record)
{
    sptr<NotificationSlot> slot;
    NotificationConstant::SlotType slotType = record->request->GetSlotType();
    ErrCode result = NotificationPreferences::GetInstance().GetNotificationSlot(record->bundleOption, slotType, slot);
    if ((result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) ||
        (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST)) {
        slot = new NotificationSlot(slotType);
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance().AddNotificationSlots(record->bundleOption, slots);
    }
    if (result == ERR_OK) {
        if (slot != nullptr && slot->GetEnable()) {
            record->slot = slot;
        } else {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_ENABLED;
            ANS_LOGE("Type[%{public}d] slot enable closed", slotType);
        }
    }
    return result;
}

inline ErrCode CheckPictureSize(const sptr<NotificationRequest> &request)
{
    ErrCode result = ERR_OK;

    auto content = request->GetContent();
    if (content != nullptr && content->GetContentType() == NotificationContent::Type::PICTURE) {
        std::shared_ptr<NotificationPictureContent> pictureContent =
            std::static_pointer_cast<NotificationPictureContent>(content->GetNotificationContent());
        if (pictureContent != nullptr) {
            auto picture = pictureContent->GetBigPicture();
            if (picture != nullptr && static_cast<uint32_t>(picture->GetByteCount()) > MAX_PICTURE_SIZE) {
                result = ERR_ANS_PICTURE_OVER_SIZE;
            }
        }
    }

    auto littleIcon = request->GetLittleIcon();
    if (littleIcon != nullptr && static_cast<uint32_t>(littleIcon->GetByteCount()) > MAX_ICON_SIZE) {
        result = ERR_ANS_ICON_OVER_SIZE;
    }

    auto bigIcon = request->GetBigIcon();
    if (bigIcon != nullptr && static_cast<uint32_t>(bigIcon->GetByteCount()) > MAX_ICON_SIZE) {
        result = ERR_ANS_ICON_OVER_SIZE;
    }

    return result;
}

ErrCode AdvancedNotificationService::PrepareNotificationRequest(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    std::string bundle = GetClientBundleName();
    if (bundle.empty()) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (request->IsAgentNotification()) {
        if (!IsSystemApp()) {
            return ERR_ANS_NON_SYSTEM_APP;
        }

        if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) ||
            !CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
            return ERR_ANS_PERMISSION_DENIED;
        }

        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        int32_t uid = -1;
        if (bundleManager != nullptr) {
            uid = bundleManager->GetDefaultUidByBundleName(request->GetOwnerBundleName(), request->GetOwnerUserId());
        }
        if (uid < 0) {
            return ERR_ANS_INVALID_UID;
        }
        request->SetOwnerUid(uid);
    } else {
        request->SetOwnerBundleName(bundle);
    }
    request->SetCreatorBundleName(bundle);

    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    request->SetCreatorPid(pid);

    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    request->SetCreatorUserId(userId);
    ErrCode result = CheckPictureSize(request);

    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }

    return result;
}

sptr<AdvancedNotificationService> AdvancedNotificationService::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);

    if (instance_ == nullptr) {
        instance_ = new AdvancedNotificationService();
    }
    return instance_;
}

AdvancedNotificationService::AdvancedNotificationService()
{
    runner_ = OHOS::AppExecFwk::EventRunner::Create("NotificationSvrMain");
    handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner_);
    AnsWatchdog::AddHandlerThread(handler_, runner_);
    recentInfo_ = std::make_shared<RecentInfo>();
    distributedKvStoreDeathRecipient_ = std::make_shared<DistributedKvStoreDeathRecipient>(
        std::bind(&AdvancedNotificationService::OnDistributedKvStoreDeathRecipient, this));

    StartFilters();

    ISystemEvent iSystemEvent = {
        std::bind(&AdvancedNotificationService::OnBundleRemoved, this, std::placeholders::_1),
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::bind(&AdvancedNotificationService::OnScreenOn, this),
        std::bind(&AdvancedNotificationService::OnScreenOff, this),
#endif
        std::bind(&AdvancedNotificationService::OnResourceRemove, this, std::placeholders::_1),
        std::bind(&AdvancedNotificationService::OnBundleDataCleared, this, std::placeholders::_1),
    };
    systemEventObserver_ = std::make_shared<SystemEventObserver>(iSystemEvent);

    dataManager_.RegisterKvStoreServiceDeathRecipient(distributedKvStoreDeathRecipient_);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
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
#endif
}

AdvancedNotificationService::~AdvancedNotificationService()
{
    dataManager_.UnRegisterKvStoreServiceDeathRecipient(distributedKvStoreDeathRecipient_);

    StopFilters();
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    DistributedNotificationManager::GetInstance()->UngegisterCallback();
#endif
}

sptr<NotificationBundleOption> AdvancedNotificationService::GenerateBundleOption()
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string bundle = GetClientBundleName();
    if (bundle.empty()) {
        return nullptr;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    bundleOption = new NotificationBundleOption(bundle, uid);
    return bundleOption;
}

sptr<NotificationBundleOption> AdvancedNotificationService::GenerateValidBundleOption(
    const sptr<NotificationBundleOption> &bundleOption)
{
    sptr<NotificationBundleOption> validBundleOption = nullptr;
    if (bundleOption->GetUid() <= 0) {
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        if (bundleManager != nullptr) {
            int32_t activeUserId = -1;
            if (!GetActiveUserId(activeUserId)) {
                ANS_LOGE("Failed to get active user id!");
                return validBundleOption;
            }
            int32_t uid = bundleManager->GetDefaultUidByBundleName(bundleOption->GetBundleName(), activeUserId);
            if (uid > 0) {
                validBundleOption = new NotificationBundleOption(bundleOption->GetBundleName(), uid);
            }
        }
    } else {
        validBundleOption = bundleOption;
    }
    return validBundleOption;
}

ErrCode AdvancedNotificationService::AssignToNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    ErrCode result = ERR_OK;
    if (!IsNotificationExists(record->notification->GetKey())) {
        result = FlowControl(record);
    } else {
        if (record->request->IsAlertOneTime()) {
            record->notification->SetEnableLight(false);
            record->notification->SetEnableSound(false);
            record->notification->SetEnableVibration(false);
        }
        UpdateInNotificationList(record);
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
    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        sptr<Notification> notification = nullptr;
        result = RemoveFromNotificationList(bundleOption, label, notificationId, notification, true);
        if (result != ERR_OK) {
            return;
        }

        if (notification != nullptr) {
            int32_t reason = NotificationConstant::APP_CANCEL_REASON_DELETE;
            UpdateRecentNotification(notification, true, reason);
            sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete("", "", notification);
#endif
        }
    }));

    SendCancelHiSysEvent(notificationId, label, bundleOption, result);
    return result;
}

ErrCode AdvancedNotificationService::PrepareNotificationInfo(
    const sptr<NotificationRequest> &request, sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if ((request->GetSlotType() == NotificationConstant::SlotType::CUSTOM) && !IsSystemApp()) {
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
        bundleOption = GenerateBundleOption();
    }

    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    ANS_LOGI(
        "bundleName=%{public}s, uid=%{public}d", (bundleOption->GetBundleName()).c_str(), bundleOption->GetUid());
    return ERR_OK;
}

ErrCode AdvancedNotificationService::PublishPreparedNotification(
    const sptr<NotificationRequest> &request, const sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGI("PublishPreparedNotification");
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification.");
        return ERR_ANS_NO_MEMORY;
    }
    record->bundleOption = bundleOption;
    SetNotificationRemindType(record->notification, true);

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = AssignValidNotificationSlot(record);
        if (result != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
            return;
        }

        result = Filter(record);
        if (result != ERR_OK) {
            ANS_LOGE("Reject by filters: %{public}d", result);
            return;
        }

        result = AssignToNotificationList(record);
        if (result != ERR_OK) {
            return;
        }
        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        ReportInfoToResourceSchedule(request->GetCreatorUserId(), bundleOption->GetBundleName());
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        if (!request->IsAgentNotification()) {
            DoDistributedPublish(bundleOption, record);
        }
#endif
    }));
    return result;
}

ErrCode AdvancedNotificationService::Publish(const std::string &label, const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!request) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (isSubsystem) {
        return PublishNotificationBySa(request);
    }

    do {
        if (request->GetReceiverUserId() != SUBSCRIBE_USER_INIT && !IsSystemApp()) {
            result = ERR_ANS_NON_SYSTEM_APP;
            break;
        }

        Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
        if (AccessTokenHelper::IsDlpHap(callerToken)) {
            result = ERR_ANS_DLP_HAP;
            ANS_LOGE("DLP hap not allowed to send notifications");
            break;
        }

        sptr<NotificationBundleOption> bundleOption;
        result = PrepareNotificationInfo(request, bundleOption);
        if (result != ERR_OK) {
            break;
        }

        result = PublishPreparedNotification(request, bundleOption);
        if (result != ERR_OK) {
            break;
        }
    } while (0);

    SendPublishHiSysEvent(request, result);
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

ErrCode AdvancedNotificationService::Filter(const std::shared_ptr<NotificationRecord> &record)
{
    ErrCode result = ERR_OK;

    for (auto filter : NOTIFICATION_FILTERS) {
        result = filter->OnPublish(record);
        if (result != ERR_OK) {
            break;
        }
    }

    return result;
}

void AdvancedNotificationService::AddToNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    notificationList_.push_back(record);
    SortNotificationList();
}

void AdvancedNotificationService::UpdateInNotificationList(const std::shared_ptr<NotificationRecord> &record)
{
    auto iter = notificationList_.begin();
    while (iter != notificationList_.end()) {
        if ((*iter)->notification->GetKey() == record->notification->GetKey()) {
            *iter = record;
            break;
        }
        iter++;
    }

    SortNotificationList();
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

sptr<NotificationSortingMap> AdvancedNotificationService::GenerateSortingMap()
{
    std::vector<NotificationSorting> sortingList;
    for (auto record : notificationList_) {
        NotificationSorting sorting;
        sorting.SetRanking(static_cast<uint64_t>(sortingList.size()));
        sorting.SetKey(record->notification->GetKey());
        sorting.SetSlot(record->slot);
        sortingList.push_back(sorting);
    }

    sptr<NotificationSortingMap> sortingMap = new NotificationSortingMap(sortingList);

    return sortingMap;
}

void AdvancedNotificationService::StartFilters()
{
    for (auto filter : NOTIFICATION_FILTERS) {
        filter->OnStart();
    }
}

void AdvancedNotificationService::StopFilters()
{
    for (auto filter : NOTIFICATION_FILTERS) {
        filter->OnStop();
    }
}

ErrCode AdvancedNotificationService::Cancel(int32_t notificationId, const std::string &label)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    return CancelPreparedNotification(notificationId, label, bundleOption);
}

ErrCode AdvancedNotificationService::CancelAll()
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;

    handler_->PostSyncTask(std::bind([&]() {
        sptr<Notification> notification = nullptr;

        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            result = RemoveFromNotificationList(key, notification, true,
                NotificationConstant::APP_CANCEL_ALL_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::APP_CANCEL_ALL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
        }

        result = ERR_OK;
    }));
    return result;
}

ErrCode AdvancedNotificationService::CancelAsBundle(
    int32_t notificationId, const std::string &representativeBundle, int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) ||
        !CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t uid = -1;
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(representativeBundle, userId);
    }
    if (uid < 0) {
        return ERR_ANS_INVALID_UID;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
        representativeBundle, uid);
    return CancelPreparedNotification(notificationId, "", bundleOption);
}

ErrCode AdvancedNotificationService::AddSlots(const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (slots.size() == 0) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        std::vector<sptr<NotificationSlot>> addSlots;
        for (auto slot : slots) {
            sptr<NotificationSlot> originalSlot;
            result =
                NotificationPreferences::GetInstance().GetNotificationSlot(bundleOption, slot->GetType(), originalSlot);
            if ((result == ERR_OK) && (originalSlot != nullptr)) {
                continue;
            } else {
                addSlots.push_back(slot);
            }
        }

        if (addSlots.size() == 0) {
            result = ERR_OK;
        } else {
            result = NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption, addSlots);
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetSlots(std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().GetNotificationAllSlots(bundleOption, slots);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            slots.clear();
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetActiveNotifications(std::vector<sptr<NotificationRequest>> &notifications)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        notifications.clear();
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid())) {
                notifications.push_back(record->request);
            }
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetActiveNotificationNums(uint64_t &num)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        size_t count = 0;
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid())) {
                count += 1;
            }
        }
        num = static_cast<uint64_t>(count);
    }));
    return result;
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

ErrCode AdvancedNotificationService::PublishAsBundle(
    const sptr<NotificationRequest> notification, const std::string &representativeBundle)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::SetNotificationBadgeNum(int32_t num)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(
        std::bind([&]() { result = NotificationPreferences::GetInstance().SetTotalBadgeNums(bundleOption, num); }));
    return result;
}

ErrCode AdvancedNotificationService::GetBundleImportance(int32_t &importance)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(
        std::bind([&]() { result = NotificationPreferences::GetInstance().GetImportance(bundleOption, importance); }));
    return result;
}

ErrCode AdvancedNotificationService::HasNotificationPolicyAccessPermission(bool &granted)
{
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetPrivateNotificationsAllowed(bool allow)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().SetPrivateNotificationsAllowed(bundleOption, allow);
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetPrivateNotificationsAllowed(bool &allow)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().GetPrivateNotificationsAllowed(bundleOption, allow);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            allow = false;
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::Delete(const std::string &key, int32_t removeReason)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;

    handler_->PostSyncTask(std::bind([&]() {
        sptr<Notification> notification = nullptr;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::string deviceId;
        std::string bundleName;
        GetDistributedInfo(key, deviceId, bundleName);
#endif
        result = RemoveFromNotificationList(key, notification, false, removeReason);
        if (result != ERR_OK) {
            return;
        }

        if (notification != nullptr) {
            UpdateRecentNotification(notification, true, removeReason);
            sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, removeReason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
        }
    }));

    return result;
}

ErrCode AdvancedNotificationService::DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        std::vector<std::string> keys = GetNotificationKeys(bundle);
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            result = RemoveFromNotificationList(key, notification, false, NotificationConstant::CANCEL_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
        }

        result = ERR_OK;
    }));

    return result;
}

ErrCode AdvancedNotificationService::DeleteAll()
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        int32_t activeUserId = SUBSCRIBE_USER_INIT;
        (void)GetActiveUserId(activeUserId);
        std::vector<std::string> keys = GetNotificationKeys(nullptr);
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            result = RemoveFromNotificationListForDeleteAll(key, activeUserId, notification);
            if ((result != ERR_OK) || (notification == nullptr)) {
                continue;
            }

            if (notification->GetUserId() == activeUserId) {
                int32_t reason = NotificationConstant::CANCEL_ALL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
        }

        result = ERR_OK;
    }));

    return result;
}

std::vector<std::string> AdvancedNotificationService::GetNotificationKeys(
    const sptr<NotificationBundleOption> &bundleOption)
{
    std::vector<std::string> keys;

    for (auto record : notificationList_) {
        if ((bundleOption != nullptr) && (record->bundleOption->GetBundleName() != bundleOption->GetBundleName()) &&
            (record->bundleOption->GetUid() != bundleOption->GetUid())) {
            continue;
        }
        keys.push_back(record->notification->GetKey());
    }

    return keys;
}

ErrCode AdvancedNotificationService::GetSlotsByBundle(
    const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().GetNotificationAllSlots(bundle, slots);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            slots.clear();
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::UpdateSlots(
    const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().UpdateNotificationSlots(bundle, slots);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST;
        }
    }));

    if (result == ERR_OK) {
        PublishSlotChangeCommonEvent(bundle);
    }

    return result;
}

ErrCode AdvancedNotificationService::SetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(
        std::bind([&]() { result = NotificationPreferences::GetInstance().SetShowBadge(bundle, enabled); }));
    return result;
}

ErrCode AdvancedNotificationService::GetShowBadgeEnabledForBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().IsShowBadge(bundle, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetShowBadgeEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().IsShowBadge(bundleOption, enabled);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    return result;
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
            notificationList_.remove(record);
            return ERR_OK;
        }
    }

    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

ErrCode AdvancedNotificationService::RemoveFromNotificationList(
    const std::string &key, sptr<Notification> &notification, bool isCancel, int32_t removeReason)
{
    for (auto record : notificationList_) {
        if (record->notification->GetKey() == key) {
            if (!isCancel && !record->notification->IsRemoveAllowed()) {
                return ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED;
            }
            notification = record->notification;
            // delete or delete all, call the function
            if (!isCancel && removeReason != NotificationConstant::CLICK_REASON_DELETE) {
                TriggerRemoveWantAgent(record->request);
            }
            notificationList_.remove(record);
            return ERR_OK;
        }
    }

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
            notification = record->notification;
            notificationList_.remove(record);
            return ERR_OK;
        }
    }

    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

ErrCode AdvancedNotificationService::Subscribe(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    ErrCode errCode = ERR_OK;
    do {
        if (subscriber == nullptr) {
            errCode = ERR_ANS_INVALID_PARAM;
            break;
        }

        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!IsSystemApp() && !isSubsystem) {
            ANS_LOGE("Client is not a system app or subsystem");
            errCode = ERR_ANS_NON_SYSTEM_APP;
            break;
        }

        if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
            errCode = ERR_ANS_PERMISSION_DENIED;
            break;
        }

        errCode = NotificationSubscriberManager::GetInstance()->AddSubscriber(subscriber, info);
        if (errCode != ERR_OK) {
            break;
        }
    } while (0);

    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info, errCode);
    return errCode;
}

ErrCode AdvancedNotificationService::Unsubscribe(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    SendUnSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!IsSystemApp() && !isSubsystem) {
        ANS_LOGE("Client is not a system app or subsystem");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (subscriber == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode errCode = NotificationSubscriberManager::GetInstance()->RemoveSubscriber(subscriber, info);
    if (errCode != ERR_OK) {
        return errCode;
    }

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetSlotByType(
    const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    handler_->PostSyncTask(std::bind([&]() {
        NotificationPreferences::GetInstance().GetNotificationSlot(bundleOption, slotType, slot);
    }));
    // if get slot failed, it still return ok.
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveSlotByType(const NotificationConstant::SlotType &slotType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    handler_->PostSyncTask(std::bind([&]() {
        NotificationPreferences::GetInstance().RemoveNotificationSlot(bundleOption, slotType);
    }));
    // if remove slot failed, it still return ok.
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!IsSystemApp() && !isSubsystem) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        notifications.clear();
        for (auto record : notificationList_) {
            if (record->notification != nullptr) {
                notifications.push_back(record->notification);
            }
        }
    }));
    return result;
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

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        for (auto record : notificationList_) {
            if (IsContained(key, record->notification->GetKey())) {
                notifications.push_back(record->notification);
            }
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string &deviceId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    ErrCode result = ERR_OK;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGD("bundleOption == nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }

    // To get the permission
    bool allowedNotify = false;
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    ANS_LOGI("result = %{public}d, allowedNotify = %{public}d", result, allowedNotify);
    if (result != ERR_OK || allowedNotify) {
        ANS_LOGD("Already granted permission");
        return result;
    }
    
    // Check to see if it has been popover before
    bool hasPopped = false;
    result = GetHasPoppedDialog(bundleOption, hasPopped);
    if (result != ERR_OK || hasPopped) {
        ANS_LOGD("Already shown dialog");
        return result;
    }
    
    ANS_LOGI("hasPopped = %{public}d, allowedNotify = %{public}d", hasPopped, allowedNotify);
    if (!hasPopped && !allowedNotify) {
        auto notificationDialog = std::make_shared<NotificationDialog>();
        result = notificationDialog->StartEnableNotificationDialogAbility();
        if (result != ERR_OK) {
            ANS_LOGD("StartEnableNotificationDialogAbility failed, result = %{public}d", result);
            return result;
        }
    }
    SetHasPoppedDialog(bundleOption, true);
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        if (deviceId.empty()) {
            // Local device
            result = NotificationPreferences::GetInstance().SetNotificationsEnabled(userId, enabled);
        } else {
            // Remote device
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForSpecialBundle(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    sptr<EnabledNotificationCallbackData> bundleData =
        new EnabledNotificationCallbackData(bundle->GetBundleName(), bundle->GetUid(), enabled);

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        if (deviceId.empty()) {
            // Local device
            result = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundle, enabled);
            if (!enabled) {
                result = RemoveAllNotifications(bundle);
            }
            if (result == ERR_OK) {
                NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
                PublishSlotChangeCommonEvent(bundle);
            }
        } else {
            // Remote revice
        }
    }));

    SendEnableNotificationHiSysEvent(bundleOption, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotify(bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        allowed = false;
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
    }));
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    return IsAllowedNotifySelf(bundleOption, allowed);
}

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(const sptr<NotificationBundleOption> &bundleOption,
    bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        allowed = false;
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
        if (result == ERR_OK && allowed) {
            result = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(bundleOption, allowed);
            if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
                result = ERR_OK;
                allowed = CheckApiCompatibility(bundleOption);
                SetNotificationsEnabledForSpecialBundle("", bundleOption, allowed);
            }
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetAppTargetBundle(const sptr<NotificationBundleOption> &bundleOption,
    sptr<NotificationBundleOption> &targetBundle)
{
    sptr<NotificationBundleOption> clientBundle = GenerateBundleOption();
    if (clientBundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (bundleOption == nullptr) {
        targetBundle = clientBundle;
    } else {
        if ((clientBundle->GetBundleName() == bundleOption->GetBundleName()) &&
            (clientBundle->GetUid() == bundleOption->GetUid())) {
            targetBundle = bundleOption;
        } else {
            if (!IsSystemApp()) {
                return ERR_ANS_NON_SYSTEM_APP;
            }
            targetBundle = GenerateValidBundleOption(bundleOption);
        }
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::IsSpecialBundleAllowedNotify(
    const sptr<NotificationBundleOption> &bundleOption, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> targetBundle = nullptr;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (isSubsystem) {
        if (bundleOption != nullptr) {
            targetBundle = GenerateValidBundleOption(bundleOption);
        }
    } else {
        ErrCode result = GetAppTargetBundle(bundleOption, targetBundle);
        if (result != ERR_OK) {
            return result;
        }
    }

    if (targetBundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        allowed = false;
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
        if (result == ERR_OK && allowed) {
            result = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(targetBundle, allowed);
            if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
                result = ERR_OK;
                allowed = CheckApiCompatibility(targetBundle);
                SetNotificationsEnabledForSpecialBundle("", bundleOption, allowed);
            }
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::PublishContinuousTaskNotification(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        return ERR_ANS_NOT_SYSTEM_SERVICE;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    request->SetCreatorUserId(userId);
    ANS_LOGD("%{public}s, uid=%{public}d userId=%{public}d", __FUNCTION__, uid, userId);

    if (request->GetCreatorBundleName().empty()) {
        request->SetCreatorBundleName(FOUNDATION_BUNDLE_NAME);
    }

    if (request->GetOwnerBundleName().empty()) {
        request->SetOwnerBundleName(FOUNDATION_BUNDLE_NAME);
    }

    sptr<NotificationBundleOption> bundleOption = nullptr;
    bundleOption = new NotificationBundleOption(std::string(), uid);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = PrepareContinuousTaskNotificationRequest(request, uid);
    if (result != ERR_OK) {
        return result;
    }
    request->SetUnremovable(true);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = new Notification(request);
    if (record->notification != nullptr) {
        record->notification->SetSourceType(NotificationConstant::SourceType::TYPE_CONTINUOUS);
    }

    handler_->PostSyncTask(std::bind([&]() {
        if (!IsNotificationExists(record->notification->GetKey())) {
            AddToNotificationList(record);
        } else {
            if (record->request->IsAlertOneTime()) {
                record->notification->SetEnableLight(false);
                record->notification->SetEnableSound(false);
                record->notification->SetEnableVibration(false);
            }
            UpdateInNotificationList(record);
        }

        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    }));

    return result;
}

ErrCode AdvancedNotificationService::CancelContinuousTaskNotification(const std::string &label, int32_t notificationId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        return ERR_ANS_NOT_SYSTEM_SERVICE;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        sptr<Notification> notification = nullptr;
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName().empty()) && (record->bundleOption->GetUid() == uid) &&
                (record->notification->GetId() == notificationId) && (record->notification->GetLabel() == label)) {
                notification = record->notification;
                notificationList_.remove(record);
                result = ERR_OK;
                break;
            }
        }
        if (notification != nullptr) {
            int32_t reason = NotificationConstant::APP_CANCEL_REASON_DELETE;
            UpdateRecentNotification(notification, true, reason);
            sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::PublishReminder(sptr<ReminderRequest> &reminder)
{
    ANSR_LOGI("Publish reminder");
    if (!reminder) {
        ANSR_LOGE("ReminderRequest object is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }

    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    ErrCode result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        callerToken, "ohos.permission.PUBLISH_AGENT_REMINDER");
    if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        ANSR_LOGW("Permission denied: ohos.permission.PUBLISH_AGENT_REMINDER");
        return ERR_REMINDER_PERMISSION_DENIED;
    }

    sptr<NotificationRequest> notificationRequest = reminder->GetNotificationRequest();
    sptr<NotificationBundleOption> bundleOption = nullptr;
    result = PrepareNotificationInfo(notificationRequest, bundleOption);
    if (result != ERR_OK) {
        ANSR_LOGW("PrepareNotificationInfo fail");
        return result;
    }
    bool allowedNotify = false;
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (result != ERR_OK || !allowedNotify) {
        ANSR_LOGW("The application does not request enable notification");
        return ERR_REMINDER_NOTIFICATION_NOT_ENABLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    return rdm->PublishReminder(reminder, bundleOption);
}

ErrCode AdvancedNotificationService::CancelReminder(const int32_t reminderId)
{
    ANSR_LOGI("Cancel Reminder");
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    return rdm->CancelReminder(reminderId, bundleOption);
}

ErrCode AdvancedNotificationService::CancelAllReminders()
{
    ANSR_LOGI("Cancel all reminders");
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    int32_t userId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    return rdm->CancelAllReminders(bundleOption->GetBundleName(), userId);
}

ErrCode AdvancedNotificationService::GetValidReminders(std::vector<sptr<ReminderRequest>> &reminders)
{
    ANSR_LOGI("GetValidReminders");
    reminders.clear();
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    auto rdm = ReminderDataManager::GetInstance();
    if (rdm == nullptr) {
        return ERR_NO_INIT;
    }
    rdm->GetValidReminders(bundleOption, reminders);
    ANSR_LOGD("Valid reminders size=%{public}zu", reminders.size());
    return ERR_OK;
}

ErrCode AdvancedNotificationService::ActiveNotificationDump(const std::string& bundle, int32_t userId,
    std::vector<std::string> &dumpInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::stringstream stream;
    for (const auto &record : notificationList_) {
        if (record->notification == nullptr || record->request == nullptr) {
            continue;
        }
        if (userId != SUBSCRIBE_USER_INIT && userId != record->notification->GetUserId()) {
            continue;
        }
        if (!bundle.empty() && bundle != record->notification->GetBundleName()) {
            continue;
        }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        if (!record->deviceId.empty()) {
            continue;
        }
#endif
        stream.clear();
        stream.str("");
        stream << "\tUserId: " << record->notification->GetUserId() << "\n";
        stream << "\tCreatePid: " << record->request->GetCreatorPid() << "\n";
        stream << "\tOwnerBundleName: " << record->notification->GetBundleName() << "\n";
        if (record->request->GetOwnerUid() > 0) {
            stream << "\tOwnerUid: " << record->request->GetOwnerUid() << "\n";
        } else {
            stream << "\tOwnerUid: " << record->request->GetCreatorUid() << "\n";
        }
        stream << "\tDeliveryTime = " << TimeToString(record->request->GetDeliveryTime()) << "\n";
        stream << "\tNotification:\n";
        stream << "\t\tId: " << record->notification->GetId() << "\n";
        stream << "\t\tLabel: " << record->notification->GetLabel() << "\n";
        stream << "\t\tSlotType = " << record->request->GetSlotType() << "\n";
        dumpInfo.push_back(stream.str());
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RecentNotificationDump(const std::string& bundle, int32_t userId,
    std::vector<std::string> &dumpInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::stringstream stream;
    for (auto recentNotification : recentInfo_->list) {
        if (recentNotification->notification == nullptr) {
            continue;
        }
        const auto &notificationRequest = recentNotification->notification->GetNotificationRequest();
        if (userId != SUBSCRIBE_USER_INIT && userId != notificationRequest.GetOwnerUserId()) {
            continue;
        }
        if (!bundle.empty() && bundle != recentNotification->notification->GetBundleName()) {
            continue;
        }
        stream.clear();
        stream.str("");
        stream << "\tUserId: " << notificationRequest.GetCreatorUserId() << "\n";
        stream << "\tCreatePid: " << notificationRequest.GetCreatorPid() << "\n";
        stream << "\tBundleName: " << recentNotification->notification->GetBundleName() << "\n";
        if (notificationRequest.GetOwnerUid() > 0) {
            stream << "\tOwnerUid: " << notificationRequest.GetOwnerUid() << "\n";
        } else {
            stream << "\tOwnerUid: " << notificationRequest.GetCreatorUid() << "\n";
        }
        stream << "\tDeliveryTime = " << TimeToString(notificationRequest.GetDeliveryTime()) << "\n";
        if (!recentNotification->isActive) {
            stream << "\tDeleteTime: " << TimeToString(recentNotification->deleteTime) << "\n";
            stream << "\tDeleteReason: " << recentNotification->deleteReason << "\n";
        }
        stream << "\tNotification:\n";
        stream << "\t\tId: " << recentNotification->notification->GetId() << "\n";
        stream << "\t\tLabel: " << recentNotification->notification->GetLabel() << "\n";
        stream << "\t\tSlotType = " << notificationRequest.GetSlotType() << "\n";
        dumpInfo.push_back(stream.str());
    }
    return ERR_OK;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
ErrCode AdvancedNotificationService::DistributedNotificationDump(const std::string& bundle, int32_t userId,
    std::vector<std::string> &dumpInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::stringstream stream;
    for (auto record : notificationList_) {
        if (record->notification == nullptr) {
            continue;
        }
        if (userId != SUBSCRIBE_USER_INIT && userId != record->notification->GetUserId()) {
            continue;
        }
        if (!bundle.empty() && bundle != record->notification->GetBundleName()) {
            continue;
        }
        if (record->deviceId.empty()) {
            continue;
        }
        stream.clear();
        stream.str("");
        stream << "\tUserId: " << record->notification->GetUserId() << "\n";
        stream << "\tCreatePid: " << record->request->GetCreatorPid() << "\n";
        stream << "\tOwnerBundleName: " << record->notification->GetBundleName() << "\n";
        if (record->request->GetOwnerUid() > 0) {
            stream << "\tOwnerUid: " << record->request->GetOwnerUid() << "\n";
        } else {
            stream << "\tOwnerUid: " << record->request->GetCreatorUid() << "\n";
        }
        stream << "\tDeliveryTime = " << TimeToString(record->request->GetDeliveryTime()) << "\n";
        stream << "\tNotification:\n";
        stream << "\t\tId: " << record->notification->GetId() << "\n";
        stream << "\t\tLabel: " << record->notification->GetLabel() << "\n";
        stream << "\t\tSlotType = " << record->request->GetSlotType() << "\n";
        dumpInfo.push_back(stream.str());
    }

    return ERR_OK;
}
#endif

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

std::string AdvancedNotificationService::TimeToString(int64_t time)
{
    auto timePoint = std::chrono::time_point<std::chrono::system_clock>(std::chrono::milliseconds(time));
    auto timeT = std::chrono::system_clock::to_time_t(timePoint);

    std::stringstream stream;
    struct tm ret = {0};
    localtime_r(&timeT, &ret);
    stream << std::put_time(&ret, "%F, %T");
    return stream.str();
}

int64_t AdvancedNotificationService::GetNowSysTime()
{
    std::chrono::time_point<std::chrono::system_clock> nowSys = std::chrono::system_clock::now();
    auto epoch = nowSys.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    int64_t duration = value.count();
    return duration;
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

inline void RemoveExpired(
    std::list<std::chrono::system_clock::time_point> &list, const std::chrono::system_clock::time_point &now)
{
    auto iter = list.begin();
    while (iter != list.end()) {
        if (abs(now - *iter) > std::chrono::seconds(1)) {
            iter = list.erase(iter);
        } else {
            break;
        }
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
    RemoveExpired(flowControlTimestampList_, now);
    if (flowControlTimestampList_.size() >= MAX_ACTIVE_NUM_PERSECOND) {
        return ERR_ANS_OVER_MAX_ACTIVE_PERSECOND;
    }

    flowControlTimestampList_.push_back(now);

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
        notificationList_.remove(bundleList.front());
    }

    if (notificationList_.size() >= MAX_ACTIVE_NUM) {
        if (bundleList.size() > 0) {
            bundleList.sort(SortNotificationsByLevelAndTime);
            recordToRemove = bundleList.front();
            SendFlowControlOccurHiSysEvent(recordToRemove);
            notificationList_.remove(bundleList.front());
        } else {
            std::list<std::shared_ptr<NotificationRecord>> sorted = notificationList_;
            sorted.sort(SortNotificationsByLevelAndTime);
            recordToRemove = sorted.front();
            SendFlowControlOccurHiSysEvent(recordToRemove);
            notificationList_.remove(sorted.front());
        }
    }

    AddToNotificationList(record);

    return ERR_OK;
}

void AdvancedNotificationService::OnBundleRemoved(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    handler_->PostTask(std::bind([this, bundleOption]() {
        ErrCode result = NotificationPreferences::GetInstance().RemoveNotificationForBundle(bundleOption);
        if (result != ERR_OK) {
            ANS_LOGW("NotificationPreferences::RemoveNotificationForBundle failed: %{public}d", result);
        }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        DistributedPreferences::GetInstance()->DeleteDistributedBundleInfo(bundleOption);
        std::vector<std::string> keys = GetLocalNotificationKeys(bundleOption);
#else
        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
#endif
        for (auto key : keys) {
            sptr<Notification> notification = nullptr;
            result = RemoveFromNotificationList(key, notification, true,
                NotificationConstant::PACKAGE_CHANGED_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::PACKAGE_CHANGED_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete("", "", notification);
#endif
            }
        }

        NotificationPreferences::GetInstance().RemoveAnsBundleDbInfo(bundleOption);
    }));
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
void AdvancedNotificationService::OnScreenOn()
{
    ANS_LOGI("%{public}s", __FUNCTION__);
    localScreenOn_ = true;
    DistributedScreenStatusManager::GetInstance()->SetLocalScreenStatus(true);
}

void AdvancedNotificationService::OnScreenOff()
{
    ANS_LOGI("%{public}s", __FUNCTION__);
    localScreenOn_ = false;
    DistributedScreenStatusManager::GetInstance()->SetLocalScreenStatus(false);
}
#endif

void AdvancedNotificationService::OnDistributedKvStoreDeathRecipient()
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    handler_->PostTask(std::bind([&]() {
        NotificationPreferences::GetInstance().OnDistributedKvStoreDeathRecipient();
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        DistributedNotificationManager::GetInstance()->OnDistributedKvStoreDeathRecipient();
#endif
    }));
}

ErrCode AdvancedNotificationService::RemoveAllSlots()
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().RemoveNotificationAllSlots(bundleOption);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::AddSlotByType(NotificationConstant::SlotType slotType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance().GetNotificationSlot(bundleOption, slotType, slot);
        if ((result == ERR_OK) && (slot != nullptr)) {
            return;
        } else {
            slot = new NotificationSlot(slotType);
            std::vector<sptr<NotificationSlot>> slots;
            slots.push_back(slot);
            result = NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption, slots);
        }
    }));
    return result;
}

ErrCode AdvancedNotificationService::RemoveNotification(const sptr<NotificationBundleOption> &bundleOption,
    int32_t notificationId, const std::string &label, int32_t removeReason)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;

    handler_->PostSyncTask(std::bind([&]() {
        sptr<Notification> notification = nullptr;
        sptr<NotificationRequest> notificationRequest = nullptr;

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::string deviceId;
        std::string bundleName;
#endif
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid()) &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                (record->deviceId.empty()) &&
#endif
                (record->notification->GetId() == notificationId) && (record->notification->GetLabel() == label)) {
                if (!record->notification->IsRemoveAllowed()) {
                    result = ERR_ANS_NOTIFICATION_IS_UNALLOWED_REMOVEALLOWED;
                    break;
                }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                deviceId = record->deviceId;
                bundleName = record->bundleName;
#endif
                notification = record->notification;
                notificationRequest = record->request;
                notificationList_.remove(record);
                result = ERR_OK;
                break;
            }
        }

        if (notification != nullptr) {
            UpdateRecentNotification(notification, true, removeReason);
            sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, removeReason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
        }
        if (removeReason != NotificationConstant::CLICK_REASON_DELETE) {
            TriggerRemoveWantAgent(notificationRequest);
        }
    }));

    SendRemoveHiSysEvent(notificationId, label, bundleOption, result);
    return result;
}

ErrCode AdvancedNotificationService::RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    handler_->PostSyncTask(std::bind([&]() {
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        for (auto record : notificationList_) {
            if (!record->notification->IsRemoveAllowed()) {
                continue;
            }

            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                record->deviceId.empty() &&
#endif
                !record->request->IsUnremovable()) {
                removeList.push_back(record);
            }
        }

        for (auto record : removeList) {
            notificationList_.remove(record);
            if (record->notification != nullptr) {
                int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
                UpdateRecentNotification(record->notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(record->notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }

            TriggerRemoveWantAgent(record->request);
        }
    }));

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetSlotNumAsBundle(
    const sptr<NotificationBundleOption> &bundleOption, uint64_t &num)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;

    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().GetNotificationSlotsNumForBundle(bundle, num);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            num = 0;
        }
    }));

    return result;
}

ErrCode AdvancedNotificationService::CancelGroup(const std::string &groupName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (groupName.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    handler_->PostSyncTask(std::bind([&]() {
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                record->deviceId.empty() &&
#endif
                (record->request->GetGroupName() == groupName)) {
                removeList.push_back(record);
            }
        }

        for (auto record : removeList) {
            notificationList_.remove(record);

            if (record->notification != nullptr) {
                int32_t reason = NotificationConstant::APP_CANCEL_REASON_DELETE;
                UpdateRecentNotification(record->notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(record->notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
        }
    }));

    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveGroupByBundle(
    const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (bundleOption == nullptr || groupName.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    handler_->PostSyncTask(std::bind([&]() {
        std::vector<std::shared_ptr<NotificationRecord>> removeList;
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
                removeList.push_back(record);
            }
        }

        for (auto record : removeList) {
            notificationList_.remove(record);

            if (record->notification != nullptr) {
                int32_t reason = NotificationConstant::CANCEL_REASON_DELETE;
                UpdateRecentNotification(record->notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(record->notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(record->deviceId, record->bundleName, record->notification);
#endif
            }
        }
    }));

    return ERR_OK;
}

void AdvancedNotificationService::AdjustDateForDndTypeOnce(int64_t &beginDate, int64_t &endDate)
{
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    time_t nowT = std::chrono::system_clock::to_time_t(now);
    tm nowTm = GetLocalTime(nowT);

    auto beginDateMilliseconds = std::chrono::milliseconds(beginDate);
    auto beginDateTimePoint =
        std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(beginDateMilliseconds);
    time_t beginDateT = std::chrono::system_clock::to_time_t(beginDateTimePoint);
    tm beginDateTm = GetLocalTime(beginDateT);

    auto endDateMilliseconds = std::chrono::milliseconds(endDate);
    auto endDateTimePoint =
        std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(endDateMilliseconds);
    time_t endDateT = std::chrono::system_clock::to_time_t(endDateTimePoint);
    tm endDateTm = GetLocalTime(endDateT);

    tm todayBeginTm = nowTm;
    todayBeginTm.tm_sec = 0;
    todayBeginTm.tm_min = beginDateTm.tm_min;
    todayBeginTm.tm_hour = beginDateTm.tm_hour;

    tm todayEndTm = nowTm;
    todayEndTm.tm_sec = 0;
    todayEndTm.tm_min = endDateTm.tm_min;
    todayEndTm.tm_hour = endDateTm.tm_hour;

    time_t todayBeginT = mktime(&todayBeginTm);
    if (todayBeginT == -1) {
        return;
    }
    time_t todayEndT = mktime(&todayEndTm);
    if (todayEndT == -1) {
        return;
    }

    auto newBeginTimePoint = std::chrono::system_clock::from_time_t(todayBeginT);
    auto newEndTimePoint = std::chrono::system_clock::from_time_t(todayEndT);
    if (newBeginTimePoint >= newEndTimePoint) {
        newEndTimePoint += std::chrono::hours(HOURS_IN_ONE_DAY);
    }

    if (newEndTimePoint < now) {
        newBeginTimePoint += std::chrono::hours(HOURS_IN_ONE_DAY);
        newEndTimePoint += std::chrono::hours(HOURS_IN_ONE_DAY);
    }

    auto newBeginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(newBeginTimePoint.time_since_epoch());
    beginDate = newBeginDuration.count();

    auto newEndDuration = std::chrono::duration_cast<std::chrono::milliseconds>(newEndTimePoint.time_since_epoch());
    endDate = newEndDuration.count();
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        ANS_LOGW("Not system app!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGW("Check permission denied!");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        ANS_LOGW("No active user found!");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    return SetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    return GetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    doesSupport = SUPPORT_DO_NOT_DISTRUB;
    return ERR_OK;
}

bool AdvancedNotificationService::CheckPermission(const std::string &permission)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (isSubsystem) {
        return true;
    }

    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool result = AccessTokenHelper::VerifyCallerPermission(tokenCaller, permission);
    if (!result) {
        ANS_LOGE("Permission denied");
    }
    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = DistributedPreferences::GetInstance()->GetDistributedEnable(enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::EnableDistributed(bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(
        std::bind([&]() { result = DistributedPreferences::GetInstance()->SetDistributedEnable(enabled); }));
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
    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundle, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = DistributedPreferences::GetInstance()->SetDistributedBundleEnable(bundle, enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
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

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind(
        [&]() { result = DistributedPreferences::GetInstance()->SetDistributedBundleEnable(bundleOption, enabled); }));
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
    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundle, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        enabled = appInfoEnable;
        return ERR_OK;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = DistributedPreferences::GetInstance()->GetDistributedBundleEnable(bundle, enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::GetDeviceRemindType(NotificationConstant::RemindType &remindType)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    handler_->PostSyncTask(std::bind([&]() { remindType = GetRemindType(); }));
    return ERR_OK;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::SetNotificationRemindType(sptr<Notification> notification, bool isLocal)
{
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    notification->SetRemindType(GetRemindType());
#else
    notification->SetRemindType(NotificationConstant::RemindType::NONE);
#endif
    return ERR_OK;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
std::vector<std::string> AdvancedNotificationService::GetLocalNotificationKeys(
    const sptr<NotificationBundleOption> &bundleOption)
{
    std::vector<std::string> keys;

    for (auto record : notificationList_) {
        if ((bundleOption != nullptr) && (record->bundleOption->GetBundleName() != bundleOption->GetBundleName()) &&
            (record->bundleOption->GetUid() != bundleOption->GetUid()) && record->deviceId.empty()) {
            continue;
        }
        keys.push_back(record->notification->GetKey());
    }

    return keys;
}

NotificationConstant::RemindType AdvancedNotificationService::GetRemindType()
{
    bool remind = localScreenOn_;
    if (distributedReminderPolicy_ == NotificationConstant::DistributedReminderPolicy::DEFAULT) {
        bool remoteUsing = false;
        ErrCode result = DistributedScreenStatusManager::GetInstance()->CheckRemoteDevicesIsUsing(remoteUsing);
        if (result != ERR_OK) {
            remind = true;
        }
        if (!localScreenOn_ && !remoteUsing) {
            remind = true;
        }
    } else if (distributedReminderPolicy_ == NotificationConstant::DistributedReminderPolicy::ALWAYS_REMIND) {
        remind = true;
    } else if (distributedReminderPolicy_ == NotificationConstant::DistributedReminderPolicy::DO_NOT_REMIND) {
        remind = false;
    }

    if (localScreenOn_) {
        if (remind) {
            return NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
        } else {
            return NotificationConstant::RemindType::DEVICE_ACTIVE_DONOT_REMIND;
        }
    } else {
        if (remind) {
            return NotificationConstant::RemindType::DEVICE_IDLE_REMIND;
        } else {
            return NotificationConstant::RemindType::DEVICE_IDLE_DONOT_REMIND;
        }
    }
}

void AdvancedNotificationService::GetDistributedInfo(
    const std::string &key, std::string &deviceId, std::string &bundleName)
{
    for (auto record : notificationList_) {
        if (record->notification->GetKey() == key) {
            deviceId = record->deviceId;
            bundleName = record->bundleName;
            break;
        }
    }
}

ErrCode AdvancedNotificationService::DoDistributedPublish(
    const sptr<NotificationBundleOption> bundleOption, const std::shared_ptr<NotificationRecord> record)
{
    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundleOption, appInfoEnable);
    if (!appInfoEnable) {
        return ERR_OK;
    }

    if (!record->request->GetNotificationDistributedOptions().IsDistributed()) {
        return ERR_OK;
    }

    ErrCode result;
    bool distributedEnable = false;
    result = DistributedPreferences::GetInstance()->GetDistributedEnable(distributedEnable);
    if (result != ERR_OK || !distributedEnable) {
        return result;
    }

    bool bundleDistributedEnable = false;
    result = DistributedPreferences::GetInstance()->GetDistributedBundleEnable(bundleOption, bundleDistributedEnable);
    if (result != ERR_OK || !bundleDistributedEnable) {
        return result;
    }

    return DistributedNotificationManager::GetInstance()->Publish(record->notification->GetBundleName(),
        record->notification->GetLabel(),
        record->notification->GetId(),
        record->request);
}

ErrCode AdvancedNotificationService::DoDistributedDelete(
    const std::string deviceId, const std::string bundleName, const sptr<Notification> notification)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    if (!notification->GetNotificationRequest().GetNotificationDistributedOptions().IsDistributed()) {
        return ERR_OK;
    }
    if (deviceId.empty()) {
        return DistributedNotificationManager::GetInstance()->Delete(
            notification->GetBundleName(), notification->GetLabel(), notification->GetId());
    } else {
        return DistributedNotificationManager::GetInstance()->DeleteRemoteNotification(
            deviceId, bundleName, notification->GetLabel(), notification->GetId());
    }

    return ERR_OK;
}

bool AdvancedNotificationService::CheckDistributedNotificationType(const sptr<NotificationRequest> &request)
{
    auto deviceTypeList = request->GetNotificationDistributedOptions().GetDevicesSupportDisplay();
    if (deviceTypeList.empty()) {
        return true;
    }

    DistributedDatabase::DeviceInfo localDeviceInfo;
    DistributedNotificationManager::GetInstance()->GetLocalDeviceInfo(localDeviceInfo);
    for (auto device : deviceTypeList) {
        if (device == localDeviceInfo.deviceType) {
            return true;
        }
    }
    return false;
}

void AdvancedNotificationService::OnDistributedPublish(
    const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    int32_t activeUserId = -1;
    if (!GetActiveUserId(activeUserId)) {
        ANS_LOGE("Failed to get active user id!");
        return;
    }

    handler_->PostTask(std::bind([this, deviceId, bundleName, request, activeUserId]() {
        if (!CheckDistributedNotificationType(request)) {
            ANS_LOGD("device type not support display.");
            return;
        }

        int32_t uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, activeUserId);
        if (uid <= 0) {
            if (CheckPublishWithoutApp(activeUserId, request)) {
                request->SetOwnerBundleName(FOUNDATION_BUNDLE_NAME);
                request->SetCreatorBundleName(FOUNDATION_BUNDLE_NAME);
            } else {
                ANS_LOGE("bundle does not exit and enable off!");
                return;
            }
        }
        std::string bundle = request->GetOwnerBundleName();
        request->SetCreatorUid(BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundle, activeUserId));
        sptr<NotificationBundleOption> bundleOption =
            GenerateValidBundleOption(new NotificationBundleOption(bundle, 0));

        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        if (record == nullptr) {
            return;
        }
        record->request = request;
        record->notification = new Notification(deviceId, request);
        record->bundleOption = bundleOption;
        record->deviceId = deviceId;
        record->bundleName = bundleName;
        SetNotificationRemindType(record->notification, false);

        ErrCode result = AssignValidNotificationSlot(record);
        if (result != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
            return;
        }

        result = Filter(record);
        if (result != ERR_OK) {
            ANS_LOGE("Reject by filters: %{public}d", result);
            return;
        }

        result = FlowControl(record);
        if (result != ERR_OK) {
            return;
        }

        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    }));
}

void AdvancedNotificationService::OnDistributedUpdate(
    const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    int32_t activeUserId = -1;
    if (!GetActiveUserId(activeUserId)) {
        ANS_LOGE("Failed to get active user id!");
        return;
    }

    handler_->PostTask(std::bind([this, deviceId, bundleName, request, activeUserId]() {
        if (!CheckDistributedNotificationType(request)) {
            ANS_LOGD("device type not support display.");
            return;
        }

        int32_t uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, activeUserId);
        if (uid <= 0) {
            if (CheckPublishWithoutApp(activeUserId, request)) {
                request->SetOwnerBundleName(FOUNDATION_BUNDLE_NAME);
                request->SetCreatorBundleName(FOUNDATION_BUNDLE_NAME);
            } else {
                ANS_LOGE("bundle does not exit and enable off!");
                return;
            }
        }
        std::string bundle = request->GetOwnerBundleName();
        request->SetCreatorUid(BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundle, activeUserId));
        sptr<NotificationBundleOption> bundleOption =
            GenerateValidBundleOption(new NotificationBundleOption(bundle, 0));

        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        if (record == nullptr) {
            return;
        }
        record->request = request;
        record->notification = new Notification(deviceId, request);
        record->bundleOption = bundleOption;
        record->deviceId = deviceId;
        record->bundleName = bundleName;
        SetNotificationRemindType(record->notification, false);

        ErrCode result = AssignValidNotificationSlot(record);
        if (result != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
            return;
        }

        result = Filter(record);
        if (result != ERR_OK) {
            ANS_LOGE("Reject by filters: %{public}d", result);
            return;
        }

        if (IsNotificationExists(record->notification->GetKey())) {
            if (record->request->IsAlertOneTime()) {
                record->notification->SetEnableLight(false);
                record->notification->SetEnableSound(false);
                record->notification->SetEnableVibration(false);
            }
            UpdateInNotificationList(record);
        }

        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    }));
}

void AdvancedNotificationService::OnDistributedDelete(
    const std::string &deviceId, const std::string &bundleName, const std::string &label, int32_t id)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    handler_->PostTask(std::bind([this, deviceId, bundleName, label, id]() {
        int32_t activeUserId = -1;
        if (!GetActiveUserId(activeUserId)) {
            ANS_LOGE("Failed to get active user id!");
            return;
        }
        int32_t uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, activeUserId);
        std::string bundle = (uid > 0) ? bundleName : FOUNDATION_BUNDLE_NAME;
        sptr<NotificationBundleOption> bundleOption =
            GenerateValidBundleOption(new NotificationBundleOption(bundle, 0));

        std::string recordDeviceId;
        DistributedDatabase::DeviceInfo localDeviceInfo;
        if (DistributedNotificationManager::GetInstance()->GetLocalDeviceInfo(localDeviceInfo) == ERR_OK &&
            deviceId == localDeviceInfo.deviceId) {
            recordDeviceId = "";
        } else {
            recordDeviceId = deviceId;
        }

        sptr<Notification> notification = nullptr;
        for (auto record : notificationList_) {
            if ((record->deviceId == recordDeviceId) &&
                ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) ||
                (record->bundleName == bundleName)) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
                (record->notification->GetLabel() == label) && (record->notification->GetId() == id)) {
                notification = record->notification;
                notificationList_.remove(record);
                break;
            }
        }

        if (notification != nullptr) {
            int32_t reason = NotificationConstant::APP_CANCEL_REASON_OTHER;
            UpdateRecentNotification(notification, true, reason);
            sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
        }
    }));
}

ErrCode AdvancedNotificationService::GetDistributedEnableInApplicationInfo(
    const sptr<NotificationBundleOption> bundleOption, bool &enable)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);

    if (userId >= SUBSCRIBE_USER_SYSTEM_BEGIN && userId <= SUBSCRIBE_USER_SYSTEM_END) {
        enable = true;
    } else {
        enable = BundleManagerHelper::GetInstance()->GetDistributedNotificationEnabled(
            bundleOption->GetBundleName(), userId);
    }

    return ERR_OK;
}

bool AdvancedNotificationService::CheckPublishWithoutApp(const int32_t userId, const sptr<NotificationRequest> &request)
{
    bool enabled = false;
    DistributedPreferences::GetInstance()->GetSyncEnabledWithoutApp(userId, enabled);
    if (!enabled) {
        ANS_LOGE("enable is false, userId[%{public}d]", userId);
        return false;
    }

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent = request->GetWantAgent();
    if (!wantAgent) {
        ANS_LOGE("Failed to get wantAgent!");
        return false;
    }

    std::shared_ptr<AAFwk::Want> want = AbilityRuntime::WantAgent::WantAgentHelper::GetWant(wantAgent);
    if (!want || want->GetDeviceId().empty()) {
        ANS_LOGE("Failed to get want!");
        return false;
    }

    return true;
}
#endif

ErrCode AdvancedNotificationService::PrepareContinuousTaskNotificationRequest(
    const sptr<NotificationRequest> &request, const int32_t &uid)
{
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    request->SetCreatorPid(pid);

    ErrCode result = CheckPictureSize(request);
    return result;
}

ErrCode AdvancedNotificationService::IsSupportTemplate(const std::string& templateName, bool &support)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        support = false;
        result = NotificationPreferences::GetInstance().GetTemplateSupported(templateName, support);
    }));
    return result;
}

bool AdvancedNotificationService::GetActiveUserId(int& userId)
{
    std::vector<int> activeUserId;
    OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);
    if (activeUserId.size() > 0) {
        userId = activeUserId[0];
        ANS_LOGD("Return active userId=%{public}d", userId);
        return true;
    }
    return false;
}

void AdvancedNotificationService::TriggerRemoveWantAgent(const sptr<NotificationRequest> &request)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    if ((request == nullptr) || (request->GetRemovalWantAgent() == nullptr)) {
        return;
    }
    OHOS::AbilityRuntime::WantAgent::TriggerInfo triggerInfo;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = request->GetRemovalWantAgent();
    AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(agent, nullptr, triggerInfo);
}

ErrCode AdvancedNotificationService::IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        allowed = false;
        result = NotificationPreferences::GetInstance().GetNotificationsEnabled(userId, allowed);
    }));
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledByUser(const int32_t &userId, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().SetNotificationsEnabled(userId, enabled);
    }));
    return result;
}

ErrCode AdvancedNotificationService::DeleteAllByUser(const int32_t &userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        std::vector<std::string> keys = GetNotificationKeys(nullptr);
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            result = RemoveFromNotificationListForDeleteAll(key, userId, notification);
            if ((result != ERR_OK) || (notification == nullptr)) {
                continue;
            }

            if (notification->GetUserId() == userId) {
                int32_t reason = NotificationConstant::CANCEL_ALL_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
        }

        result = ERR_OK;
    }));

    return result;
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDate(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (!IsSystemApp()) {
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

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    return GetDoNotDisturbDateByUser(userId, date);
}

ErrCode AdvancedNotificationService::SetDoNotDisturbDateByUser(const int32_t &userId,
    const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s enter, userId = %{public}d", __FUNCTION__, userId);
    if (date == nullptr) {
        ANS_LOGE("Invalid date param");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;

    int64_t beginDate = ResetSeconds(date->GetBeginDate());
    int64_t endDate = ResetSeconds(date->GetEndDate());
    switch (date->GetDoNotDisturbType()) {
        case NotificationConstant::DoNotDisturbType::NONE:
            beginDate = 0;
            endDate = 0;
            break;
        case NotificationConstant::DoNotDisturbType::ONCE:
            AdjustDateForDndTypeOnce(beginDate, endDate);
            break;
        case NotificationConstant::DoNotDisturbType::CLEARLY:
            if (beginDate >= endDate) {
                return ERR_ANS_INVALID_PARAM;
            }
            break;
        default:
            break;
    }
    ANS_LOGD("Before set SetDoNotDisturbDate beginDate = %{public}" PRId64 ", endDate = %{public}" PRId64,
             beginDate, endDate);
    const sptr<NotificationDoNotDisturbDate> newConfig = new NotificationDoNotDisturbDate(
        date->GetDoNotDisturbType(),
        beginDate,
        endDate
    );

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Generate invalid bundle option!");
        return ERR_ANS_INVALID_BUNDLE;
    }

    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().SetDoNotDisturbDate(userId, newConfig);
        if (result == ERR_OK) {
            NotificationSubscriberManager::GetInstance()->NotifyDoNotDisturbDateChanged(newConfig);
        }
    }));

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetDoNotDisturbDateByUser(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    ErrCode result = ERR_OK;

    handler_->PostSyncTask(std::bind([&]() {
        sptr<NotificationDoNotDisturbDate> currentConfig = nullptr;
        result = NotificationPreferences::GetInstance().GetDoNotDisturbDate(userId, currentConfig);
        if (result == ERR_OK) {
            int64_t now = GetCurrentTime();
            switch (currentConfig->GetDoNotDisturbType()) {
                case NotificationConstant::DoNotDisturbType::CLEARLY:
                case NotificationConstant::DoNotDisturbType::ONCE:
                    if (now >= currentConfig->GetEndDate()) {
                        date = new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::NONE, 0, 0);
                        NotificationPreferences::GetInstance().SetDoNotDisturbDate(userId, date);
                    } else {
                        date = currentConfig;
                    }
                    break;
                default:
                    date = currentConfig;
                    break;
            }
        }
    }));

    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetHasPoppedDialog(
    const sptr<NotificationBundleOption> bundleOption, bool hasPopped)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().SetHasPoppedDialog(bundleOption, hasPopped);
    }));
    return result;
}

ErrCode AdvancedNotificationService::GetHasPoppedDialog(
    const sptr<NotificationBundleOption> bundleOption, bool &hasPopped)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        result = NotificationPreferences::GetInstance().GetHasPoppedDialog(bundleOption, hasPopped);
    }));
    return result;
}

bool AdvancedNotificationService::CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        return false;
    }
    return bundleManager->CheckApiCompatibility(bundleOption);
}

void AdvancedNotificationService::OnResourceRemove(int32_t userId)
{
    DeleteAllByUser(userId);

    handler_->PostSyncTask(std::bind([&]() {
        NotificationPreferences::GetInstance().RemoveSettings(userId);
    }));
}

void AdvancedNotificationService::OnBundleDataCleared(const sptr<NotificationBundleOption> &bundleOption)
{
    handler_->PostSyncTask(std::bind([&]() {
        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            ErrCode result = RemoveFromNotificationList(key, notification, true,
                NotificationConstant::PACKAGE_CHANGED_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::PACKAGE_CHANGED_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
                NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, sortingMap, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
        }
    }));
}

void AdvancedNotificationService::GetDisplayPosition(
    int& offsetX, int& offsetY, int& width, int& height, bool& wideScreen)
{
    wideScreen = false;
    auto display = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (display == nullptr) {
        ANS_LOGD("dialog GetDefaultDisplay fail, try again.");
        display = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    }

    if (display != nullptr) {
        ANS_LOGD("display size: %{public}d x %{public}d",
            display->GetWidth(), display->GetHeight());
        if (display->GetWidth() < display->GetHeight()) {
            float widthRatio = 0.75f;
            int32_t heightRatio = 5;
            width = static_cast<int32_t>(display->GetWidth() * widthRatio);
            height = display->GetHeight() / heightRatio;
        } else {
            int32_t widthRatio = 3;
            int32_t heightRatio = 4;
            wideScreen = true;
            width = display->GetWidth() / widthRatio;
            height = display->GetHeight() / heightRatio;
        }
        offsetX = (display->GetWidth() - width) / UI_HALF;
        offsetY = (display->GetHeight() - height) / UI_HALF;
    } else {
        ANS_LOGD("dialog get display fail, use default wide.");
        width = DIALOG_DEFAULT_WIDTH;
        height = DIALOG_DEFAULT_HEIGHT;
        offsetX = (WINDOW_DEFAULT_WIDTH - width) / UI_HALF;
        offsetY = (WINDOW_DEFAULT_HEIGHT - height) / UI_HALF;
    }
    ANS_LOGD("GetDisplayPosition: %{public}d, %{public}d (%{public}d x %{public}d)",
        offsetX, offsetY, width, height);
}

ErrCode AdvancedNotificationService::SetEnabledForBundleSlot(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType, bool enabled)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("slotType: %{public}d, enabled: %{public}d", slotType, enabled);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance().GetNotificationSlot(bundle, slotType, slot);
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST ||
            result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            slot = new (std::nothrow) NotificationSlot(slotType);
            if (slot == nullptr) {
                ANS_LOGE("Failed to create NotificationSlot ptr.");
                result = ERR_ANS_NO_MEMORY;
                return;
            }
        } else if ((result == ERR_OK) && (slot != nullptr)) {
            if (slot->GetEnable() == enabled) {
                return;
            }
            NotificationPreferences::GetInstance().RemoveNotificationSlot(bundle, slotType);
        } else {
            ANS_LOGE("Set enable slot: GetNotificationSlot failed");
            return;
        }

        slot->SetEnable(enabled);
        std::vector<sptr<NotificationSlot>> slots;
        slots.push_back(slot);
        result = NotificationPreferences::GetInstance().AddNotificationSlots(bundle, slots);
        if (result != ERR_OK) {
            ANS_LOGE("Set enable slot: AddNotificationSlot failed");
            return;
        }

        PublishSlotChangeCommonEvent(bundle);
    }));

    SendEnableNotificationSlotHiSysEvent(bundleOption, slotType, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::GetEnabledForBundleSlot(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled)
{
    ANS_LOGD("slotType: %{public}d", slotType);

    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(std::bind([&]() {
        sptr<NotificationSlot> slot;
        result = NotificationPreferences::GetInstance().GetNotificationSlot(bundle, slotType, slot);
        if (result != ERR_OK) {
            ANS_LOGE("Get enable slot: GetNotificationSlot failed");
            return;
        }
        if (slot == nullptr) {
            ANS_LOGW("Get enable slot: object is null, enabled default true");
            enabled = true;
            result = ERR_OK;
            return;
        }
        enabled = slot->GetEnable();
    }));

    return result;
}

bool AdvancedNotificationService::PublishSlotChangeCommonEvent(const sptr<NotificationBundleOption> &bundleOption)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("bundle [%{public}s : %{public}d]", bundleOption->GetBundleName().c_str(), bundleOption->GetUid());

    EventFwk::Want want;
    AppExecFwk::ElementName element;
    element.SetBundleName(bundleOption->GetBundleName());
    want.SetElement(element);
    want.SetParam(AppExecFwk::Constants::UID, bundleOption->GetUid());
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SLOT_CHANGE);
    EventFwk::CommonEventData commonData {want};
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData)) {
        ANS_LOGE("PublishCommonEvent failed");
        return false;
    }

    return true;
}

ErrCode AdvancedNotificationService::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    std::vector<std::string> &dumpInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        ANS_LOGE("Not subsystem or shell request");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    ErrCode result = ERR_ANS_NOT_ALLOWED;
    handler_->PostSyncTask(std::bind([&]() {
        if (cmd == ACTIVE_NOTIFICATION_OPTION) {
            result = ActiveNotificationDump(bundle, userId, dumpInfo);
        } else if (cmd == RECENT_NOTIFICATION_OPTION) {
            result = RecentNotificationDump(bundle, userId, dumpInfo);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        } else if (cmd == DISTRIBUTED_NOTIFICATION_OPTION) {
            result = DistributedNotificationDump(bundle, userId, dumpInfo);
#endif
        } else if (cmd.substr(0, cmd.find_first_of(" ", 0)) == SET_RECENT_COUNT_OPTION) {
            result = SetRecentNotificationCount(cmd.substr(cmd.find_first_of(" ", 0) + 1));
        } else {
            result = ERR_ANS_INVALID_PARAM;
        }
    }));
    return result;
}

int AdvancedNotificationService::Dump(int fd, const std::vector<std::u16string> &args)
{
    ANS_LOGD("enter");
    std::string result;
    GetDumpInfo(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        ANS_LOGE("dprintf error");
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}

void AdvancedNotificationService::GetDumpInfo(const std::vector<std::u16string> &args, std::string &result)
{
    if (args.size() != 1) {
        result = HIDUMPER_ERR_MSG;
        return;
    }
    std::vector<std::string> dumpInfo;
    std::string cmd = Str16ToStr8(args.front());
    if (HIDUMPER_CMD_MAP.find(cmd) == HIDUMPER_CMD_MAP.end()) {
        result = HIDUMPER_ERR_MSG;
        return;
    }
    std::string cmdValue = HIDUMPER_CMD_MAP.find(cmd)->second;
    if (cmdValue == HELP_NOTIFICATION_OPTION) {
        result = HIDUMPER_HELP_MSG;
    }
    ShellDump(cmdValue, "", SUBSCRIBE_USER_INIT, dumpInfo);
    if (dumpInfo.empty()) {
        result.append("no notification\n");
        return;
    }
    int32_t index = 0;
    result.append("notification list:\n");
    for (const auto &info: dumpInfo) {
        result.append("No." + std::to_string(++index) + "\n");
        result.append(info);
    }
}

void AdvancedNotificationService::SendSubscribeHiSysEvent(int32_t pid, int32_t uid,
    const sptr<NotificationSubscribeInfo> &info, ErrCode errCode)
{
    EventInfo eventInfo;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    if (info != nullptr) {
        eventInfo.userId = info->GetAppUserId();
        std::vector<std::string> appNames = info->GetAppNames();
        eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
            [appNames](const std::string &bundleName, const std::string &str) {
                return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
            });
    }

    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(SUBSCRIBE_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(SUBSCRIBE, eventInfo);
    }
}

void AdvancedNotificationService::SendUnSubscribeHiSysEvent(int32_t pid, int32_t uid,
    const sptr<NotificationSubscribeInfo> &info)
{
    EventInfo eventInfo;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    if (info != nullptr) {
        eventInfo.userId = info->GetAppUserId();
        std::vector<std::string> appNames = info->GetAppNames();
        eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
            [appNames](const std::string &bundleName, const std::string &str) {
                return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
            });
    }

    EventReport::SendHiSysEvent(UNSUBSCRIBE, eventInfo);
}

void AdvancedNotificationService::SendPublishHiSysEvent(const sptr<NotificationRequest> &request, ErrCode errCode)
{
    if (request == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = request->GetNotificationId();
    eventInfo.contentType = static_cast<int32_t>(request->GetNotificationType());
    eventInfo.bundleName = request->GetCreatorBundleName();
    eventInfo.userId = request->GetCreatorUserId();
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(PUBLISH_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(PUBLISH, eventInfo);
    }
}

void AdvancedNotificationService::SendCancelHiSysEvent(int32_t notificationId, const std::string &label,
    const sptr<NotificationBundleOption> &bundleOption, ErrCode errCode)
{
    if (bundleOption == nullptr || errCode != ERR_OK) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = notificationId;
    eventInfo.notificationLabel = label;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    EventReport::SendHiSysEvent(CANCEL, eventInfo);
}

void AdvancedNotificationService::SendRemoveHiSysEvent(int32_t notificationId, const std::string &label,
    const sptr<NotificationBundleOption> &bundleOption, ErrCode errCode)
{
    if (bundleOption == nullptr || errCode != ERR_OK) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = notificationId;
    eventInfo.notificationLabel = label;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    EventReport::SendHiSysEvent(REMOVE, eventInfo);
}

void AdvancedNotificationService::SendEnableNotificationHiSysEvent(const sptr<NotificationBundleOption> &bundleOption,
    bool enabled, ErrCode errCode)
{
    if (bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    eventInfo.enable = enabled;
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION, eventInfo);
    }
}

void AdvancedNotificationService::SendEnableNotificationSlotHiSysEvent(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
    bool enabled, ErrCode errCode)
{
    if (bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    eventInfo.slotType = slotType;
    eventInfo.enable = enabled;
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT, eventInfo);
    }
}

void AdvancedNotificationService::SendFlowControlOccurHiSysEvent(const std::shared_ptr<NotificationRecord> &record)
{
    if (record == nullptr || record->request == nullptr || record->bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = record->request->GetNotificationId();
    eventInfo.bundleName = record->bundleOption->GetBundleName();
    eventInfo.uid = record->bundleOption->GetUid();
    EventReport::SendHiSysEvent(FLOW_CONTROL_OCCUR, eventInfo);
}

ErrCode AdvancedNotificationService::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    ANS_LOGD("userId: %{public}d, enabled: %{public}d", userId, enabled);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(
        std::bind([&]() {
            result = DistributedPreferences::GetInstance()->SetSyncEnabledWithoutApp(userId, enabled);
        }));
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    ANS_LOGD("userId: %{public}d", userId);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (!IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    handler_->PostSyncTask(
        std::bind([&]() {
            result = DistributedPreferences::GetInstance()->GetSyncEnabledWithoutApp(userId, enabled);
        }));
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::PublishNotificationBySa(const sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    int32_t uid = request->GetCreatorUid();
    if (uid <= 0) {
        ANS_LOGE("CreatorUid[%{public}d] error", uid);
        return ERR_ANS_INVALID_UID;
    }

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        ANS_LOGE("failed to get bundleManager!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    std::string bundle = bundleManager->GetBundleNameByUid(uid);
    if (request->GetCreatorBundleName().empty()) {
        request->SetCreatorBundleName(bundle);
    }
    if (request->GetOwnerBundleName().empty()) {
        request->SetOwnerBundleName(bundle);
    }

    request->SetCreatorPid(IPCSkeleton::GetCallingPid());
    int32_t userId = SUBSCRIBE_USER_INIT;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), userId);
    request->SetCreatorUserId(userId);
    ANS_LOGD("creator uid=%{public}d, userId=%{public}d, bundleName=%{public}s ", uid, userId, bundle.c_str());

    ErrCode result = CheckPictureSize(request);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to check picture size");
        return result;
    }

    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(bundle, uid);
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create bundleOption");
        return ERR_ANS_NO_MEMORY;
    }

    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->bundleOption = bundleOption;
    record->notification = new (std::nothrow) Notification(request);
    if (record->notification == nullptr) {
        ANS_LOGE("Failed to create notification");
        return ERR_ANS_NO_MEMORY;
    }

    handler_->PostSyncTask([this, &record]() {
        if (AssignToNotificationList(record) != ERR_OK) {
            ANS_LOGE("Failed to assign notification list");
            return;
        }

        UpdateRecentNotification(record->notification, false, 0);
        sptr<NotificationSortingMap> sortingMap = GenerateSortingMap();
        NotificationSubscriberManager::GetInstance()->NotifyConsumed(record->notification, sortingMap);
    });

    return result;
}
}  // namespace Notification
}  // namespace OHOS
