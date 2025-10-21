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

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_config_parse.h"
#include "notification_constant.h"
#include "os_account_manager.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"
#include "singleton.h"
#include "want_agent_helper.h"
#include "hitrace_meter.h"
#include "notification_timer_info.h"
#include "time_service_client.h"
#include "notification_extension_wrapper.h"
#include "string_utils.h"

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#include "distributed_database.h"
#endif

#include "system_sound_helper.h"
#include "advanced_notification_inline.h"
#include "notification_analytics_util.h"
#include "notification_clone_disturb_service.h"
#include "notification_clone_bundle_service.h"
#include "advanced_notification_flow_control_service.h"
#include "parameters.h"

#define CHECK_BUNDLE_OPTION_IS_INVALID(option)                              \
    if (option == nullptr || option->GetBundleName().empty()) {             \
        ANS_LOGE("Bundle option sptr is null or bundle name is empty!");    \
        return;                                                             \
    }

#define CHECK_BUNDLE_OPTION_IS_INVALID_WITH_RETURN(option, retVal)          \
    if (option == nullptr || option->GetBundleName().empty()) {             \
        ANS_LOGE("Bundle option sptr is null or bundle name is empty!");    \
        return retVal;                                                      \
    }

namespace OHOS {
namespace Notification {
namespace {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
constexpr char DISTRIBUTED_NOTIFICATION_OPTION[] = "distributed";
#endif
constexpr int32_t HOURS_IN_ONE_DAY = 24;
constexpr char FOUNDATION_BUNDLE_NAME[] = "ohos.global.systemres";
constexpr char ACTIVE_NOTIFICATION_OPTION[] = "active";
constexpr char SET_RECENT_COUNT_OPTION[] = "setRecentCount";
constexpr char HELP_NOTIFICATION_OPTION[] = "help";
constexpr char RECENT_NOTIFICATION_OPTION[] = "recent";
constexpr char HIDUMPER_ERR_MSG[] =
    "error: unknown option.\nThe arguments are illegal and you can enter '-h' for help.";
constexpr int32_t MAIN_USER_ID = 100;
constexpr int32_t ZERO_USER_ID = 0;
constexpr char OLD_KEY_BUNDLE_DISTRIBUTED_ENABLE_NOTIFICATION[] = "enabledNotificationDistributed";
constexpr char KEY_TABLE_VERSION[] = "tableVersion";
constexpr char SPLIT_FLAG[] = "-";
constexpr int32_t KEYWORD_SIZE = 4;
constexpr int32_t MIN_VERSION = 1;
constexpr int32_t OPERATION_TYPE_COMMON_EVENT = 4;
const std::unordered_map<std::string, std::string> HIDUMPER_CMD_MAP = {
    { "--help", HELP_NOTIFICATION_OPTION },
    { "--active", ACTIVE_NOTIFICATION_OPTION },
    { "--recent", RECENT_NOTIFICATION_OPTION },
    { "-h", HELP_NOTIFICATION_OPTION },
    { "-a", ACTIVE_NOTIFICATION_OPTION },
    { "-r", RECENT_NOTIFICATION_OPTION },
};

constexpr char HIDUMPER_HELP_MSG[] =
    "Usage:dump <command> [options]\n"
    "Description::\n"
    "  --active, -a                 list all active notifications\n"
    "  --recent, -r                 list recent notifications\n";
}

std::shared_ptr<ffrt::queue> AdvancedNotificationService::GetNotificationSvrQueue()
{
    return notificationSvrQueue_;
}

void AdvancedNotificationService::SubmitAsyncTask(const std::function<void()>& func)
{
    notificationSvrQueue_->submit_h(func);
}

void AdvancedNotificationService::SubmitSyncTask(const std::function<void()>& func)
{
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(func);
    notificationSvrQueue_->wait(handler);
}

sptr<NotificationBundleOption> AdvancedNotificationService::GenerateBundleOption()
{
    sptr<NotificationBundleOption> bundleOption = nullptr;
    std::string bundle = "";
    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        bundle = GetClientBundleName();
        if (bundle.empty()) {
            return nullptr;
        }
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    bundleOption = new (std::nothrow) NotificationBundleOption(bundle, uid);
    if (bundleOption == nullptr) {
        return nullptr;
    }
    return bundleOption;
}

sptr<NotificationBundleOption> AdvancedNotificationService::GenerateValidBundleOption(
    const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is invalid!");
        return nullptr;
    }

    sptr<NotificationBundleOption> validBundleOption = nullptr;
    if (bundleOption->GetUid() <= 0) {
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        if (bundleManager != nullptr) {
            int32_t activeUserId = -1;
            if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
                ANS_LOGE("Failed to get active user id!");
                return validBundleOption;
            }
            int32_t uid = bundleManager->GetDefaultUidByBundleName(bundleOption->GetBundleName(), activeUserId);
            if (uid > 0) {
                validBundleOption = new (std::nothrow) NotificationBundleOption(bundleOption->GetBundleName(), uid);
                if (validBundleOption == nullptr) {
                    ANS_LOGE("Failed to create NotificationBundleOption instance");
                    return nullptr;
                }
            }
        }
    } else {
        validBundleOption = bundleOption;
    }
    return validBundleOption;
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

    sptr<NotificationSortingMap> sortingMap = new (std::nothrow) NotificationSortingMap(sortingList);
    if (sortingMap == nullptr) {
        ANS_LOGE("Failed to create NotificationSortingMap instance");
        return nullptr;
    }

    return sortingMap;
}

ErrCode AdvancedNotificationService::CheckCommonParams()
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    return ERR_OK;
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
            bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
            if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
                return ERR_ANS_NON_SYSTEM_APP;
            }
            targetBundle = GenerateValidBundleOption(bundleOption);
        }
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::FillRequestByKeys(const sptr<NotificationRequest> &oldRequest,
    const std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &newRequest)
{
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
        oldRequest->GetContent()->GetNotificationContent());
    auto liveViewExtraInfo = liveViewContent->GetExtraInfo();

    newRequest = sptr<NotificationRequest>::MakeSptr(*(oldRequest));
    auto requestLiveViewContent = std::make_shared<NotificationLiveViewContent>();

    requestLiveViewContent->SetLiveViewStatus(liveViewContent->GetLiveViewStatus());
    requestLiveViewContent->SetVersion(liveViewContent->GetVersion());
    requestLiveViewContent->SetLockScreenPicture(liveViewContent->GetLockScreenPicture());

    std::shared_ptr<AAFwk::WantParams> requestExtraInfo = std::make_shared<AAFwk::WantParams>();
    if (requestExtraInfo == nullptr) {
        ANS_LOGE("Failed to make extraInfos.");
        return ERR_ANS_TASK_ERR;
    }
    for (const auto &extraInfoKey : extraInfoKeys) {
        auto paramValue = liveViewExtraInfo->GetParam(extraInfoKey);
        if (paramValue != nullptr) {
            requestExtraInfo->SetParam(extraInfoKey, paramValue);
        }
    }
    requestLiveViewContent->SetExtraInfo(requestExtraInfo);

    auto requestContent = std::make_shared<NotificationContent>(requestLiveViewContent);
    newRequest->SetContent(requestContent);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::IsAllowedGetNotificationByFilter(
    const std::shared_ptr<NotificationRecord> &record, const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption->GetUid() == record->bundleOption->GetUid() &&
        bundleOption->GetBundleName() == record->bundleOption->GetBundleName()) {
        return ERR_OK;
    }
    ANS_LOGE("Get live view by filter failed because no permission.");
    return ERR_ANS_PERMISSION_DENIED;
}

void AdvancedNotificationService::SetAgentNotification(sptr<NotificationRequest>& notificationRequest,
    std::string& bundleName)
{
    auto bundleManager = BundleManagerHelper::GetInstance();
    int32_t activeUserId = -1;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANSR_LOGE("Failed to get active user id!");
        return;
    }

    notificationRequest->SetIsAgentNotification(true);
    notificationRequest->SetOwnerUserId(activeUserId);
    notificationRequest->SetOwnerBundleName(bundleName);
}

void AdvancedNotificationService::ExtendDumpForFlags(
    std::shared_ptr<NotificationFlags> notificationFlags, std::stringstream &stream)
{
    if (notificationFlags == nullptr) {
        ANS_LOGD("The notificationFlags is nullptr.");
        return;
    }
    stream << "\t\tReminderFlags : " << notificationFlags->GetReminderFlags() << "\n";
    bool isEnable = false;
    if (notificationFlags->IsSoundEnabled() == NotificationConstant::FlagStatus::OPEN) {
        isEnable = true;
    }
    stream << "\t\tSound : " << isEnable << "\n";
    isEnable = false;
    if (notificationFlags->IsVibrationEnabled() == NotificationConstant::FlagStatus::OPEN) {
        isEnable = true;
    }
    stream << "\t\tVibration : " << isEnable << "\n";
    stream << "\t\tLockScreenVisbleness : " << notificationFlags->IsLockScreenVisblenessEnabled() << "\n";
    stream << "\t\tBanner : " << notificationFlags->IsBannerEnabled() << "\n";
    stream << "\t\tLightScreen : " << notificationFlags->IsLightScreenEnabled() << "\n";
    stream << "\t\tStatusIcon : " << notificationFlags->IsStatusIconEnabled() << "\n";
}

ErrCode AdvancedNotificationService::ActiveNotificationDump(const std::string& bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
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
        if (recvUserId != SUBSCRIBE_USER_INIT && recvUserId != record->notification->GetRecvUserId()) {
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
            ANS_LOGD("GetOwnerUid larger than zero.");
            stream << "\tOwnerUid: " << record->request->GetOwnerUid() << "\n";
        } else {
            stream << "\tOwnerUid: " << record->request->GetCreatorUid() << "\n";
        }
        stream << "\tReceiverUserId: " << record->request->GetReceiverUserId() << "\n";
        stream << "\tDeliveryTime = " << TimeToString(record->request->GetDeliveryTime()) << "\n";
        stream << "\tNotification:\n";
        stream << "\t\tId: " << record->notification->GetId() << "\n";
        stream << "\t\tLabel: " << record->notification->GetLabel() << "\n";
        stream << "\t\tSlotType = " << record->request->GetSlotType() << "\n";
        ExtendDumpForFlags(record->request->GetFlags(), stream);
        ANS_LOGD("DumpInfo push stream.");
        dumpInfo.push_back(stream.str());
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RecentNotificationDump(const std::string& bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
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
        if (recvUserId != SUBSCRIBE_USER_INIT && recvUserId != recentNotification->notification->GetRecvUserId()) {
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
        stream << "\tReceiverUserId: " << notificationRequest.GetReceiverUserId() << "\n";
        stream << "\tDeliveryTime = " << TimeToString(notificationRequest.GetDeliveryTime()) << "\n";
        if (!recentNotification->isActive) {
            stream << "\tDeleteTime: " << TimeToString(recentNotification->deleteTime) << "\n";
            stream << "\tDeleteReason: " << recentNotification->deleteReason << "\n";
        }
        stream << "\tNotification:\n";
        stream << "\t\tId: " << recentNotification->notification->GetId() << "\n";
        stream << "\t\tLabel: " << recentNotification->notification->GetLabel() << "\n";
        stream << "\t\tSlotType = " << notificationRequest.GetSlotType() << "\n";
        ExtendDumpForFlags(notificationRequest.GetFlags(), stream);
        dumpInfo.push_back(stream.str());
    }
    return ERR_OK;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
ErrCode AdvancedNotificationService::DistributedNotificationDump(const std::string& bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
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
        if (recvUserId != SUBSCRIBE_USER_INIT && recvUserId != record->notification->GetRecvUserId()) {
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
        stream << "\tReceiverUserId: " << record->request->GetReceiverUserId() << "\n";
        stream << "\tDeliveryTime = " << TimeToString(record->request->GetDeliveryTime()) << "\n";
        stream << "\tNotification:\n";
        stream << "\t\tId: " << record->notification->GetId() << "\n";
        stream << "\t\tLabel: " << record->notification->GetLabel() << "\n";
        stream << "\t\tSlotType = " << record->request->GetSlotType() << "\n";
        ExtendDumpForFlags(record->request->GetFlags(), stream);
        dumpInfo.push_back(stream.str());
    }

    return ERR_OK;
}
#endif

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

void AdvancedNotificationService::OnBundleRemoved(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    notificationSvrQueue_->submit(std::bind([this, bundleOption]() {
        ANS_LOGD("ffrt enter!");
        ErrCode result = NotificationPreferences::GetInstance()->RemoveNotificationForBundle(bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("NotificationPreferences::RemoveNotificationForBundle failed: %{public}d", result);
        }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        DistributedPreferences::GetInstance()->DeleteDistributedBundleInfo(bundleOption);
        std::vector<std::string> keys = GetLocalNotificationKeys(bundleOption);
#else
        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
#endif
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto key : keys) {
            sptr<Notification> notification = nullptr;
            result = RemoveFromNotificationList(key, notification, true,
                NotificationConstant::PACKAGE_REMOVE_REASON_DELETE);
            if (result != ERR_OK) {
                continue;
            }

            if (notification != nullptr) {
                int32_t reason = NotificationConstant::PACKAGE_REMOVE_REASON_DELETE;
                UpdateRecentNotification(notification, true, reason);
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
                ExecBatchCancel(notifications, reason);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete("", "", notification);
#endif
            }
        }
        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::PACKAGE_REMOVE_REASON_DELETE);
        }
        BatchCancelTimer(timerIds);
        NotificationPreferences::GetInstance()->RemoveAnsBundleDbInfo(bundleOption);
        RemoveDoNotDisturbProfileTrustList(bundleOption);
        DeleteDuplicateMsgs(bundleOption);
    }));
    NotificationPreferences::GetInstance()->RemoveEnabledDbByBundle(bundleOption);
    NotificationPreferences::GetInstance()->RemoveSilentEnabledDbByBundle(bundleOption);
#ifdef ENABLE_ANS_AGGREGATION
    EXTENTION_WRAPPER->UpdateByBundle(bundleOption->GetBundleName(),
        NotificationConstant::PACKAGE_REMOVE_REASON_DELETE);
#endif

    if (!isCachedAppAndDeviceRelationMap_) {
        if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetAppAndDeviceRelationMap(
            appAndDeviceRelationMap_)) {
            ANS_LOGE("GetAppAndDeviceRelationMap failed");
            return;
        }
        isCachedAppAndDeviceRelationMap_ = true;
    }
    auto appAndDeviceRelation = appAndDeviceRelationMap_.find(bundleOption->GetBundleName());
    if (appAndDeviceRelation != appAndDeviceRelationMap_.end()) {
        SetAndPublishSubscriberExistFlag(appAndDeviceRelation->second, false);
    }
}

void AdvancedNotificationService::ExecBatchCancel(std::vector<sptr<Notification>> &notifications,
    int32_t &reason)
{
    if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
        std::vector<sptr<Notification>> currNotificationList = notifications;
        NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
            currNotificationList, nullptr, reason);
        notifications.clear();
    }
}

void AdvancedNotificationService::RemoveDoNotDisturbProfileTrustList(
    const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    int32_t userId = 0;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGE("Failed to get active user id.");
        return;
    }
    NotificationPreferences::GetInstance()->RemoveDoNotDisturbProfileTrustList(userId, bundleOption);
}

void AdvancedNotificationService::OnBundleDataAdd(const sptr<NotificationBundleOption> &bundleOption)
{
    CHECK_BUNDLE_OPTION_IS_INVALID(bundleOption)
    ANS_LOGI("bundle added, bundleName:%{public}s", bundleOption->GetBundleName().c_str());
    auto bundleInstall = [bundleOption, this]() {
        CHECK_BUNDLE_OPTION_IS_INVALID(bundleOption)
        AppExecFwk::BundleInfo bundleInfo;
        if (!GetBundleInfoByNotificationBundleOption(bundleOption, bundleInfo)) {
            ANS_LOGE("Failed to get BundleInfo using NotificationBundleOption.");
            return;
        }

        // In order to adapt to the publish reminder interface, currently only the input from the whitelist is written
        UpdateNotificationSwitchState(bundleOption, bundleInfo);
        if (bundleInfo.applicationInfo.allowEnableNotification) {
            SetSlotFlagsTrustlistsAsBundle(bundleOption);
            auto errCode = NotificationPreferences::GetInstance()->SetShowBadge(bundleOption, true);
            if (errCode != ERR_OK) {
                ANS_LOGE("Set badge enable error! code: %{public}d", errCode);
            }
        }
    };

    notificationSvrQueue_ != nullptr ? notificationSvrQueue_->submit(bundleInstall) : bundleInstall();
}

void AdvancedNotificationService::OnBundleDataUpdate(const sptr<NotificationBundleOption> &bundleOption)
{
    CHECK_BUNDLE_OPTION_IS_INVALID(bundleOption)
    ANS_LOGI("bundle update, bundleName:%{public}s", bundleOption->GetBundleName().c_str());
    AppExecFwk::BundleInfo bundleInfo;
    if (!GetBundleInfoByNotificationBundleOption(bundleOption, bundleInfo)) {
        ANS_LOGE("Failed to get BundleInfo using NotificationBundleOption.");
        return;
    }

    auto bundleUpdate = [bundleOption, bundleInfo, this]() {
        NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        auto errCode = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(
            bundleOption, state);
        if (errCode != ERR_OK) {
            ANS_LOGD("Get notification user option fail, need to insert data");
            OnBundleDataAdd(bundleOption);
            return;
        }
        
        bool isSystemDefault = (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF ||
                                state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
        if (isSystemDefault) {
            errCode = UpdateNotificationSwitchState(bundleOption, bundleInfo);
            if (errCode != ERR_OK) {
                ANS_LOGD("Update notification state error: %{public}d", errCode);
            }
        }
    };

    notificationSvrQueue_ != nullptr ? notificationSvrQueue_->submit(bundleUpdate) : bundleUpdate();
}

void AdvancedNotificationService::OnBootSystemCompleted()
{
    ANS_LOGD("Called.");
    InitNotificationEnableList();
    TryStartReminderAgentService();
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
void AdvancedNotificationService::OnScreenOn()
{
    ANS_LOGD("called");
    localScreenOn_ = true;
    DistributedScreenStatusManager::GetInstance()->SetLocalScreenStatus(true);
}

void AdvancedNotificationService::OnScreenOff()
{
    ANS_LOGD("called");
    localScreenOn_ = false;
    DistributedScreenStatusManager::GetInstance()->SetLocalScreenStatus(false);
}
#endif

void AdvancedNotificationService::OnDistributedKvStoreDeathRecipient()
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        DistributedNotificationManager::GetInstance()->OnDistributedKvStoreDeathRecipient();
#endif
    }));
}

ErrCode AdvancedNotificationService::GetTargetRecordList(const int32_t uid,
    NotificationConstant::SlotType slotType, NotificationContent::Type contentType,
    std::vector<std::shared_ptr<NotificationRecord>>& recordList)
{
    for (auto& notification : notificationList_) {
        if (notification->request != nullptr && notification->request->GetSlotType()== slotType &&
            notification->request->GetNotificationType() == contentType &&
            notification->request->GetCreatorUid() == uid) {
            recordList.emplace_back(notification);
        }
    }
    if (recordList.empty()) {
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetCommonTargetRecordList(const int32_t uid,
    NotificationConstant::SlotType slotType, NotificationContent::Type contentType,
    std::vector<std::shared_ptr<NotificationRecord>>& recordList)
{
    for (auto& notification : notificationList_) {
        if (notification->request != nullptr && notification->request->IsCommonLiveView()) {
            auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
                notification->request->GetContent()->GetNotificationContent());
            if (notification->request->GetCreatorUid() == uid &&
                notification->request->GetSlotType()== slotType &&
                notification->request->GetNotificationType() == contentType &&
                liveViewContent->GetIsOnlyLocalUpdate()) {
                    recordList.emplace_back(notification);
            }
        }
    }
    if (recordList.empty()) {
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
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

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
void AdvancedNotificationService::OnDistributedPublish(
    const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    int32_t activeUserId = -1;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANS_LOGE("Failed to get active user id!");
        return;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return;
    }
    const int32_t callingUid = IPCSkeleton::GetCallingUid();
    notificationSvrQueue_->submit(std::bind([this, deviceId, bundleName, request, activeUserId, callingUid]() {
        ANS_LOGD("ffrt enter!");
        if (!CheckDistributedNotificationType(request)) {
            ANS_LOGD("CheckDistributedNotificationType is false.");
            return;
        }

        int32_t uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, activeUserId);
        if (uid <= 0) {
            if (CheckPublishWithoutApp(activeUserId, request)) {
                request->SetOwnerBundleName(FOUNDATION_BUNDLE_NAME);
                request->SetCreatorBundleName(FOUNDATION_BUNDLE_NAME);
            } else {
                ANS_LOGE("bundle does not exit and make off!");
                return;
            }
        }
        std::string bundle = request->GetOwnerBundleName();
        request->SetCreatorUid(BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundle, activeUserId));
        sptr<NotificationBundleOption> bundleOption =
            GenerateValidBundleOption(new NotificationBundleOption(bundle, 0));

        std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
        if (record == nullptr) {
            ANS_LOGD("record is nullptr.");
            return;
        }
        record->request = request;
        record->notification = new (std::nothrow) Notification(deviceId, request);
        if (record->notification == nullptr) {
            ANS_LOGE("Failed to create Notification instance");
            return;
        }
        record->bundleOption = bundleOption;
        record->deviceId = deviceId;
        record->bundleName = bundleName;
        SetNotificationRemindType(record->notification, false);

        ErrCode result = AssignValidNotificationSlot(record, bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
            return;
        }

        result = Filter(record);
        if (result != ERR_OK) {
            ANS_LOGE("Reject by filters: %{public}d", result);
            return;
        }

        bool isNotificationExists = IsNotificationExists(record->notification->GetKey());
        result = FlowControlService::GetInstance().FlowControl(record, callingUid, isNotificationExists);
        if (result != ERR_OK) {
            return;
        }
        result = PublishInNotificationList(record);
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
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANS_LOGE("Failed to get active user id!");
        return;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    const int32_t callingUid = IPCSkeleton::GetCallingUid();
    notificationSvrQueue_->submit(std::bind([this, deviceId, bundleName, request, activeUserId, callingUid]() {
        ANS_LOGD("ffrt enter!");
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
        record->notification = new (std::nothrow) Notification(deviceId, request);
        if (record->notification == nullptr) {
            ANS_LOGE("Failed to create Notification instance");
            return;
        }
        record->bundleOption = bundleOption;
        record->deviceId = deviceId;
        record->bundleName = bundleName;
        SetNotificationRemindType(record->notification, false);

        ErrCode result = AssignValidNotificationSlot(record, bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Can not assign valid slot!");
            return;
        }

        result = Filter(record);
        if (result != ERR_OK) {
            ANS_LOGE("Reject by filters: %{public}d", result);
            return;
        }
        bool isNotificationExists = IsNotificationExists(record->notification->GetKey());
        result = FlowControlService::GetInstance().FlowControl(record, callingUid, isNotificationExists);
        if (result != ERR_OK) {
            return;
        }
        if (IsNotificationExists(record->notification->GetKey())) {
            if (record->request->IsAlertOneTime()) {
                CloseAlert(record);
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
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    notificationSvrQueue_->submit(std::bind([this, deviceId, bundleName, label, id]() {
        ANS_LOGD("ffrt enter!");
        int32_t activeUserId = -1;
        if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
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
            strcmp(deviceId.c_str(), localDeviceInfo.deviceId) == 0) {
            recordDeviceId = "";
        } else {
            recordDeviceId = deviceId;
        }

        if (bundleOption == nullptr) {
            ANS_LOGE("Failed to get bundleOption!");
            return;
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
            CancelTimer(notification->GetAutoDeletedTimer());
            NotificationSubscriberManager::GetInstance()->NotifyCanceled(notification, nullptr, reason);
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

bool AdvancedNotificationService::CheckDistributedNotificationType(const sptr<NotificationRequest> &request)
{
    auto deviceTypeList = request->GetNotificationDistributedOptions().GetDevicesSupportDisplay();
    if (deviceTypeList.empty()) {
        return true;
    }

    DistributedDatabase::DeviceInfo localDeviceInfo;
    DistributedNotificationManager::GetInstance()->GetLocalDeviceInfo(localDeviceInfo);
    for (auto device : deviceTypeList) {
        if (atoi(device.c_str()) == localDeviceInfo.deviceTypeId) {
            return true;
        }
    }
    return false;
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

std::vector<std::string> AdvancedNotificationService::GetLocalNotificationKeys(
    const sptr<NotificationBundleOption> &bundleOption)
{
    std::vector<std::string> keys;

    for (auto record : notificationList_) {
        if ((bundleOption != nullptr) &&
            ((record->bundleOption->GetBundleName() != bundleOption->GetBundleName()) ||
            (record->bundleOption->GetUid() != bundleOption->GetUid())) &&
            record->deviceId.empty()) {
            continue;
        }
        keys.push_back(record->notification->GetKey());
    }

    return keys;
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
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    if (!notification->GetNotificationRequestPoint()->GetNotificationDistributedOptions().IsDistributed()) {
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
#endif

ErrCode AdvancedNotificationService::PrepareContinuousTaskNotificationRequest(
    const sptr<NotificationRequest> &request, const int32_t &uid)
{
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    request->SetCreatorPid(pid);
    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }

    ErrCode result = CheckPictureSize(request);
    return result;
}

ErrCode AdvancedNotificationService::IsSupportTemplate(const std::string& templateName, bool &support)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        support = false;
        result = NotificationPreferences::GetInstance()->GetTemplateSupported(templateName, support);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

void AdvancedNotificationService::TriggerRemoveWantAgent(const sptr<NotificationRequest> &request,
    int32_t removeReason, bool isThirdParty)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s %{public}d %{public}d", __FUNCTION__, isThirdParty, removeReason);

    if ((request == nullptr) || (request->GetRemovalWantAgent() == nullptr)) {
        return;
    }

    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    if (!isThirdParty) {
        want->SetParam("deleteReason", removeReason);
    }
    OHOS::AbilityRuntime::WantAgent::TriggerInfo triggerInfo("", nullptr, want, 0);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = request->GetRemovalWantAgent();
    sptr<AbilityRuntime::WantAgent::CompletedDispatcher> data;
    AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(agent, nullptr, triggerInfo, data, nullptr);
}

void AdvancedNotificationService::OnResourceRemove(int32_t userId)
{
    OnUserRemoved(userId);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("ffrt enter!");
        NotificationPreferences::GetInstance()->RemoveSettings(userId);
    }));
}

void AdvancedNotificationService::OnBundleDataCleared(const sptr<NotificationBundleOption> &bundleOption)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
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
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                std::vector<sptr<Notification>> currNotificationList = notifications;
                NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                    currNotificationList, nullptr, NotificationConstant::PACKAGE_CHANGED_REASON_DELETE);
                notifications.clear();
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::PACKAGE_CHANGED_REASON_DELETE);
        }
        BatchCancelTimer(timerIds);
    }));
}

bool AdvancedNotificationService::CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
#ifdef ANS_DISABLE_FA_MODEL
    return false;
#endif
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        return false;
    }
    return bundleManager->CheckApiCompatibility(bundleOption);
}

void AdvancedNotificationService::OnUserRemoved(const int32_t &userId)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not system app.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 5)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, NotificationConstant::USER_REMOVED_REASON_DELETE, message);
        ANS_LOGE("%{public}s", message.c_str());
    }
    DeleteAllByUserInner(userId, NotificationConstant::USER_REMOVED_REASON_DELETE, true);
}

void AdvancedNotificationService::OnUserStopped(int32_t userId)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
 
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        DeleteAllByUserStopped(userId);
    }));
}

void AdvancedNotificationService::DeleteAllByUserStopped(int32_t userId)
{
    std::vector<std::string> keys = GetNotificationKeys(nullptr);
    std::vector<sptr<Notification>> notifications;
    std::vector<uint64_t> timerIds;
    for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::string deviceId;
        std::string bundleName;
        GetDistributedInfo(key, deviceId, bundleName);
#endif
        sptr<Notification> notification = nullptr;
        for (auto record : notificationList_) {
            if ((record->notification->GetKey() == key) &&
                ((record->notification->GetRecvUserId() == userId) ||
                (record->notification->GetRecvUserId() == ZERO_USER_ID))) {
                ProcForDeleteLiveView(record);
                notification = record->notification;
                notificationList_.remove(record);
                break;
            }
        }
 
        if (notification == nullptr) {
            continue;
        }
        if (notification->GetRecvUserId() == userId || notification->GetRecvUserId() == ZERO_USER_ID) {
            UpdateRecentNotification(notification, true, NotificationConstant::USER_LOGOUT_REASON_DELETE);
            notifications.emplace_back(notification);
            timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
        }
        if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
            SendNotificationsOnCanceled(notifications, nullptr, NotificationConstant::USER_LOGOUT_REASON_DELETE);
        }
    }
 
    if (!notifications.empty()) {
        NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
            notifications, nullptr, NotificationConstant::USER_LOGOUT_REASON_DELETE);
    }
    BatchCancelTimer(timerIds);
}

ErrCode AdvancedNotificationService::DeleteAllByUser(int32_t userId)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        std::string message = "not system app.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 5)
            .ErrorCode(ERR_ANS_NON_SYSTEM_APP);
        ReportDeleteFailedEventPush(haMetaMessage, NotificationConstant::APP_REMOVE_ALL_USER_REASON_DELETE, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("No acl permission.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return DeleteAllByUserInner(userId, NotificationConstant::APP_REMOVE_ALL_USER_REASON_DELETE);
}

ErrCode AdvancedNotificationService::DeleteAllByUserInner(const int32_t &userId, int32_t deleteReason,
    bool isAsync, bool removeAll)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (userId <= SUBSCRIBE_USER_INIT) {
        std::string message = "userId is error.";
        OHOS::Notification::HaMetaMessage haMetaMessage = HaMetaMessage(6, 6)
            .ErrorCode(ERR_ANS_INVALID_PARAM);
        ReportDeleteFailedEventPush(haMetaMessage, deleteReason, message);
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        std::string message = "Serial queue is invalid.";
        ANS_LOGE("%{public}s", message.c_str());
        return ERR_ANS_INVALID_PARAM;
    }
    std::shared_ptr<ErrCode> result = std::make_shared<ErrCode>(ERR_OK);
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::string> keys = GetNotificationKeys(nullptr);
        std::vector<sptr<Notification>> notifications;
        std::vector<uint64_t> timerIds;
        for (auto key : keys) {
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            std::string deviceId;
            std::string bundleName;
            GetDistributedInfo(key, deviceId, bundleName);
#endif
            sptr<Notification> notification = nullptr;

            *result = RemoveFromNotificationListForDeleteAll(key, userId, notification, removeAll);
            if ((*result != ERR_OK) || (notification == nullptr)) {
                continue;
            }

            if (notification->GetUserId() == userId) {
                UpdateRecentNotification(notification, true, deleteReason);
                notifications.emplace_back(notification);
                timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete(deviceId, bundleName, notification);
#endif
            }
            if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                SendNotificationsOnCanceled(notifications, nullptr, deleteReason);
            }
        }

        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, deleteReason);
        }
        BatchCancelTimer(timerIds);
        *result = ERR_OK;
    }));

    if (!isAsync) {
        notificationSvrQueue_->wait(handler);
        return *result;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
    int32_t recvUserId, std::vector<std::string> &dumpInfo)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    auto callerToken = IPCSkeleton::GetCallingTokenID();
    if (!AccessTokenHelper::VerifyShellToken(callerToken) && !AccessTokenHelper::VerifyNativeToken(callerToken)) {
        ANS_LOGE("Not subsystem or shell request");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_ANS_NOT_ALLOWED;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (cmd == ACTIVE_NOTIFICATION_OPTION) {
            result = ActiveNotificationDump(bundle, userId, recvUserId, dumpInfo);
        } else if (cmd == RECENT_NOTIFICATION_OPTION) {
            result = RecentNotificationDump(bundle, userId, recvUserId, dumpInfo);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        } else if (cmd == DISTRIBUTED_NOTIFICATION_OPTION) {
            result = DistributedNotificationDump(bundle, userId, recvUserId, dumpInfo);
#endif
        } else if (cmd.substr(0, cmd.find_first_of(" ", 0)) == SET_RECENT_COUNT_OPTION) {
            result = SetRecentNotificationCount(cmd.substr(cmd.find_first_of(" ", 0) + 1));
        } else {
            result = ERR_ANS_INVALID_PARAM;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

int AdvancedNotificationService::Dump(int fd, const std::vector<std::u16string> &args)
{
    ANS_LOGD("called");
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
    ShellDump(cmdValue, "", SUBSCRIBE_USER_INIT, SUBSCRIBE_USER_INIT, dumpInfo);
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

ErrCode AdvancedNotificationService::SetRequestBundleInfo(const sptr<NotificationRequest> &request,
    int32_t uid, std::string &bundle)
{
    if (!bundle.empty()) {
        if (request->GetCreatorBundleName().empty()) {
            request->SetCreatorBundleName(bundle);
        }
        if (request->GetOwnerBundleName().empty()) {
            request->SetOwnerBundleName(bundle);
        }
    } else {
        if (!request->GetCreatorBundleName().empty()) {
            bundle = request->GetCreatorBundleName();
        }
        if (!request->GetOwnerBundleName().empty()) {
            bundle = request->GetOwnerBundleName();
        }
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::PrePublishNotificationBySa(const sptr<NotificationRequest> &request,
    int32_t uid, std::string &bundle)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_4, EventBranchId::BRANCH_2);
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        ANS_LOGE("failed to get bundleManager!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundle = bundleManager->GetBundleNameByUid(uid);
    ErrCode result = SetRequestBundleInfo(request, uid, bundle);
    if (result != ERR_OK) {
        message.ErrorCode(result);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }

    request->SetCreatorPid(IPCSkeleton::GetCallingPid());
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (request->GetCreatorUserId() == SUBSCRIBE_USER_INIT) {
        if (request->GetCreatorUid() != 0) {
            OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(request->GetCreatorUid(), userId);
        } else {
            OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(IPCSkeleton::GetCallingUid(), userId);
        }
        request->SetCreatorUserId(userId);
    } else {
        userId = request->GetCreatorUserId();
    }

    if (request->GetOwnerUserId() == SUBSCRIBE_USER_INIT && request->GetOwnerUid() != DEFAULT_UID) {
        int32_t ownerUserId = SUBSCRIBE_USER_INIT;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(request->GetOwnerUid(), ownerUserId);
        request->SetOwnerUserId(ownerUserId);
    }

    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }
    result = CheckPictureSize(request);
    if (result != ERR_OK) {
        message.ErrorCode(result).Message("Failed to check picture size", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }
    if (request->GetOwnerUid() == DEFAULT_UID) {
        request->SetOwnerUid(request->GetCreatorUid());
    }
    if (request->GetOwnerBundleName().empty()) {
        request->SetOwnerBundleName(request->GetCreatorBundleName());
    }
    request->SetAppName(BundleManagerHelper::GetInstance()->GetBundleLabel(request->GetOwnerBundleName()));
    return ERR_OK;
}

ErrCode AdvancedNotificationService::PrePublishRequest(const sptr<NotificationRequest> &request)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_9, EventBranchId::BRANCH_0);
    if (!InitPublishProcess()) {
        return ERR_ANS_NO_MEMORY;
    }
    AnsStatus ansStatus = publishProcess_[request->GetSlotType()]->PublishPreWork(request, false);
    ErrCode result = ansStatus.GetErrCode();
    if (result != ERR_OK) {
        message.BranchId(EventBranchId::BRANCH_0).ErrorCode(result).Message("publish prework failed", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }
    result = CheckUserIdParams(request->GetReceiverUserId());
    if (result != ERR_OK) {
        message.BranchId(EventBranchId::BRANCH_1).ErrorCode(result).Message("User is invalid", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }

    if (request->GetCreatorUid() <= 0) {
        message.BranchId(EventBranchId::BRANCH_2).ErrorCode(ERR_ANS_INVALID_UID)
            .Message("createUid failed" + std::to_string(request->GetCreatorUid()), true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_INVALID_UID;
    }
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        ANS_LOGE("failed to get bundleManager!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    request->SetCreatorPid(IPCSkeleton::GetCallingPid());
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (request->GetCreatorUserId() == SUBSCRIBE_USER_INIT) {
        OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(request->GetCreatorUid(), userId);
        request->SetCreatorUserId(userId);
    }

    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }
    result = CheckPictureSize(request);
    if (result != ERR_OK) {
        message.ErrorCode(result).Message("Failed to check picture size", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }
    return ERR_OK;
}

uint64_t AdvancedNotificationService::StartAutoDelete(const std::shared_ptr<NotificationRecord> &record,
    int64_t deleteTimePoint, int32_t reason)
{
    ANS_LOGD("called");

    wptr<AdvancedNotificationService> wThis = this;
    auto triggerFunc = [wThis, record, reason] {
        sptr<AdvancedNotificationService> sThis = wThis.promote();
        if (sThis != nullptr) {
            sThis->TriggerAutoDelete(record->notification->GetKey(), reason);
            if (record->finish_status != NotificationConstant::DEFAULT_FINISH_STATUS) {
                sThis->SendLiveViewUploadHiSysEvent(record, record->finish_status);
            }
        }
    };
    std::shared_ptr<NotificationTimerInfo> notificationTimerInfo = std::make_shared<NotificationTimerInfo>();
    notificationTimerInfo->SetCallbackInfo(triggerFunc);

    sptr<MiscServices::TimeServiceClient> timer = MiscServices::TimeServiceClient::GetInstance();
    if (timer == nullptr) {
        ANS_LOGE("Failed to start timer due to get TimeServiceClient is null.");
        return 0;
    }
    uint64_t timerId = timer->CreateTimer(notificationTimerInfo);
    timer->StartTimer(timerId, deleteTimePoint);
    return timerId;
}

void AdvancedNotificationService::CancelTimer(uint64_t timerId)
{
    ANS_LOGD("called");
    if (timerId == NotificationConstant::INVALID_TIMER_ID) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(timerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

void AdvancedNotificationService::BatchCancelTimer(std::vector<uint64_t> timerIds)
{
    ANS_LOGD("called");
    for (uint64_t timerId : timerIds) {
        CancelTimer(timerId);
    }
}

void AdvancedNotificationService::SendNotificationsOnCanceled(std::vector<sptr<Notification>> &notifications,
    const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason)
{
    std::vector<sptr<Notification>> currNotifications;
    for (auto notification : notifications) {
        currNotifications.emplace_back(notification);
    }
    NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
        currNotifications, nullptr, deleteReason);
    notifications.clear();
}

void AdvancedNotificationService::SetSlotFlagsTrustlistsAsBundle(const sptr<NotificationBundleOption> &bundleOption)
{
    if (!NotificationPreferences::GetInstance()->IsNotificationSlotFlagsExists(bundleOption) &&
        DelayedSingleton<NotificationConfigParse>::GetInstance()->IsBannerEnabled(bundleOption->GetBundleName())) {
        uint32_t slotFlags = 0b111111;
        ErrCode saveRef = NotificationPreferences::GetInstance()->SetNotificationSlotFlagsForBundle(
            bundleOption, slotFlags);
        if (saveRef != ERR_OK) {
            ANS_LOGE("Set slotflags error! code: %{public}d", saveRef);
        }
        UpdateSlotReminderModeBySlotFlags(bundleOption, slotFlags);
    }
}

ErrCode AdvancedNotificationService::UpdateNotificationSwitchState(
    const sptr<NotificationBundleOption> &bundleOption, const AppExecFwk::BundleInfo &bundleInfo)
{
    ANS_LOGD("called");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_9);
    NotificationConstant::SWITCH_STATE targetState = bundleInfo.applicationInfo.allowEnableNotification ?
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
        NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;

    NotificationConstant::SWITCH_STATE currentState = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    ErrCode result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(
        bundleOption, currentState);
    if (result != ERR_OK) {
        ANS_LOGI("Initialize %{public}s to %{public}s",
            bundleOption->GetBundleName().c_str(),
            (targetState == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) ?
                "SYSTEM_DEFAULT_ON" : "SYSTEM_DEFAULT_OFF");
        message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid())
            + "_st" + std::to_string(static_cast<int32_t>(targetState)));
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(
            bundleOption, targetState);
    }

    bool isSystemDefaultState = (currentState == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
                            currentState == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
    if (isSystemDefaultState && (currentState != targetState)) {
        ANS_LOGI("Updating system default state for %{public}s : %{public}d -> %{public}d",
            bundleOption->GetBundleName().c_str(),
            static_cast<int32_t>(currentState),
            static_cast<int32_t>(targetState));
        message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid())
            + "_st" + std::to_string(static_cast<int32_t>(targetState))).BranchId(BRANCH_10);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(
            bundleOption, targetState);
    }
    return ERR_OK;
}

void AdvancedNotificationService::InitNotificationEnableList()
{
    auto task = [&]() {
        std::vector<AppExecFwk::BundleInfo> bundleInfos = GetBundlesOfActiveUser();
        for (const auto &bundleInfo : bundleInfos) {
            sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
                bundleInfo.applicationInfo.bundleName, bundleInfo.uid);
            if (bundleOption == nullptr) {
                ANS_LOGE("New bundle option obj error! bundlename:%{public}s",
                    bundleInfo.applicationInfo.bundleName.c_str());
                continue;
            }
            ErrCode result = UpdateNotificationSwitchState(bundleOption, bundleInfo);
            if (result != ERR_OK) {
                ANS_LOGE("Update switch state error. code: %{public}d", result);
            }

            if (bundleInfo.applicationInfo.allowEnableNotification) {
                result = NotificationPreferences::GetInstance()->SetShowBadge(bundleOption, true);
                if (result != ERR_OK) {
                    ANS_LOGE("Set badge enable error! code: %{public}d", result);
                }
                SetSlotFlagsTrustlistsAsBundle(bundleOption);
            }
        }
    };
    notificationSvrQueue_ != nullptr ? notificationSvrQueue_->submit(task) : task();
}

bool AdvancedNotificationService::GetBundleInfoByNotificationBundleOption(
    const sptr<NotificationBundleOption> &bundleOption, AppExecFwk::BundleInfo &bundleInfo)
{
    CHECK_BUNDLE_OPTION_IS_INVALID_WITH_RETURN(bundleOption, false)
    int32_t callingUserId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleOption->GetUid(), callingUserId);
    auto bundleMgr = BundleManagerHelper::GetInstance();
    if (bundleMgr == nullptr) {
        ANS_LOGE("bundleMgr instance error!");
        return false;
    }
    if (!bundleMgr->GetBundleInfoByBundleName(bundleOption->GetBundleName(), callingUserId, bundleInfo)) {
        ANS_LOGE("Get bundle info error!");
        return false;
    }
    return true;
}

ErrCode AdvancedNotificationService::CheckBundleOptionValid(sptr<NotificationBundleOption> &bundleOption)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_7, EventBranchId::BRANCH_8);
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Bundle option is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    message.Message(bundleOption->GetBundleName() + "_" +std::to_string(bundleOption->GetUid()));
    int32_t activeUserId = 0;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANS_LOGE("Failed to get active user id.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append("Failed to get bundle manager.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE("Failed to get bundle manager.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    int32_t uid = bundleManager->GetDefaultUidByBundleName(bundleOption->GetBundleName(), activeUserId);
    if (uid == -1) {
        if (bundleOption->GetUid() > DEFAULT_UID) {
            uid = bundleOption->GetUid();
        } else {
            message.ErrorCode(ERR_ANS_INVALID_BUNDLE).Append("Bundle name was not found.");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            ANS_LOGE("The specified bundle name was not found.");
            return ERR_ANS_INVALID_BUNDLE;
        }
    }

    if (bundleOption->GetUid() > 0) {
        return ERR_OK;
    }

    bundleOption->SetUid(uid);
    return ERR_OK;
}

sptr<NotificationBundleOption> AdvancedNotificationService::GenerateValidBundleOptionV2(
    const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("bundleOption or bundle name is invalid!");
        return nullptr;
    }

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        return nullptr;
    }

    int32_t activeUserId = -1;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANS_LOGE("Failed to get active user id!");
        return nullptr;
    }

    int32_t actualUid = bundleManager->GetDefaultUidByBundleName(bundleOption->GetBundleName(), activeUserId);
    if (actualUid < 0) {
        ANS_LOGE("Bundle name %{public}s does not exist in userId %{public}d",
            bundleOption->GetBundleName().c_str(), activeUserId);
        return nullptr;
    }

    sptr<NotificationBundleOption> validBundleOption = nullptr;
    if (bundleOption->GetUid() <= 0) {
        validBundleOption = new (std::nothrow) NotificationBundleOption(bundleOption->GetBundleName(), actualUid);
        if (validBundleOption == nullptr) {
            ANS_LOGE("Failed to create NotificationBundleOption instance");
            return nullptr;
        }
    } else {
        std::string actualBundleName = bundleManager->GetBundleNameByUid(bundleOption->GetUid());
        if (actualBundleName != bundleOption->GetBundleName()) {
            ANS_LOGE("Bundle name mismatch: expected %{public}s, actual %{public}s",
                actualBundleName.c_str(), bundleOption->GetBundleName().c_str());
            return nullptr;
        }
        validBundleOption = bundleOption;
    }
    return validBundleOption;
}

sptr<NotificationBundleOption> AdvancedNotificationService::GenerateCloneValidBundleOption(
    const sptr<NotificationBundleOption> &bundleOption)
{
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("bundleOption or bundle name is invalid!");
        return nullptr;
    }

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        return nullptr;
    }

    int32_t activeUserId = -1;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(activeUserId) != ERR_OK) {
        ANS_LOGE("Failed to get active user id!");
        return nullptr;
    }

    int32_t actualUid = bundleManager->GetDefaultUidByBundleName(bundleOption->GetBundleName(), activeUserId);
    if (actualUid < 0) {
        ANS_LOGE("Bundle name %{public}s does not exist in userId %{public}d",
            bundleOption->GetBundleName().c_str(), activeUserId);
        return nullptr;
    }

    sptr<NotificationBundleOption> validBundleOption = nullptr;
    validBundleOption = new (std::nothrow) NotificationBundleOption(bundleOption->GetBundleName(), actualUid);
    if (validBundleOption == nullptr) {
        ANS_LOGE("Failed to create CloneNotificationBundleOption instance");
        return nullptr;
    }
    return validBundleOption;
}

std::vector<AppExecFwk::BundleInfo> AdvancedNotificationService::GetBundlesOfActiveUser()
{
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    auto bundleMgr = BundleManagerHelper::GetInstance();
    if (bundleMgr == nullptr) {
        ANS_LOGE("Get bundle mgr error!");
        return bundleInfos;
    }

    std::vector<int32_t> activeUserId;
    OsAccountManagerHelper::GetInstance().GetAllActiveOsAccount(activeUserId);
    if (activeUserId.empty()) {
        activeUserId.push_back(MAIN_USER_ID);
    }
    AppExecFwk::BundleFlag flag = AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT;
    for (auto &itemUser: activeUserId) {
        std::vector<AppExecFwk::BundleInfo> infos;
        if (!bundleMgr->GetBundleInfos(flag, infos, itemUser)) {
            ANS_LOGW("Get bundle infos error");
            continue;
        }
        bundleInfos.insert(bundleInfos.end(), infos.begin(), infos.end());
    }

    return bundleInfos;
}

void AdvancedNotificationService::CloseAlert(const std::shared_ptr<NotificationRecord> &record)
{
    record->notification->SetEnableLight(false);
    record->notification->SetEnableSound(false);
    record->notification->SetEnableVibration(false);
    record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::SOUND_FLAG, false);
    record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::LIGHTSCREEN_FLAG, false);
    record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::VIBRATION_FLAG, false);
    record->request->SetDistributedFlagBit(NotificationConstant::ReminderFlag::BANNER_FLAG, false);
    ANS_LOGI("SetFlags-CloseAlert, flags = %{public}d", record->request->GetFlags()->GetReminderFlags());
}

bool AdvancedNotificationService::AllowUseReminder(const std::string& bundleName)
{
    int32_t userId = DEFAULT_UID;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    int32_t uid = BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId);
    if (VerifyCloudCapability(uid, REMINDER_CAPABILITY)) {
        return true;
    }
    if (DelayedSingleton<NotificationConfigParse>::GetInstance()->IsReminderEnabled(bundleName)) {
        return true;
    }
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
    int32_t ctrlResult = EXTENTION_WRAPPER->ReminderControl(bundleName);
    return ctrlResult == ERR_OK;
#else
    return true;
#endif
}

ErrCode AdvancedNotificationService::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    isAllowUseReminder = AllowUseReminder(bundleName);
    return ERR_OK;
}

void AdvancedNotificationService::ResetDistributedEnabled()
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue is nullptr");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        std::string value;
        NotificationPreferences::GetInstance()->GetKvFromDb(KEY_TABLE_VERSION, value, ZERO_USER_ID);
        if (!value.empty()) {
            return;
        }
        ANS_LOGI("start ResetDistributedEnabled");
        std::unordered_map<std::string, std::string> oldValues;
        NotificationPreferences::GetInstance()->GetBatchKvsFromDb(
            OLD_KEY_BUNDLE_DISTRIBUTED_ENABLE_NOTIFICATION, oldValues, ZERO_USER_ID);
        if (oldValues.empty()) {
            NotificationPreferences::GetInstance()->SetKvToDb(
                KEY_TABLE_VERSION, std::to_string(MIN_VERSION), ZERO_USER_ID);
            return;
        }
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        std::vector<std::string> delKeys;
        for (auto iter : oldValues) {
            std::vector<std::string> keywordVector;
            StringUtils::Split(iter.first, SPLIT_FLAG, keywordVector);
            delKeys.push_back(iter.first);
            if (keywordVector.size() != KEYWORD_SIZE) {
                continue;
            }
            std::string bundleName = keywordVector[1];
            int32_t activeUserId = atoi(keywordVector[2].c_str());
            std::string deviceType = keywordVector[3];
            bool enabled = atoi(iter.second.c_str());
            int32_t uid = bundleManager->GetDefaultUidByBundleName(bundleName, activeUserId);
            if (uid <= 0) {
                continue;
            }
            sptr<NotificationBundleOption> bundleOption =
                new NotificationBundleOption(bundleName, uid);
            ErrCode result =  NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(
                bundleOption, deviceType, enabled);
            if (result != ERR_OK) {
                ANS_LOGE("SetDistributeEnabled failed! key:%{public}s, uid:%{public}d",
                    iter.first.c_str(), uid);
            }
        }
        NotificationPreferences::GetInstance()->DeleteBatchKvFromDb(delKeys, ZERO_USER_ID);
        NotificationPreferences::GetInstance()->SetKvToDb(
            KEY_TABLE_VERSION, std::to_string(MIN_VERSION), ZERO_USER_ID);
    }));
}

ErrCode AdvancedNotificationService::OnRecoverLiveView(
    const std::vector<std::string> &keys)
{
    ANS_LOGD("called");

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    std::vector<sptr<Notification>> notifications;
    int32_t removeReason = NotificationConstant::RECOVER_LIVE_VIEW_DELETE;
    std::vector<uint64_t> timerIds;
    for (auto key : keys) {
        ANS_LOGI("BatchRemoveByKeys key = %{public}s", key.c_str());
        sptr<Notification> notification = nullptr;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
        std::string deviceId;
        std::string bundleName;
        GetDistributedInfo(key, deviceId, bundleName);
#endif
        ErrCode result = RemoveFromNotificationList(key, notification, true, removeReason);
        if (result != ERR_OK) {
            continue;
        }
        if (notification != nullptr) {
            notifications.emplace_back(notification);
            timerIds.emplace_back(notification->GetAutoDeletedTimer());
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            DoDistributedDelete(deviceId, bundleName, notification);
#endif
        }
        if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
            std::vector<sptr<Notification>> currNotificationList = notifications;
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                currNotificationList, nullptr, removeReason);
            notifications.clear();
        }
    }

    if (!notifications.empty()) {
        NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(notifications, nullptr, removeReason);
    }
    BatchCancelTimer(timerIds);
    return ERR_OK;
}

sptr<NotificationRingtoneInfo> GetRingtoneInfoForClone(NotificationRingtoneInfo ringtoneInfo)
{
    sptr<NotificationRingtoneInfo> ringtoneInfoPtr = new (std::nothrow) NotificationRingtoneInfo();
    if (ringtoneInfoPtr == nullptr) {
        ANS_LOGW("New info failed.");
        return nullptr;
    }
    ringtoneInfoPtr->SetRingtoneType(ringtoneInfo.GetRingtoneType());
    ringtoneInfoPtr->SetRingtoneTitle(ringtoneInfo.GetRingtoneTitle());
    ringtoneInfoPtr->SetRingtoneFileName(ringtoneInfo.GetRingtoneFileName());
    ringtoneInfoPtr->SetRingtoneUri(ringtoneInfo.GetRingtoneUri());
    return ringtoneInfoPtr;
}

void AdvancedNotificationService::UpdateCloneBundleInfoForRingtone(NotificationRingtoneInfo ringtoneInfo,
    const sptr<NotificationBundleOption> bundle, const NotificationCloneBundleInfo cloneBundleInfo)
{
    if (ringtoneInfo.GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT) {
        sptr<NotificationRingtoneInfo> oldRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
        auto result = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundle, oldRingtoneInfo);
        if (result == ERR_OK) {
            NotificationPreferences::GetInstance()->RemoveRingtoneInfoByBundle(bundle);
            ANSR_LOGI("Remove current ringtone %{public}s %{public}s.", bundle->GetBundleName().c_str(),
                oldRingtoneInfo->GetRingtoneUri().c_str());
        }
        return;
    }

    // clear last clone save ringtone info by current clone ringtone info, that last info is not set.
    int32_t userId = -1;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANSR_LOGW("Failed to get active user id!");
        return;
    }
    NotificationRingtoneInfo lastCloneRingtone;
    NotificationPreferences::GetInstance()->GetCloneRingtoneInfo(userId, cloneBundleInfo, lastCloneRingtone);
    if (lastCloneRingtone.GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT) {
        if (lastCloneRingtone.GetRingtoneFileName() != ringtoneInfo.GetRingtoneFileName() ||
            lastCloneRingtone.GetRingtoneType() != ringtoneInfo.GetRingtoneType() ||
            lastCloneRingtone.GetRingtoneUri() != ringtoneInfo.GetRingtoneUri() ||
            lastCloneRingtone.GetRingtoneTitle() != ringtoneInfo.GetRingtoneTitle()) {
            SystemSoundHelper::GetInstance()->RemoveCustomizedTone(lastCloneRingtone.GetRingtoneUri());
        }
        NotificationPreferences::GetInstance()->DeleteCloneRingtoneInfo(userId, cloneBundleInfo);
    }

    // if the application has ringtone before clone, clear the information.
    int64_t curTime = GetCurrentTime();
    int64_t cloneTime = NotificationPreferences::GetInstance()->GetCloneTimeStamp();
    if (cloneTime != 0 && cloneTime <= curTime &&
        (curTime - cloneTime < NotificationConstant::MAX_CLONE_TIME)) {
        sptr<NotificationRingtoneInfo> ringtoneInfoPtr = GetRingtoneInfoForClone(ringtoneInfo);
        sptr<NotificationRingtoneInfo> oldRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
        auto result = NotificationPreferences::GetInstance()->GetRingtoneInfoByBundle(bundle, oldRingtoneInfo);
        if (result == ERR_OK && (
            oldRingtoneInfo->GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL ||
            oldRingtoneInfo->GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE)) {
            SystemSoundHelper::GetInstance()->RemoveCustomizedTone(oldRingtoneInfo);
        }

        ANSR_LOGW("Clone : %{public}d %{public}s", result, oldRingtoneInfo->GetRingtoneUri().c_str());
        NotificationPreferences::GetInstance()->SetRingtoneInfoByBundle(bundle, ringtoneInfoPtr);
    }
}

void AdvancedNotificationService::UpdateCloneBundleInfo(const NotificationCloneBundleInfo cloneBundleInfo)
{
    ANS_LOGI("Event bundle update %{public}s.", cloneBundleInfo.Dump().c_str());
    if (notificationSvrQueue_ == nullptr) {
        return;
    }

    NotificationRingtoneInfo ringtoneInfo;
    if (cloneBundleInfo.GetRingtoneInfo() != nullptr) {
        ringtoneInfo = (*cloneBundleInfo.GetRingtoneInfo());
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&, ringtoneInfo, cloneBundleInfo]() {
        sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(
            cloneBundleInfo.GetBundleName(), cloneBundleInfo.GetUid());
        if (bundle == nullptr) {
            return;
        }
        bundle->SetAppIndex(cloneBundleInfo.GetAppIndex());
        UpdateCloneBundleInfoForEnable(cloneBundleInfo, bundle);
        UpdateCloneBundleInfoFoSlot(cloneBundleInfo, bundle);
        UpdateCloneBundleInfoForRingtone(ringtoneInfo, bundle, cloneBundleInfo);

        if (NotificationPreferences::GetInstance()->SetShowBadge(bundle, cloneBundleInfo.GetIsShowBadge()) == ERR_OK) {
            HandleBadgeEnabledChanged(bundle, cloneBundleInfo.GetIsShowBadge());
        } else {
            ANS_LOGW("Set notification badge failed.");
        }
        if (cloneBundleInfo.GetIshasPoppedSupportClone() && NotificationPreferences::GetInstance()->SetHasPoppedDialog(
            bundle, cloneBundleInfo.GetHasPoppedDialog()) != ERR_OK) {
            ANS_LOGW("Set hasPoped failed.");
        }
        NotificationConstant::SWITCH_STATE state = cloneBundleInfo.GetEnabledExtensionSubscription();
        if (state != NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF) {
            UpdateCloneBundleInfoForExtensionSubscription(cloneBundleInfo, bundle, state);
        }
        UpdateCloneBundleInfoFoSilentReminder(cloneBundleInfo, bundle);
        NotificationAnalyticsUtil::ReportCloneInfo(cloneBundleInfo);
        EnsureExtensionServiceLoadedAndSubscribed(bundle, cloneBundleInfo.GetExtensionSubscriptionBundles());
    }));
}

void AdvancedNotificationService::UpdateCloneBundleInfoForExtensionSubscription(
    const NotificationCloneBundleInfo &cloneBundleInfo,
    const sptr<NotificationBundleOption> &bundle,
    NotificationConstant::SWITCH_STATE state)
{
    sptr<NotificationBundleOption> processBundle = GenerateCloneValidBundleOption(bundle);
    if (processBundle == nullptr) {
        return;
    }

    if (NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(processBundle, state) != ERR_OK) {
        ANS_LOGW("Set subscription enabled failed.");
    }

    if (NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(
        processBundle, cloneBundleInfo.GetExtensionSubscriptionInfos()) != ERR_OK) {
        ANS_LOGW("Set subscription infos failed.");
    }

    std::vector<sptr<NotificationBundleOption>> grantBundles;
    for (const auto grantBundle : cloneBundleInfo.GetExtensionSubscriptionBundles()) {
        sptr<NotificationBundleOption> processGrantBundle = GenerateCloneValidBundleOption(grantBundle);
        if (processGrantBundle == nullptr) {
            continue;
        }
        grantBundles.emplace_back(processGrantBundle);
    }
    if (NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(
        processBundle, grantBundles) != ERR_OK) {
        ANS_LOGW("Set subscription bundles failed.");
    }
}

void AdvancedNotificationService::UpdateCloneBundleInfoForEnable(
    const NotificationCloneBundleInfo cloneBundleInfo, const sptr<NotificationBundleOption> bundle)
{
    NotificationConstant::SWITCH_STATE state = cloneBundleInfo.GetEnableNotification();
    ErrCode result = NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundle, state);
    if (result == ERR_OK) {
        SetSlotFlagsTrustlistsAsBundle(bundle);
        bool enabled = (state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
            state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
        sptr<EnabledNotificationCallbackData> bundleData = new (std::nothrow) EnabledNotificationCallbackData(
            bundle->GetBundleName(), bundle->GetUid(), enabled);
        if (bundleData == nullptr) {
            return;
        }
        NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
    } else {
        ANS_LOGW("Set notification enable failed.");
        return;
    }
}

void AdvancedNotificationService::UpdateCloneBundleInfoFoSlot(
    const NotificationCloneBundleInfo cloneBundleInfo, const sptr<NotificationBundleOption> bundle)
{
    if (cloneBundleInfo.GetSlotInfo().empty()) {
        PublishSlotChangeCommonEvent(bundle);
    }
    if (NotificationPreferences::GetInstance()->SetNotificationSlotFlagsForBundle(bundle,
        cloneBundleInfo.GetSlotFlags()) != ERR_OK) {
        ANS_LOGW("Set notification slot failed.");
        return;
    }
    if (UpdateSlotReminderModeBySlotFlags(bundle, cloneBundleInfo.GetSlotFlags()) != ERR_OK) {
        ANS_LOGW("Set notification reminder slot failed.");
        return;
    }

    for (auto& cloneSlot : cloneBundleInfo.GetSlotInfo()) {
        NotificationSlot slotInfo = NotificationSlot(cloneSlot.slotType_);
        slotInfo.SetEnable(cloneSlot.enable_);
        slotInfo.SetForceControl(cloneSlot.isForceControl_);
        slotInfo.SetAuthorizedStatus(cloneSlot.GetAuthStaus());
        if (SetEnabledForBundleSlotInner(bundle, bundle, cloneSlot.slotType_, slotInfo) != ERR_OK) {
            ANS_LOGW("Set notification slots failed %{public}s.", cloneSlot.Dump().c_str());
        }
    }
}

void AdvancedNotificationService::UpdateCloneBundleInfoFoSilentReminder(
    const NotificationCloneBundleInfo cloneBundleInfo, const sptr<NotificationBundleOption> bundle)
{
    auto enableStatus = cloneBundleInfo.GetSilentReminderEnabled();
    if (NotificationPreferences::GetInstance()->SetSilentReminderEnabled(bundle,
    (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
    enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) ?
    true : false) != ERR_OK) {
        ANS_LOGW("SetSilentReminderEnabled failed.");
    }
}

void AdvancedNotificationService::CheckRemovalWantAgent(const sptr<NotificationRequest> &request)
{
    if (request->GetRemovalWantAgent() != nullptr && request->GetRemovalWantAgent()->GetPendingWant() != nullptr) {
        uint32_t operationType = (uint32_t)(request->GetRemovalWantAgent()->GetPendingWant()
            ->GetType(request->GetRemovalWantAgent()->GetPendingWant()->GetTarget()));
        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        bool isSystemApp = AccessTokenHelper::IsSystemApp();
        if (!isSubsystem && !isSystemApp && operationType != OPERATION_TYPE_COMMON_EVENT) {
            ANS_LOGI("SetRemovalWantAgent null");
            request->SetRemovalWantAgent(nullptr);
        }
    }
}
}  // namespace Notification
}  // namespace OHOS
