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

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "os_account_manager.h"
#include "notification_preferences.h"
#include "distributed_database.h"
#include "want_agent_helper.h"
#include "hitrace_meter.h"
#include "notification_timer_info.h"
#include "time_service_client.h"

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

#include "advanced_notification_inline.cpp"

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

static bool SortNotificationsByLevelAndTime(
    const std::shared_ptr<NotificationRecord> &first, const std::shared_ptr<NotificationRecord> &second)
{
    if (first->slot->GetLevel() != second->slot->GetLevel()) {
        return (first->slot->GetLevel() < second->slot->GetLevel());
    }
    return (first->request->GetCreateTime() < second->request->GetCreateTime());
}

std::shared_ptr<ffrt::queue> AdvancedNotificationService::GetNotificationSvrQueue()
{
    return notificationSvrQueue_;
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
        ANS_LOGE("Failed to create NotificationBundleOption instance");
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
            if (!GetActiveUserId(activeUserId)) {
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

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
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
    const std::shared_ptr<NotificationRecord> &record)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (isSubsystem || AccessTokenHelper::IsSystemApp()) {
        if (CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
            return ERR_OK;
        }

        ANS_LOGD("Get live view by filter failed because check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    std::string bundle = GetClientBundleName();
    if (bundle.empty()) {
        ANS_LOGD("Get live view by filter failed because bundle name is empty.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid == record->bundleOption->GetUid() && bundle == record->bundleOption->GetBundleName()) {
        return ERR_OK;
    }

    ANS_LOGD("Get live view by filter failed because no permission.");
    return ERR_ANS_PERMISSION_DENIED;
}

ErrCode AdvancedNotificationService::GetActiveNotificationByFilter(
    const sptr<NotificationBundleOption> &bundleOption, const int32_t notificationId, const std::string &label,
    const std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");

        auto record = GetRecordFromNotificationList(notificationId, bundle->GetUid(), label, bundle->GetBundleName());
        if ((record == nullptr) || (!record->request->IsCommonLiveView())) {
            return;
        }
        result = IsAllowedGetNotificationByFilter(record);
        if (result != ERR_OK) {
            return;
        }

        if (extraInfoKeys.empty()) {
            // return all liveViewExtraInfo because no extraInfoKeys
            request = record->request;
            return;
        }
        // obtain extraInfo by extraInfoKeys
        if (FillRequestByKeys(record->request, extraInfoKeys, request) != ERR_OK) {
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

void AdvancedNotificationService::SetAgentNotification(sptr<NotificationRequest>& notificationRequest,
    std::string& bundleName)
{
    auto bundleManager = BundleManagerHelper::GetInstance();
    int32_t activeUserId = -1;
    if (!GetActiveUserId(activeUserId)) {
        ANSR_LOGW("Failed to get active user id!");
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

int64_t AdvancedNotificationService::GetNowSysTime()
{
    std::chrono::time_point<std::chrono::system_clock> nowSys = std::chrono::system_clock::now();
    auto epoch = nowSys.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    int64_t duration = value.count();
    return duration;
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
        std::vector<sptr<Notification>> notifications;
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
                notifications.emplace_back(notification);
                if (notifications.size() >= MAX_CANCELED_PARCELABLE_VECTOR_NUM) {
                    std::vector<sptr<Notification>> currNotificationList = notifications;
                    NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                        currNotificationList, nullptr, reason);
                    notifications.clear();
                }
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
                DoDistributedDelete("", "", notification);
#endif
            }
        }
        if (!notifications.empty()) {
            NotificationSubscriberManager::GetInstance()->BatchNotifyCanceled(
                notifications, nullptr, NotificationConstant::PACKAGE_CHANGED_REASON_DELETE);
        }
        NotificationPreferences::GetInstance().RemoveAnsBundleDbInfo(bundleOption);
        RemoveDoNotDisturbProfileTrustList(bundleOption);
    }));
    NotificationPreferences::GetInstance().RemoveEnabledDbByBundle(bundleOption);
}

void AdvancedNotificationService::RemoveDoNotDisturbProfileTrustList(
    const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    int32_t userId = 0;
    if (!GetActiveUserId(userId)) {
        ANS_LOGE("Failed to get active user id.");
        return;
    }
    NotificationPreferences::GetInstance().RemoveDoNotDisturbProfileTrustList(userId, bundleOption);
}

void AdvancedNotificationService::OnBundleDataAdd(const sptr<NotificationBundleOption> &bundleOption)
{
    CHECK_BUNDLE_OPTION_IS_INVALID(bundleOption)
    auto bundleInstall = [bundleOption]() {
        CHECK_BUNDLE_OPTION_IS_INVALID(bundleOption)
        AppExecFwk::BundleInfo bundleInfo;
        if (!GetBundleInfoByNotificationBundleOption(bundleOption, bundleInfo)) {
            ANS_LOGE("Failed to get BundleInfo using NotificationBundleOption.");
            return;
        }

        // In order to adapt to the publish reminder interface, currently only the input from the whitelist is written
        if (bundleInfo.applicationInfo.allowEnableNotification) {
            auto errCode = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundleOption, true);
            if (errCode != ERR_OK) {
                ANS_LOGE("Set notification enable error! code: %{public}d", errCode);
            }

            errCode = NotificationPreferences::GetInstance().SetShowBadge(bundleOption, true);
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
    auto bundleUpdate = [bundleOption]() {
        CHECK_BUNDLE_OPTION_IS_INVALID(bundleOption)
        AppExecFwk::BundleInfo bundleInfo;
        if (!GetBundleInfoByNotificationBundleOption(bundleOption, bundleInfo)) {
            ANS_LOGE("Failed to get BundleInfo using NotificationBundleOption.");
            return;
        }

        if (!bundleInfo.applicationInfo.allowEnableNotification) {
            ANS_LOGE("Current application allowEnableNotification is false, do not record.");
            return;
        }

        bool hasPopped = false;
        auto errCode = NotificationPreferences::GetInstance().GetHasPoppedDialog(bundleOption, hasPopped);
        if (errCode != ERR_OK) {
            ANS_LOGD("Get notification user option fail, need to insert data");
            errCode = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(
                bundleOption, bundleInfo.applicationInfo.allowEnableNotification);
            if (errCode != ERR_OK) {
                ANS_LOGE("Set notification enable error! code: %{public}d", errCode);
            }

            errCode = NotificationPreferences::GetInstance().SetShowBadge(bundleOption, true);
            if (errCode != ERR_OK) {
                ANS_LOGE("Set badge enable error! code: %{public}d", errCode);
            }
            return;
        }

        if (hasPopped) {
            ANS_LOGI("The user has made changes, subject to the user's selection");
            return;
        }

        errCode = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(
            bundleOption, bundleInfo.applicationInfo.allowEnableNotification);
        if (errCode != ERR_OK) {
            ANS_LOGE("Set notification enable error! code: %{public}d", errCode);
        }
        errCode = NotificationPreferences::GetInstance().SetShowBadge(bundleOption, true);
        if (errCode != ERR_OK) {
            ANS_LOGE("Set badge enable error! code: %{public}d", errCode);
        }
    };

    notificationSvrQueue_ != nullptr ? notificationSvrQueue_->submit(bundleUpdate) : bundleUpdate();
}

void AdvancedNotificationService::OnBootSystemCompleted()
{
    ANS_LOGI("Called.");
    InitNotificationEnableList();
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

ErrCode AdvancedNotificationService::GetTargetRecordList(const std::string& bundleName,
    NotificationConstant::SlotType slotType, NotificationContent::Type contentType,
    std::vector<std::shared_ptr<NotificationRecord>>& recordList)
{
    for (auto& notification : notificationList_) {
        if (notification->request != nullptr && notification->request->GetOwnerBundleName() == bundleName &&
                notification->request->GetSlotType()== slotType &&
                notification->request->GetNotificationType() == contentType) {
                recordList.emplace_back(notification);
        }
    }
    if (recordList.empty()) {
        return ERR_ANS_NOTIFICATION_NOT_EXISTS;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetCommonTargetRecordList(const std::string& bundleName,
    NotificationConstant::SlotType slotType, NotificationContent::Type contentType,
    std::vector<std::shared_ptr<NotificationRecord>>& recordList)
{
    for (auto& notification : notificationList_) {
        if (notification->request->IsCommonLiveView()) {
            auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
                notification->request->GetContent()->GetNotificationContent());
            if (notification->request != nullptr && notification->request->GetOwnerBundleName() == bundleName &&
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

ErrCode AdvancedNotificationService::SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
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

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
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

ErrCode AdvancedNotificationService::AddDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("Called.");
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
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        ANS_LOGW("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    ffrt::task_handle handler =
        notificationSvrQueue_->submit_h(std::bind([copyUserId = userId, copyProfiles = profiles]() {
            ANS_LOGD("The ffrt enter.");
            NotificationPreferences::GetInstance().AddDoNotDisturbProfiles(copyUserId, copyProfiles);
        }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveDoNotDisturbProfiles(
    const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles)
{
    ANS_LOGD("Called.");
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
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (!GetActiveUserId(userId)) {
        ANS_LOGW("No active user found.");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
    ffrt::task_handle handler =
        notificationSvrQueue_->submit_h(std::bind([copyUserId = userId, copyProfiles = profiles]() {
            ANS_LOGD("The ffrt enter.");
            NotificationPreferences::GetInstance().RemoveDoNotDisturbProfiles(copyUserId, copyProfiles);
        }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::DoesSupportDoNotDisturbMode(bool &doesSupport)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
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
    if (supportCheckSaPermission_.compare("true") != 0) {
        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (isSubsystem) {
            return true;
        }
    }
    auto tokenCaller = IPCSkeleton::GetCallingTokenID();
    bool result = AccessTokenHelper::VerifyCallerPermission(tokenCaller, permission);
    if (!result) {
        ANS_LOGE("Permission denied");
    }
    return result;
}

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
void AdvancedNotificationService::OnDistributedPublish(
    const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    int32_t activeUserId = -1;
    if (!GetActiveUserId(activeUserId)) {
        ANS_LOGE("Failed to get active user id!");
        return;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return;
    }
    notificationSvrQueue_->submit(std::bind([this, deviceId, bundleName, request, activeUserId]() {
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

        result = PublishFlowControl(record);
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

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    notificationSvrQueue_->submit(std::bind([this, deviceId, bundleName, request, activeUserId]() {
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
            strcmp(deviceId.c_str(), localDeviceInfo.deviceId) == 0) {
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
        if ((bundleOption != nullptr) && (record->bundleOption->GetBundleName() != bundleOption->GetBundleName()) &&
            (record->bundleOption->GetUid() != bundleOption->GetUid()) && record->deviceId.empty()) {
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
        result = NotificationPreferences::GetInstance().GetTemplateSupported(templateName, support);
    }));
    notificationSvrQueue_->wait(handler);
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

void AdvancedNotificationService::OnResourceRemove(int32_t userId)
{
    DeleteAllByUser(userId);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        NotificationPreferences::GetInstance().RemoveSettings(userId);
    }));
    notificationSvrQueue_->wait(handler);
}

void AdvancedNotificationService::OnBundleDataCleared(const sptr<NotificationBundleOption> &bundleOption)
{
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::string> keys = GetNotificationKeys(bundleOption);
        std::vector<sptr<Notification>> notifications;
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
    }));
    notificationSvrQueue_->wait(handler);
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

void AdvancedNotificationService::OnUserRemoved(const int32_t &userId)
{
    DeleteAllByUserInner(userId, NotificationConstant::USER_REMOVED_REASON_DELETE);
}

ErrCode AdvancedNotificationService::DeleteAllByUser(const int32_t &userId)
{
    return DeleteAllByUserInner(userId, NotificationConstant::CANCEL_ALL_REASON_DELETE);
}

ErrCode AdvancedNotificationService::DeleteAllByUserInner(const int32_t &userId, int32_t deleteReason)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (userId <= SUBSCRIBE_USER_INIT) {
        ANS_LOGE("Input userId is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        std::vector<std::string> keys = GetNotificationKeys(nullptr);
        std::vector<sptr<Notification>> notifications;
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
                UpdateRecentNotification(notification, true, deleteReason);
                notifications.emplace_back(notification);
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

        result = ERR_OK;
    }));
    notificationSvrQueue_->wait(handler);

    return result;
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
    const sptr<NotificationDoNotDisturbDate> newConfig = new (std::nothrow) NotificationDoNotDisturbDate(
        date->GetDoNotDisturbType(),
        beginDate,
        endDate
    );
    if (newConfig == nullptr) {
        ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
        return ERR_NO_MEMORY;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Generate invalid bundle option!");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance().SetDoNotDisturbDate(userId, newConfig);
        if (result == ERR_OK) {
            NotificationSubscriberManager::GetInstance()->NotifyDoNotDisturbDateChanged(newConfig);
        }
    }));
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetDoNotDisturbDateByUser(const int32_t &userId,
    sptr<NotificationDoNotDisturbDate> &date)
{
    ErrCode result = ERR_OK;
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<NotificationDoNotDisturbDate> currentConfig = nullptr;
        result = NotificationPreferences::GetInstance().GetDoNotDisturbDate(userId, currentConfig);
        if (result == ERR_OK) {
            int64_t now = GetCurrentTime();
            switch (currentConfig->GetDoNotDisturbType()) {
                case NotificationConstant::DoNotDisturbType::CLEARLY:
                case NotificationConstant::DoNotDisturbType::ONCE:
                    if (now >= currentConfig->GetEndDate()) {
                        date = new (std::nothrow) NotificationDoNotDisturbDate(
                            NotificationConstant::DoNotDisturbType::NONE, 0, 0);
                        if (date == nullptr) {
                            ANS_LOGE("Failed to create NotificationDoNotDisturbDate instance");
                            return;
                        }
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
    notificationSvrQueue_->wait(handler);

    return ERR_OK;
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

    std::shared_ptr<NotificationBundleOption> agentBundle =
        std::make_shared<NotificationBundleOption>(bundle, uid);
    if (agentBundle == nullptr) {
        ANS_LOGE("Failed to create agentBundle instance");
        return ERR_ANS_INVALID_BUNDLE;
    }
    request->SetAgentBundle(agentBundle);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::PrePublishNotificationBySa(const sptr<NotificationRequest> &request,
    int32_t uid, std::string &bundle)
{
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        ANS_LOGE("failed to get bundleManager!");
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundle = bundleManager->GetBundleNameByUid(uid);
    ErrCode result = SetRequestBundleInfo(request, uid, bundle);
    if (result != ERR_OK) {
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

    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }
    result = CheckPictureSize(request);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to check picture size");
        return result;
    }
    ANS_LOGD("creator uid=%{public}d, userId=%{public}d, bundleName=%{public}s ", uid,
        userId, bundle.c_str());
    return ERR_OK;
}

uint64_t AdvancedNotificationService::StartAutoDelete(const std::string &key, int64_t deleteTimePoint, int32_t reason)
{
    ANS_LOGD("Enter");

    auto triggerFunc = [this, key, reason] { TriggerAutoDelete(key, reason); };
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
    ANS_LOGD("Enter");
    if (timerId == NotificationConstant::INVALID_TIMER_ID) {
        return;
    }
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(timerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(timerId);
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

void AdvancedNotificationService::InitNotificationEnableList()
{
    auto task = [&]() {
        std::vector<AppExecFwk::BundleInfo> bundleInfos = GetBundlesOfActiveUser();
        bool notificationEnable = false;
        for (const auto &bundleInfo : bundleInfos) {
            // Currently only the input from the whitelist is written
            if (!bundleInfo.applicationInfo.allowEnableNotification) {
                continue;
            }
            sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
                bundleInfo.applicationInfo.bundleName, bundleInfo.uid);
            if (bundleOption == nullptr) {
                ANS_LOGE("New bundle option obj error! bundlename:%{public}s",
                    bundleInfo.applicationInfo.bundleName.c_str());
                continue;
            }
            ErrCode saveRef = NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(
                bundleOption, notificationEnable);
            // record already exists
            if (saveRef == ERR_OK) {
                continue;
            }
            saveRef = NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundleOption, true);
            if (saveRef != ERR_OK) {
                ANS_LOGE("Set enable error! code: %{public}d", saveRef);
            }
            saveRef = NotificationPreferences::GetInstance().SetShowBadge(bundleOption, true);
            if (saveRef != ERR_OK) {
                ANS_LOGE("Set badge enable error! code: %{public}d", saveRef);
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
    if (bundleOption == nullptr || bundleOption->GetBundleName().empty()) {
        ANS_LOGE("Bundle option is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    int32_t activeUserId = 0;
    if (!GetActiveUserId(activeUserId)) {
        ANS_LOGE("Failed to get active user id.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager == nullptr) {
        ANS_LOGE("Failed to get bundle manager.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    int32_t uid = bundleManager->GetDefaultUidByBundleName(bundleOption->GetBundleName(), activeUserId);
    if (uid == -1) {
        ANS_LOGE("The specified bundle name was not found.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (bundleOption->GetUid() > 0) {
        return ERR_OK;
    }

    bundleOption->SetUid(uid);
    return ERR_OK;
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
    AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);
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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
void AdvancedNotificationService::OnScreenLock()
{
    ReminderSwingDecisionCenter::GetInstance().OnScreenLock();
}

void AdvancedNotificationService::OnScreenUnlock()
{
    ReminderSwingDecisionCenter::GetInstance().OnScreenUnlock();
}
#endif
void AdvancedNotificationService::CloseAlert(const std::shared_ptr<NotificationRecord> &record)
{
    record->notification->SetEnableLight(false);
    record->notification->SetEnableSound(false);
    record->notification->SetEnableVibration(false);
    auto flag = record->request->GetFlags();
    flag->SetSoundEnabled(NotificationConstant::FlagStatus::CLOSE);
    flag->SetLightScreenEnabled(false);
    flag->SetVibrationEnabled(NotificationConstant::FlagStatus::CLOSE);
    record->request->SetFlags(flag);
}
}  // namespace Notification
}  // namespace OHOS
