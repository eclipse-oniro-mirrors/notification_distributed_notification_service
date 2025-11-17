/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "access_token_helper.h"

#include "ipc_skeleton.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {
constexpr int32_t RSS_UID = 1096;

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

ErrCode AdvancedNotificationService::GetActiveNotifications(const std::string &instanceKey,
    const sptr<IAnsResultDataSynchronizer> &synchronizer)
{
    ANS_LOGD("called");
    if (synchronizer == nullptr) {
        ANS_LOGE("synchronizer is null");
        return ERR_ANS_INVALID_PARAM;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    bundleOption->SetAppInstanceKey(instanceKey);

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("called");
        std::vector<sptr<NotificationRequest>> requests;
        for (auto record : notificationList_) {
            if ((record->bundleOption->GetBundleName() == bundleOption->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundleOption->GetUid()) &&
                (record->notification->GetInstanceKey() == bundleOption->GetAppInstanceKey())) {
                requests.push_back(record->request);
            }
        }
        synchronizer->TransferResultData(ERR_OK, requests);
    }));
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetActiveNotificationNums(uint64_t &num)
{
    ANS_LOGD("called");

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("called");
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

ErrCode AdvancedNotificationService::GetAllActiveNotifications(const sptr<IAnsResultDataSynchronizer> &synchronizer)
{
    ANS_LOGD("called");
    if (synchronizer == nullptr) {
        ANS_LOGE("synchronizer is null");
        return ERR_ANS_INVALID_PARAM;
    }
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != RSS_UID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("AccessTokenHelper::CheckPermission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([=]() {
        ANS_LOGD("called");
        std::vector<sptr<Notification>> notifications;
        for (auto record : notificationList_) {
            if (record->notification != nullptr && record->notification->request_ != nullptr) {
                notifications.push_back(record->notification);
            }
        }
        synchronizer->TransferResultData(ERR_OK, notifications);
    }));
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
    int32_t slotTypeInt)
{
    ANS_LOGD("called");

    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("AccessTokenHelper::CheckPermission failed.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("called");
        notifications.clear();
        for (auto record : notificationList_) {
            if (record->notification == nullptr || record->notification->request_ == nullptr) {
                continue;
            }
            if (record->notification->request_->GetSlotType() != slotType) {
                continue;
            }

            int32_t receiver = record->notification->request_->GetReceiverUserId();
            if (receiver == SUBSCRIBE_USER_INIT || (receiver != 0 && receiver != userId)) {
                ANS_LOGI("Userid %{public}d %{public}d %{public}s.", receiver, userId,
                    record->notification->GetKey().c_str());
                continue;
            }
            notifications.push_back(record->notification);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetSpecialActiveNotifications(
    const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications)
{
    ANS_LOGD("called");

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("called");
        for (auto record : notificationList_) {
            if (IsContained(key, record->notification->GetKey())) {
                notifications.push_back(record->notification);
            }
        }
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetActiveNotificationByFilter(
    const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, const std::string &label,
    int32_t userId, const std::vector<std::string> &extraInfoKeys, sptr<NotificationRequest> &request)
{
    ANS_LOGD("called");
    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr && userId != -1 && !bundleOption->GetBundleName().empty()) {
        bundle = new (std::nothrow) NotificationBundleOption(bundleOption->GetBundleName(), 0);
    }
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    // get other bundle notification need controller permission
    if (bundle->GetUid() != IPCSkeleton::GetCallingUid()) {
        ANS_LOGI_LIMIT("None-self call, uid: %{public}d, curUid: %{public}d.",
            bundle->GetUid(), IPCSkeleton::GetCallingUid());
        if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
            ANS_LOGE("Get live view by filter failed because check permission is false.");
            return ERR_ANS_PERMISSION_DENIED;
        }
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("called");

        auto record = GetRecordFromNotificationList(
            notificationId, bundle->GetUid(), label, bundle->GetBundleName(), userId);
        if ((record == nullptr) || (!record->request->IsCommonLiveView())) {
            return;
        }
        result = IsAllowedGetNotificationByFilter(record, bundle);
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

ErrCode AdvancedNotificationService::GetNotificationRequestByHashCode(
    const std::string& hashCode, sptr<NotificationRequest>& notificationRequest)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("null notificationSvrQueue");
        return ERR_ANS_INVALID_PARAM;
    }

    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        auto record = GetFromNotificationList(hashCode);
        if (record != nullptr) {
            notificationRequest = record->request;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
}
} // Notification
} // OHOS
