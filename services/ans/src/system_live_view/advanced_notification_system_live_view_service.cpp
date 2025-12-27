/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ans_permission_def.h"
#include "access_token_helper.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_inner_errors.h"
#include "errors.h"
#include "ipc_skeleton.h"

#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_local_live_view_subscriber_manager.h"
#include "live_publish_process.h"

namespace OHOS {
namespace Notification {
ErrCode AdvancedNotificationService::TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
    const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is bogus.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    ErrCode result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        sptr<Notification> notification = nullptr;
        result = GetNotificationById(bundle, notificationId, notification);
        if (notification != nullptr) {
            NotificationLocalLiveViewSubscriberManager::GetInstance()->NotifyTriggerResponse(notification,
                buttonOption);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetNotificationById(const sptr<NotificationBundleOption> &bundle,
    const int32_t notificationId, sptr<Notification> &notification)
{
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    for (auto record : notificationList_) {
        if (record->request->GetAgentBundle() != nullptr) {
            if ((record->request->GetAgentBundle()->GetBundleName() == bundle->GetBundleName()) &&
                (record->request->GetAgentBundle()->GetUid() == bundle->GetUid()) &&
                (record->notification->GetId() == notificationId)) {
                notification = record->notification;
                return ERR_OK;
            }
        } else {
            if ((record->bundleOption->GetBundleName() == bundle->GetBundleName()) &&
                (record->bundleOption->GetUid() == bundle->GetUid()) &&
                (record->notification->GetId() == notificationId)) {
                notification = record->notification;
                return ERR_OK;
            }
        }
    }
    return ERR_ANS_NOTIFICATION_NOT_EXISTS;
}

ErrCode AdvancedNotificationService::SubscribeLocalLiveView(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber, const bool isNative)
{
    return SubscribeLocalLiveView(subscriber, nullptr, isNative);
}

ErrCode AdvancedNotificationService::SubscribeLocalLiveView(
    const sptr<IAnsSubscriberLocalLiveView> &subscriber,
    const sptr<NotificationSubscribeInfo> &info, const bool isNative)
{
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s, isNative: %{public}d", __FUNCTION__, isNative);

    ErrCode errCode = ERR_OK;
    do {
        if (!isNative) {
            bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
            if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
                ANS_LOGE("Client is not a system app or subsystem.");
                errCode = ERR_ANS_NON_SYSTEM_APP;
                break;
            }
        }

        if (subscriber == nullptr) {
            errCode = ERR_ANS_INVALID_PARAM;
            break;
        }

        errCode = NotificationLocalLiveViewSubscriberManager::GetInstance()->AddLocalLiveViewSubscriber(
            subscriber, info);
        if (errCode != ERR_OK) {
            break;
        }
    } while (0);
    if (errCode == ERR_OK) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        int32_t callingPid = IPCSkeleton::GetCallingPid();
        ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
            LivePublishProcess::GetInstance()->AddLiveViewSubscriber(callingUid, callingPid);
        }));
        notificationSvrQueue_->wait(handler);
    }
    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info, errCode);
    return errCode;
}

ErrCode AdvancedNotificationService::RemoveSystemLiveViewNotifications(
    const std::string& bundleName, const int32_t uid, const int32_t pid)
{
    std::vector<std::shared_ptr<NotificationRecord>> recordList;
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue is nullptr");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        LivePublishProcess::GetInstance()->EraseLiveViewSubscriber(uid, pid);
        GetTargetRecordList(uid, pid, NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LOCAL_LIVE_VIEW, recordList);
        GetCommonTargetRecordList(uid,  NotificationConstant::SlotType::LIVE_VIEW,
            NotificationContent::Type::LIVE_VIEW, recordList);
        if (recordList.size() == 0) {
            ANS_LOGE("Empty list");
            result = ERR_ANS_NOTIFICATION_NOT_EXISTS;
            return;
        }
        result = RemoveNotificationFromRecordList(recordList);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::RemoveSystemLiveViewNotificationsOfSa(int32_t uid)
{
    {
        std::lock_guard<ffrt::mutex> lock(delayNotificationMutext_);
        for (auto iter = delayNotificationList_.begin(); iter != delayNotificationList_.end();) {
            if ((*iter).first->notification->GetNotificationRequest().GetCreatorUid() == uid &&
                (*iter).first->notification->GetNotificationRequest().IsInProgress()) {
                CancelTimer((*iter).second);
                iter = delayNotificationList_.erase(iter);
            } else {
                iter++;
            }
        }
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        LivePublishProcess::GetInstance()->EraseLiveViewSubscriber(uid);
        std::vector<std::shared_ptr<NotificationRecord>> recordList;
        for (auto item : notificationList_) {
            if (item->notification->GetNotificationRequest().GetCreatorUid() == uid &&
                item->notification->GetNotificationRequest().IsInProgress() &&
                !item->notification->GetNotificationRequest().IsCommonLiveView()) {
                recordList.emplace_back(item);
            }
        }
        if (!recordList.empty()) {
            result = RemoveNotificationFromRecordList(recordList);
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}
}  // namespace Notification
}  // namespace OHOS