/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "live_publish_process.h"

#include "access_token_helper.h"
#include "advanced_notification_service.h"
#include "ans_log_wrapper.h"
#include "ans_const_define.h"
#include "ipc_skeleton.h"
#include "notification_content.h"
#include "notification_live_view_content.h"
#include "os_account_manager_helper.h"

#include "../advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {
std::shared_ptr<LivePublishProcess> LivePublishProcess::instance_;
std::mutex LivePublishProcess::instanceMutex_;

std::shared_ptr<LivePublishProcess> LivePublishProcess::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);

    if (instance_ == nullptr) {
        instance_ = std::make_shared<LivePublishProcess>();
        if (instance_ == nullptr) {
            ANS_LOGE("Failed to create LivePublishProcess instance");
            return nullptr;
        }
    }
    return instance_;
}

ErrCode LivePublishProcess::PublishPreWork(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1);
    if (!CheckLocalLiveViewAllowed(request, isUpdateByOwnerAllowed)) {
        message.BranchId(EventBranchId::BRANCH_3).ErrorCode(ERR_ANS_NON_SYSTEM_APP)
            .Message("CheckLocalLiveViewAllowed is false", true);
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!request->IsRemoveAllowed()) {
        if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION)) {
            request->SetRemoveAllowed(true);
        }
    }

    bool isHap = !AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID()) &&
        !AccessTokenHelper::IsSystemApp();
    if (isUpdateByOwnerAllowed && isHap) {
        if (request->GetTemplate() == nullptr) {
            message.BranchId(EventBranchId::BRANCH_4).ErrorCode(ERR_ANS_INVALID_PARAM)
                .Message("Owner must has template to update", true);
            NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
            return ERR_ANS_INVALID_PARAM;
        }
    }
    return ERR_OK;
}

ErrCode LivePublishProcess::PublishNotificationByApp(const sptr<NotificationRequest> &request)
{
    ErrCode result = CommonPublishCheck(request);
    if (result != ERR_OK) {
        return result;
    }

    if (request->IsInProgress() &&
        !AccessTokenHelper::IsSystemApp() &&
        !request->IsCommonLiveView()) {
        request->SetInProgress(false);
    }

    result = CommonPublishProcess(request);
    if (result != ERR_OK) {
        return result;
    }
    return ERR_OK;
}

bool LivePublishProcess::CheckLocalLiveViewSubscribed(
    const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed, int32_t uid)
{
    if (request->GetNotificationType() == NotificationContent::Type::LOCAL_LIVE_VIEW) {
        return GetLiveViewSubscribeState(uid) || isUpdateByOwnerAllowed;
    }
    if (request->IsCommonLiveView()) {
        std::shared_ptr<NotificationLiveViewContent> liveViewContent = nullptr;
        liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
            request->GetContent()->GetNotificationContent());
        if (liveViewContent != nullptr && liveViewContent->GetIsOnlyLocalUpdate() &&
            !GetLiveViewSubscribeState(uid)) {
            ANS_LOGE("Not subscribe common live view.");
            return false;
        }
    }
    return true;
}

bool LivePublishProcess::CheckLocalLiveViewAllowed(
    const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed)
{
    if (request->GetNotificationType() == NotificationContent::Type::LOCAL_LIVE_VIEW) {
        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
            ANS_LOGE("Client is not a system app or subsystem");
            return isUpdateByOwnerAllowed;
        } else {
            return true;
        }
    }
    return true;
}

void LivePublishProcess::AddLiveViewSubscriber(int32_t uid)
{
    localLiveViewSubscribedList_.emplace(uid);
}

void LivePublishProcess::EraseLiveViewSubsciber(int32_t uid)
{
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    localLiveViewSubscribedList_.erase(uid);
}

bool LivePublishProcess::GetLiveViewSubscribeState(int32_t uid)
{
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    if (localLiveViewSubscribedList_.find(uid) == localLiveViewSubscribedList_.end()) {
        return false;
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS
