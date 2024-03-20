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
#include "ipc_skeleton.h"
#include "notification_content.h"
#include "notification_live_view_content.h"

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

ErrCode LivePublishProcess::PublishPreWork(const sptr<NotificationRequest> &request)
{
    if (!CheckLocalLiveViewAllowed(request)) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckLocalLiveViewSubscribed(request)) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!request->IsRemoveAllowed()) {
        if (!CheckPermission(OHOS_PERMISSION_SET_UNREMOVABLE_NOTIFICATION)) {
            request->SetRemoveAllowed(true);
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

bool LivePublishProcess::CheckLocalLiveViewSubscribed(const sptr<NotificationRequest> &request)
{
    if (request->GetNotificationType() == NotificationContent::Type::LOCAL_LIVE_VIEW &&
        !GetLiveViewSubscribeState(GetClientBundleName())) {
        ANS_LOGE("Not subscribe local live view.");
        return false;
    }
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(
        request->GetContent()->GetNotificationContent());
    if (request->GetSlotType() == NotificationConstant::SlotType::LIVE_VIEW &&
        request->GetNotificationType() == NotificationContent::Type::LIVE_VIEW &&
        liveViewContent->GetIsOnlylocalUpdate() &&
        !GetLiveViewSubscribeState(GetClientBundleName())) {
        ANS_LOGE("Not subscribe common live view.");
        return false;
    }
    return true;
}

bool LivePublishProcess::CheckLocalLiveViewAllowed(const sptr<NotificationRequest> &request)
{
    if (request->GetNotificationType() == NotificationContent::Type::LOCAL_LIVE_VIEW) {
        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
            ANS_LOGE("Client is not a system app or subsystem");
            return false;
        } else {
            return true;
        }
    }
    return true;
}

void LivePublishProcess::AddLiveViewSubscriber()
{
    std::string bundleName = GetClientBundleName();
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    localLiveViewSubscribedList_.emplace(bundleName);
}

void LivePublishProcess::EraseLiveViewSubsciber(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    localLiveViewSubscribedList_.erase(bundleName);
}

bool LivePublishProcess::GetLiveViewSubscribeState(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(liveViewMutext_);
    if (localLiveViewSubscribedList_.find(bundleName) == localLiveViewSubscribedList_.end()) {
        return false;
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS
