/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NOTIFICATION_ADVANCED_NOTIFICATION_INLINE_H
#define NOTIFICATION_ADVANCED_NOTIFICATION_INLINE_H

#include "ans_log_wrapper.h"
#include "access_token_helper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "ipc_skeleton.h"
#include "os_account_manager_helper.h"
#include "notification_preferences.h"
#include "notification_analytics_util.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
inline std::string GetClientBundleNameByUid(int32_t callingUid)
{
    std::string bundle;

    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        bundle = bundleManager->GetBundleNameByUid(callingUid);
    }

    return bundle;
}

inline std::string __attribute__((weak)) GetClientBundleName()
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return GetClientBundleNameByUid(callingUid);
}

inline int32_t CheckUserIdParams(const int userId)
{
    if (userId != SUBSCRIBE_USER_INIT && !OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        return ERROR_USER_NOT_EXIST;
    }
    return ERR_OK;
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

inline ErrCode CheckPictureSize(const sptr<NotificationRequest> &request)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_1, EventBranchId::BRANCH_1);
    auto result = request->CheckImageSizeForContent();
    if (result != ERR_OK) {
        ANS_LOGE("Check image size failed.");
        message.ErrorCode(result).Message("Check image size failed.");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return result;
    }

    if (request->CheckImageOverSizeForPixelMap(request->GetLittleIcon(), MAX_ICON_SIZE)) {
        message.ErrorCode(ERR_ANS_ICON_OVER_SIZE).Message("Check little image size failed.");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_ICON_OVER_SIZE;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp() && request->GetOverlayIcon()
        && request->GetSlotType() != NotificationConstant::SlotType::SOCIAL_COMMUNICATION) {
        request->SetOverlayIcon(nullptr);
        ANS_LOGI("fix overlayicon");
    }

    if (request->CheckImageOverSizeForPixelMap(request->GetOverlayIcon(), MAX_ICON_SIZE)) {
        message.ErrorCode(ERR_ANS_ICON_OVER_SIZE).Message("Check overlay size failed.");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message);
        return ERR_ANS_ICON_OVER_SIZE;
    }

    if (request->CheckImageOverSizeForPixelMap(request->GetBigIcon(), MAX_ICON_SIZE)) {
        request->ResetBigIcon();
        ANS_LOGI("Check big image size over limit");
    }

    return ERR_OK;
}

inline OHOS::Notification::HaMetaMessage AddInformationInMessage(
    OHOS::Notification::HaMetaMessage haMetaMessage, const int32_t reason,
    std::string message)
{
    message += "reason:" + std::to_string(reason) + ".";

    std::string bundleName;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    message += "uid:" + std::to_string(callingUid) + ".";
    bundleName = GetClientBundleNameByUid(callingUid);

    haMetaMessage = haMetaMessage.AgentBundleName(bundleName);
    haMetaMessage = haMetaMessage.Message(message);
    return haMetaMessage;
}


inline void ReportDeleteFailedEventPush(OHOS::Notification::HaMetaMessage haMetaMessage,
    const int32_t reason, std::string message)
{
    haMetaMessage = AddInformationInMessage(haMetaMessage, reason, message);
    NotificationAnalyticsUtil::ReportDeleteFailedEvent(haMetaMessage);
}

inline void ReportDeleteFailedEventPushByNotification(const sptr<Notification> &notification,
    OHOS::Notification::HaMetaMessage haMetaMessage, const int32_t reason,
    std::string message)
{
    if (notification == nullptr) {
        ANS_LOGW("report notificaiton is null");
        return;
    }
    haMetaMessage = AddInformationInMessage(haMetaMessage, reason, message);
    NotificationAnalyticsUtil::ReportDeleteFailedEvent(
        notification->GetNotificationRequestPoint(), haMetaMessage);
}

inline ErrCode PermissionVerification()
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER) ||
        !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_AGENT_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
#endif // NOTIFICATION_ADVANCED_NOTIFICATION_INLINE_H