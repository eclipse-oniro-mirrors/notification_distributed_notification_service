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

#include "access_token_helper.h"
#include "advanced_notification_service.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "errors.h"
#include "ipc_skeleton.h"
#include "notification_preferences.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr const char* ANS_EXTENSION_SERVICE_MODULE_NAME = "libans_extension_service.z.so";
}

ErrCode AdvancedNotificationService::NotificationExtensionSubscribe(
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("AdvancedNotificationService::NotificationExtensionSubscribe");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (infos.empty()) {
        ANS_LOGE("subscribe list is empty.");
        return ERR_ANS_INVALID_PARAM;
    }
    
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to insert subscription info into db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    // ExtensionService condition check
    // ExtensionService load
    // call ExtensionService interface

    return result;
}

ErrCode AdvancedNotificationService::NotificationExtensionUnsubscribe()
{
    ANS_LOGD("AdvancedNotificationService::NotificationExtensionUnsubscribe");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->ClearExtensionSubscriptionInfos(bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to insert subscription info into db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    // ExtensionService condition check
    // ExtensionService unload

    return result;
}

ErrCode AdvancedNotificationService::GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    ANS_LOGD("AdvancedNotificationService::GetSubscribeInfo");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_BUNDLE;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundleOption, infos);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to insert subscription info into db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}
}  // namespace Notification
}  // namespace OHOS
