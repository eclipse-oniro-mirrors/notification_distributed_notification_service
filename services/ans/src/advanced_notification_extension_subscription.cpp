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
#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "bundle_manager_helper.h"
#include "errors.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {

ErrCode AdvancedNotificationService::GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("AdvancedNotificationService::GetAllSubscriptionBundles");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetCurrentCallingUserId(userId);
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!BundleManagerHelper::GetInstance()->QueryExtensionInfos(extensionInfos, userId)) {
            ANS_LOGE("Failed to QueryExtensionInfos!");
            result = ERROR_INTERNAL_ERROR;
            return;
        }
        for (const auto& extensionInfo : extensionInfos) {
            sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
                extensionInfo.bundleName, extensionInfo.uid);
            if (bundleOption == nullptr) {
                ANS_LOGE("Failed to create NotificationBundleOption for %{public}s",
                    extensionInfo.bundleName.c_str());
                continue;
            }
            
            bundles.emplace_back(bundleOption);
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::CanOpenSubscribeSettings()
{
    ANS_LOGD("AdvancedNotificationService::CanOpenSubscribeSettings");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}

}  // namespace Notification
}  // namespace OHOS
