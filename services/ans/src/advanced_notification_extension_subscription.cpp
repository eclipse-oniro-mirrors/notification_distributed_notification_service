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

bool AdvancedNotificationService::HasGrantedBundleStateChanged(
    const sptr<NotificationBundleOption>& bundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, bundles);
    if (result != ERR_OK) {
        return true;
    }
    
    if (bundles.size() == 0) {
        return true;
    }
    
    if (bundles.size() != enabledBundles.size()) {
        return true;
    }
    
    for (size_t i = 0; i < bundles.size(); ++i) {
        if (bundles[i] == nullptr || enabledBundles[i] == nullptr) {
            return true;
        }
        if (bundles[i]->GetBundleName() != enabledBundles[i]->GetBundleName() ||
            bundles[i]->GetUid() != enabledBundles[i]->GetUid()) {
            return true;
        }
    }
    return false;
}

bool AdvancedNotificationService::HasExtensionSubscriptionStateChanged(
    const sptr<NotificationBundleOption> &bundle, bool enabled)
{
    if (bundle == nullptr) {
        return true;
    }
    
    NotificationConstant::SWITCH_STATE state;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state);
    if (result != ERR_OK) {
        return true;
    }
    
    bool oldEnabled = (state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    
    if (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF) {
        return true;
    }
    
    return (oldEnabled != enabled);
}

bool AdvancedNotificationService::HasExtensionSubscriptionInfosChanged(const sptr<NotificationBundleOption> &bundle,
    const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos)
{
    if (bundle == nullptr) {
        return true;
    }

    std::vector<sptr<NotificationExtensionSubscriptionInfo>> oldInfos;
    ErrCode result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionInfos(bundle, oldInfos);
    if (result != ERR_OK) {
        return true;
    }

    if (oldInfos.size() == 0) {
        return true;
    }

    if (oldInfos.size() != infos.size()) {
        return true;
    }

    for (size_t i = 0; i < oldInfos.size(); ++i) {
        if (oldInfos[i] == nullptr || infos[i] == nullptr) {
            return true;
        }
        if (oldInfos[i]->GetAddr() != infos[i]->GetAddr() ||
            oldInfos[i]->GetType() != infos[i]->GetType() ||
            oldInfos[i]->IsHfp() != infos[i]->IsHfp()) {
            return true;
        }
    }
    return false;
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
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    int32_t userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
    if (!BundleManagerHelper::GetInstance()->
        CheckBundleImplExtensionAbility(bundleOption->GetBundleName(), userId)) {
        ANS_LOGE("App Not Implement NotificationSubscriberExtensionAbility.");
        return ERR_ANS_NOT_IMPL_EXTENSIONABILITY;
    }
    
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!HasExtensionSubscriptionInfosChanged(bundleOption, infos)) {
            ANS_LOGW("No change in extension subscription infos, skip db insert.");
            return;
        }
        result = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to insert subscription info into db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
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
        return ERR_ANS_INVALID_PARAM;
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
            ANS_LOGE("Failed to clean subscription info into db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

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
        return ERR_ANS_INVALID_PARAM;
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
            ANS_LOGE("Failed to get subscription info from db, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::IsUserGranted(bool& isEnabled)
{
    ANS_LOGD("AdvancedNotificationService::IsUserGranted");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundleOption, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get extensionsubscriptionenabled info from db, ret: %{public}d", result);
            return;
        }
        isEnabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedState(
    const sptr<NotificationBundleOption>& targetBundle, bool& enabled)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    NotificationConstant::SWITCH_STATE state;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionEnabled(bundle, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get user granted state for bundle: %{public}s, ret: %{public}d",
                targetBundle->GetBundleName().c_str(), result);
            return;
        }
        enabled = ((state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) ? true : false);
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetUserGrantedState(
    const sptr<NotificationBundleOption>& targetBundle, bool enabled)
{
    ANS_LOGD("AdvancedNotificationService::SetUserGrantedState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (!HasExtensionSubscriptionStateChanged(bundle, enabled)) {
            ANS_LOGW("User State No change for bundle: %{public}s", bundle->GetBundleName().c_str());
            return;
        }
        AdvancedNotificationService::GetInstance()->
            PublishExtensionServiceStateChange(NotificationConstant::USER_GRANTED_STATE, bundle, enabled, {});
        NotificationConstant::SWITCH_STATE state = enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
            : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
        result = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundle, state);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set user granted state for bundle: %{public}s, ret: %{public}d",
                bundle->GetBundleName().c_str(), result);
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedEnabledBundles(
    const sptr<NotificationBundleOption>& targetBundle, std::vector<sptr<NotificationBundleOption>>& enabledBundles)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedEnabledBundles");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter GetUserGrantedEnabledBundles!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundle, enabledBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get enabled bundles from database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::GetUserGrantedEnabledBundlesForSelf(
    std::vector<sptr<NotificationBundleOption>>& bundles)
{
    ANS_LOGD("AdvancedNotificationService::GetUserGrantedEnabledBundlesForSelf");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_SUBSCRIBE_NOTIFICATION)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("Failed to create NotificationBundleOption");
        return ERR_ANS_INVALID_PARAM;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter GetUserGrantedEnabledBundlesForSelf!");
        result = NotificationPreferences::GetInstance()->GetExtensionSubscriptionBundles(bundleOption, bundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to get enabled bundles from database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetUserGrantedBundleState(
    const sptr<NotificationBundleOption>& targetBundle,
    const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled)
{
    ANS_LOGD("AdvancedNotificationService::SetUserGrantedBundleState");
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(targetBundle);
    if (bundle == nullptr) {
        ANS_LOGE("Bundle is null.");
        return ERR_ANS_INVALID_BUNDLE_OPTION;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter SetUserGrantedBundleState!");
        if (!HasGrantedBundleStateChanged(bundle, enabledBundles)) {
            ANS_LOGW("User granted bundle state has no change");
            return;
        }
        AdvancedNotificationService::GetInstance()->PublishExtensionServiceStateChange(
            NotificationConstant::USER_GRANTED_BUNDLE_STATE, bundle, enabled, enabledBundles);
        result = enabled ?
            NotificationPreferences::GetInstance()->AddExtensionSubscriptionBundles(bundle, enabledBundles) :
            NotificationPreferences::GetInstance()->RemoveExtensionSubscriptionBundles(bundle, enabledBundles);
        if (result != ERR_OK) {
            ANS_LOGE("Failed to set enabled bundles to database, ret: %{public}d", result);
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}
}  // namespace Notification
}  // namespace OHOS
