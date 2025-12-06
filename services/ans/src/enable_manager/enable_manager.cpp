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

#include "accesstoken_kit.h"
#include "access_token_helper.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_trace_wrapper.h"
#include "ans_permission_def.h"

#include "bundle_manager_helper.h"
#include "ipc_skeleton.h"

#include "notification_preferences.h"
#include "notification_bundle_option.h"
#include "notification_analytics_util.h"
#include "os_account_manager_helper.h"
#include "notification_extension_wrapper.h"
#include "notification_config_parse.h"
#include "distributed_data_define.h"

namespace OHOS {
namespace Notification {
    
constexpr int32_t ANS_USERID = 5523;
const static std::string BUNDLE_NAME_ZYT = "com.zhuoyi.appstore.lite";
const static std::string BUNDLE_NAME_ABROAD = "com.easy.abroad";
const static std::string INSTALL_SOURCE_EASYABROAD = "com.easy.abroad";
constexpr int32_t ZERO_USER_ID = 0;

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback)
{
    return RequestEnableNotification(deviceId, callback, nullptr);
}

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_13, EventBranchId::BRANCH_4);
    message.Message(" de:" + deviceId);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (callback == nullptr) {
        ANS_LOGE("callback == nullptr");
        message.ErrorCode(ERR_ANS_INVALID_PARAM);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_PARAM;
    }
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERROR_INTERNAL_ERROR;
    }
    return CommonRequestEnableNotification(deviceId, callback, callerToken, bundleOption, false, false);
}

ErrCode AdvancedNotificationService::RequestEnableNotification(const std::string& bundleName, int32_t uid)
{
    ANS_LOGI("requestEnableNotification bundle=%{public}s uid=%{public}d", bundleName.c_str(), uid);
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (bundleName == BUNDLE_NAME_ZYT || bundleName == BUNDLE_NAME_ABROAD) {
        ANS_LOGE("zyt or abroad");
        return ERR_ANS_NOT_ALLOWED;
    }

    AppExecFwk::BundleInfo bundleInfo;
    bool ret = BundleManagerHelper::GetInstance()->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION),
        bundleInfo, ZERO_USER_ID);
    if (bundleInfo.applicationInfo.label.empty()) {
        ANS_LOGE("empty label, %{public}s", bundleName.c_str());
        return ERR_ANS_NOT_ALLOWED;
    }
    bool easyAbroad = false;
    if (bundleInfo.applicationInfo.installSource == INSTALL_SOURCE_EASYABROAD) {
        ANS_LOGW("abroad app");
        easyAbroad = true;
    }
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERROR_INTERNAL_ERROR;
    }
    return CommonRequestEnableNotification("", nullptr, nullptr, bundleOption, true, easyAbroad);
}

ErrCode AdvancedNotificationService::CommonRequestEnableNotification(const std::string &deviceId,
    const sptr<IAnsDialogCallback> &callback,
    const sptr<IRemoteObject> &callerToken,
    const sptr<NotificationBundleOption> bundleOption,
    const bool innerLake,
    const bool easyAbroad)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    // To get the permission
    bool allowedNotify = false;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_5);
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERROR_INTERNAL_ERROR;
    }
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
            " deviceId:" + deviceId);
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (result != ERR_OK) {
        ANS_LOGE("Not allowed notify self");
        message.ErrorCode(result).Append(" Allow failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    ANS_LOGI("allowedNotify=%{public}d, bundle=%{public}s", allowedNotify,
        bundleOption->GetBundleName().c_str());
    if (allowedNotify) {
        message.ErrorCode(ERR_OK).Append(" Allow success");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_OK;
    }
    // Check to see if it has been popover before
    bool hasPopped = false;
    result = GetHasPoppedDialog(bundleOption, hasPopped);
    if (result != ERR_OK) {
        ANS_LOGE("Get has popped dialog failed.");
        message.ErrorCode(result).Append(" Get dialog failed.");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    if (hasPopped) {
        ANS_LOGW("Has popped is true.");
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
        int32_t userId = -1;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
        ANS_LOGD("GetOsAccountLocalIdFromUid PRI, %{public}d, %{public}d", bundleOption->GetUid(), userId);
        if (!EXTENTION_WRAPPER->GetPrivilegeDialogPopped(bundleOption, userId)) {
            ANS_LOGE("GetPrivilegeDialogPopped false.");
            message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Has no permission popped");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return ERR_ANS_NOT_ALLOWED;
        } else {
            ANS_LOGW("duplicated popped.");
            message.Append(" duplicated popped.");
        }
#else
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Has popped");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NOT_ALLOWED;
#endif
    }
    if (!EXTENTION_WRAPPER->NotificationDialogControl()) {
        return ERR_ANS_NOT_ALLOWED;
    }

    if (!CreateDialogManager()) {
        ANS_LOGE("Create dialog manager failed.");
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Create dialog failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }

    result = dialogManager_->RequestEnableNotificationDailog(bundleOption,
        callback, callerToken, innerLake, easyAbroad);
    if (result == ERR_OK) {
        result = ERR_ANS_DIALOG_POP_SUCCEEDED;
    }

    ANS_LOGI("%{public}s_%{public}d, deviceId: %{public}s, result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), StringAnonymous(deviceId).c_str(), result);
    message.ErrorCode(result);
    if (!innerLake || result == ERR_ANS_DIALOG_POP_SUCCEEDED) {
        NotificationAnalyticsUtil::ReportModifyEvent(message);
    }
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled)
{
    return ERR_INVALID_OPERATION;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        if (deviceId.empty()) {
            // Local device
            result = NotificationPreferences::GetInstance()->SetNotificationsEnabled(userId, enabled);
        } else {
            // Remote device
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForSpecialBundle(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled,
    bool updateUnEnableTime)
{
    return SetNotificationsEnabledForSpecialBundleImpl(
        deviceId, bundleOption, enabled, updateUnEnableTime, false);
}

ErrCode AdvancedNotificationService::SetNotificationsSystemEnabledForSpecialBundle(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled,
    bool updateUnEnableTime)
{
    return SetNotificationsEnabledForSpecialBundleImpl(
        deviceId, bundleOption, enabled, updateUnEnableTime, true);
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledForSpecialBundleImpl(
    const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled,
    bool updateUnEnableTime, bool isSystemCall)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_13, EventBranchId::BRANCH_5);
    NOTIFICATION_HITRACE(HITRACE_TAG_NOTIFICATION);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_INVALID_BUNDLE;
    }

    NotificationConstant::SWITCH_STATE state = isSystemCall ?
        (enabled ? NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON :
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF) :
        (enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
            NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);

    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
            " st:" + std::to_string(static_cast<int32_t>(state)) +
            " dId:" + deviceId);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).BranchId(BRANCH_6);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ANS_USERID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).BranchId(BRANCH_7);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        message.ErrorCode(ERR_ANS_INVALID_BUNDLE).BranchId(BRANCH_8);
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        ANS_LOGE(" Bundle is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    sptr<EnabledNotificationCallbackData> bundleData = new (std::nothrow)
        EnabledNotificationCallbackData(bundle->GetBundleName(), bundle->GetUid(), enabled);
    if (bundleData == nullptr) {
        ANS_LOGE("Failed to create EnabledNotificationCallbackData instance");
        return ERR_NO_MEMORY;
    }

    ErrCode result = ERR_OK;
    if (deviceId.empty()) {
        // Local device
        result = NotificationPreferences::GetInstance()->SetNotificationsEnabledForBundle(bundle, state);
        if (result == ERR_OK) {
            if (!enabled) {
                result = RemoveAllNotificationsForDisable(bundle);
            }
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
            if (!enabled && result == ERR_OK && updateUnEnableTime) {
                SetDialogPoppedUnEnableTime(bundleOption);
            }
#endif
            SetSlotFlagsTrustlistsAsBundle(bundle);
            NotificationSubscriberManager::GetInstance()->NotifyEnabledNotificationChanged(bundleData);
            PublishSlotChangeCommonEvent(bundle);
        }
    } else {
        // Remote device
    }

    ANS_LOGI("set enable for special bundle %{public}s_%{public}d, deviceId: %{public}s, state: %{public}s, "
        "result: %{public}d", bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid(), StringAnonymous(deviceId).c_str(),
        std::to_string(static_cast<int32_t>(state)).c_str(), result);
        message.ErrorCode(result).BranchId(BRANCH_9);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    SendEnableNotificationHiSysEvent(bundleOption, enabled, result);
    return result;
}

ErrCode AdvancedNotificationService::CanPopEnableNotificationDialog(
    const sptr<IAnsDialogCallback> &callback, bool &canPop, std::string &bundleName)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    canPop = false;
    ErrCode result = ERR_OK;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption is nullptr.");
        return ERR_ANS_INVALID_BUNDLE;
    }
    // To get the permission
    bool allowedNotify = false;
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_2, EventBranchId::BRANCH_2);
    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " canPop:" + std::to_string(canPop));
    result = IsAllowedNotifySelf(bundleOption, allowedNotify);
    if (result != ERR_OK) {
        ANS_LOGE("Not allowed Notify self.");
        message.ErrorCode(result).Append(" Not Allow");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    ANS_LOGI("allowedNotify=%{public}d, bundle=%{public}s", allowedNotify,
        bundleOption->GetBundleName().c_str());
    if (allowedNotify) {
        message.ErrorCode(ERR_OK).Append(" Allow success");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_OK;
    }
    // Check to see if it has been popover before
    bool hasPopped = false;
    result = GetHasPoppedDialog(bundleOption, hasPopped);
    if (result != ERR_OK) {
        ANS_LOGE("Get has popped dialog failed. result: %{public}d", result);
        message.ErrorCode(result).Append(" Has popped");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    if (hasPopped) {
        ANS_LOGE("Has popped is true.");
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
        int32_t userId = -1;
        OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId);
        ANS_LOGD("GetOsAccountLocalIdFromUid PRI, %{public}d, %{public}d", bundleOption->GetUid(), userId);
        if (!EXTENTION_WRAPPER->GetPrivilegeDialogPopped(bundleOption, userId)) {
            ANS_LOGE("GetPrivilegeDialogPopped false.");
            message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Has no permission popped");
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            return ERR_ANS_NOT_ALLOWED;
        } else {
            ANS_LOGI("duplicated popped.");
            message.Append(" duplicated popped.");
        }
#else
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Has popped");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NOT_ALLOWED;
#endif
    }
    if (!EXTENTION_WRAPPER->NotificationDialogControl()) {
        return ERR_ANS_NOT_ALLOWED;
    }
    
    if (!CreateDialogManager()) {
        ANS_LOGE("Create dialog manager failed.");
        message.ErrorCode(ERR_ANS_NOT_ALLOWED).Append(" Create dialog failed");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERROR_INTERNAL_ERROR;
    }
    result = dialogManager_->AddDialogInfo(bundleOption, callback);
    if (result != ERR_OK) {
        ANS_LOGI("AddDialogInfo result: %{public}d", result);
        message.ErrorCode(result).Append(" AddDialogInfo");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return result;
    }

    canPop = true;
    bundleName = bundleOption->GetBundleName();
    ANS_LOGI("%{public}s_%{public}d, canPop: %{public}s, result: %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), std::to_string(canPop).c_str(), result);
    message.ErrorCode(result).Append(" CanPopEnableNotificationDialog end");
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::RemoveEnableNotificationDialog()
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    ErrCode result = ERR_OK;
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption == nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    return RemoveEnableNotificationDialog(bundleOption);
}

ErrCode AdvancedNotificationService::RemoveEnableNotificationDialog(const sptr<NotificationBundleOption> &bundleOption)
{
    ANS_LOGI("%{public}s, %{public}d",
        bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid());
    if (!CreateDialogManager()) {
        return ERROR_INTERNAL_ERROR;
    }
    std::unique_ptr<NotificationDialogManager::DialogInfo> dialogInfoRemoved = nullptr;
    dialogManager_->RemoveDialogInfoByBundleOption(bundleOption, dialogInfoRemoved);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetAllNotificationEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    if (!AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Is not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetAllNotificationEnabledBundles(bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Get all notification enable status failed");
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::GetAllNotificationEnabledBundles(
    std::vector<NotificationBundleOption> &bundleOption, const int32_t userId)
{
    ANS_LOGD("Called.");
    if (!OsAccountManagerHelper::GetInstance().CheckUserExists(userId)) {
        ANS_LOGE("Check user exists failed.");
        return ERROR_USER_NOT_EXIST;
    }
    if (!AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Is not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetAllNotificationEnabledBundles(bundleOption, userId);
        if (result != ERR_OK) {
            ANS_LOGE("Get all notification enable status failed");
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetNotificationsEnabledByUser(int32_t userId, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is ineffectiveness.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->SetNotificationsEnabled(userId, enabled);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotify(bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false");
        return ERR_ANS_PERMISSION_DENIED;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentCallingUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        allowed = false;
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }
    return IsAllowedNotifySelf(bundleOption, allowed);
}

ErrCode AdvancedNotificationService::IsAllowedNotifySelf(const sptr<NotificationBundleOption> &bundleOption,
    bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
#ifdef NOTIFICATION_MULTI_FOREGROUND_USER
    if (OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(bundleOption->GetUid(), userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
#else
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGD("GetActiveUserId is false");
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
#endif

    ErrCode result = ERR_OK;
    allowed = false;
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(bundleOption, state);
        if (result == ERR_OK) {
            allowed = (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
                state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        }
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            // FA model app can publish notification without user confirm
            allowed = CheckApiCompatibility(bundleOption);
            SetDefaultNotificationEnabled(bundleOption, allowed);
        }
    }
    ANS_LOGI("get ntf auth status %{public}s %{public}d %{public}d %{public}d",
        bundleOption->GetBundleName().c_str(), bundleOption->GetUid(), allowed, result);
    return result;
}

ErrCode AdvancedNotificationService::IsSpecialUserAllowedNotify(int32_t userId, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Failed to checkPermission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("NotificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        allowed = false;
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    }));
    notificationSvrQueue_->wait(handler);
    return result;
}

ErrCode AdvancedNotificationService::IsSpecialBundleAllowedNotify(
    const sptr<NotificationBundleOption> &bundleOption, bool &allowed)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system application");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ANS_USERID && !AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> targetBundle = nullptr;
    if (isSubsystem) {
        if (bundleOption != nullptr) {
            targetBundle = GenerateValidBundleOption(bundleOption);
        }
    } else {
        ErrCode result = GetAppTargetBundle(bundleOption, targetBundle);
        if (result != ERR_OK) {
            return result;
        }
    }

    if (targetBundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    int32_t userId = SUBSCRIBE_USER_INIT;
#ifdef NOTIFICATION_MULTI_FOREGROUND_USER
    if (OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(targetBundle->GetUid(), userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
#else
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }
#endif

    ErrCode result = ERR_OK;
    allowed = false;
    NotificationConstant::SWITCH_STATE state = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    result = NotificationPreferences::GetInstance()->GetNotificationsEnabled(userId, allowed);
    if (result == ERR_OK && allowed) {
        result = NotificationPreferences::GetInstance()->GetNotificationsEnabledForBundle(targetBundle, state);
        if (result == ERR_OK) {
            allowed = (state == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
                state == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        }
        if (result == ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST) {
            result = ERR_OK;
            allowed = CheckApiCompatibility(targetBundle);
            SetNotificationsSystemEnabledForSpecialBundle("", bundleOption, allowed);
        }
    }
    return result;
}

ErrCode AdvancedNotificationService::CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish)
{
    return ERR_INVALID_OPERATION;
}

} // Notification
} // OHOS
