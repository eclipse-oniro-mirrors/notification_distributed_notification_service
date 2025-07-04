/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "os_account_manager_helper.h"
#include "hitrace_meter_adapter.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

#include "../advanced_notification_inline.cpp"
#include "notification_analytics_util.h"
#include "notification_operation_service.h"
#include "distributed_device_data_service.h"
#include "distributed_extension_service.h"

namespace OHOS {
namespace Notification {
using namespace OHOS::AccountSA;

ErrCode AdvancedNotificationService::IsDistributedEnabled(bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = DistributedPreferences::GetInstance()->GetDistributedEnable(enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::SetDistributedEnabledBySlot(
    int32_t slotTypeInt, const std::string &deviceType, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_7);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append("Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append("No permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    ErrCode result = NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(slotType,
        deviceType, enabled);
    if (result == ERR_OK && slotType == NotificationConstant::SlotType::LIVE_VIEW) {
        NotificationConstant::ENABLE_STATUS notification = NotificationConstant::ENABLE_STATUS::DEFAULT_FALSE;
        if (NotificationPreferences::GetInstance()->IsDistributedEnabled(deviceType,
            notification) != ERR_OK) {
            ANS_LOGW("Get notification distributed failed %{public}s!", deviceType.c_str());
        }
        DeviceStatueChangeInfo changeInfo;
        changeInfo.enableChange = (notification == NotificationConstant::ENABLE_STATUS::ENABLE_TRUE) ? true : false;
        changeInfo.liveViewChange = enabled;
        changeInfo.changeType = DeviceStatueChangeType::NOTIFICATION_ENABLE_CHANGE;
        DistributedExtensionService::GetInstance().DeviceStatusChange(changeInfo);
    }

    if (result == ERR_OK && !enabled) {
        RemoveDistributedNotifications(slotType,
            NotificationConstant::DISTRIBUTED_ENABLE_CLOSE_DELETE,
            NotificationConstant::DistributedDeleteType::SLOT);
    }
    ANS_LOGI("SetDistributedEnabledBySlot %{public}d, deviceType: %{public}s, enabled: %{public}s, "
        "SetDistributedEnabledBySlot result: %{public}d",
        slotType, deviceType.c_str(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);

    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabledBySlot(
    int32_t slotTypeInt, const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    NotificationConstant::SlotType slotType = static_cast<NotificationConstant::SlotType>(slotTypeInt);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    return NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(slotType, deviceType, enabled);
}

ErrCode AdvancedNotificationService::EnableDistributed(bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("VerifyNativeToken and IsSystemApp is false.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            result = DistributedPreferences::GetInstance()->SetDistributedEnable(enabled);
            ANS_LOGE("ffrt enter!");
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::EnableDistributedByBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Create bundle failed.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundle, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = DistributedPreferences::GetInstance()->SetDistributedBundleEnable(bundle, enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::EnableDistributedSelf(const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    sptr<NotificationBundleOption> bundleOption = GenerateBundleOption();
    if (bundleOption == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundleOption, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("notificationSvrQueue_ is nullptr.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind(
        [&]() {
            ANS_LOGD("ffrt enter!");
            result = DistributedPreferences::GetInstance()->SetDistributedBundleEnable(bundleOption, enabled);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::IsDistributedEnableByBundle(
    const sptr<NotificationBundleOption> &bundleOption, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGD("Failed to create bundle.");
        return ERR_ANS_INVALID_BUNDLE;
    }

    bool appInfoEnable = true;
    GetDistributedEnableInApplicationInfo(bundle, appInfoEnable);
    if (!appInfoEnable) {
        ANS_LOGD("Get from bms is %{public}d", appInfoEnable);
        enabled = appInfoEnable;
        return ERR_OK;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        ANS_LOGD("ffrt enter!");
        result = DistributedPreferences::GetInstance()->GetDistributedBundleEnable(bundle, enabled);
        if (result != ERR_OK) {
            result = ERR_OK;
            enabled = false;
        }
    }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    uint32_t result = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(deviceType);
    status = static_cast<int32_t>(result);
    ANS_LOGI("Get %{public}s status %{public}u", deviceType.c_str(), status);
    return ERR_OK;
}


ErrCode DistributeOperationParamCheck(const sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    if (operationInfo == nullptr || operationInfo->GetHashCode().empty()) {
        ANS_LOGE("hashCode is empty.");
        return ERR_ANS_INVALID_PARAM;
    }

    OperationType operationType = operationInfo->GetOperationType();
    if (operationType != OperationType::DISTRIBUTE_OPERATION_JUMP &&
        operationType != OperationType::DISTRIBUTE_OPERATION_REPLY &&
        operationType != OperationType::DISTRIBUTE_OPERATION_JUMP_BY_TYPE) {
        ANS_LOGE("operation type is error.");
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("is not system app.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("not have permission.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode AdvancedNotificationService::DistributeOperation(const sptr<NotificationOperationInfo>& operationInfo,
    const sptr<IAnsOperationCallback> &callback)
{
    ErrCode result = DistributeOperationParamCheck(operationInfo, callback);
    if (result != ERR_OK) {
        return result;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated");
        return ERR_ANS_INVALID_PARAM;
    }

    OperationType operationType = operationInfo->GetOperationType();
    if (operationType == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        operationInfo->SetEventId(std::to_string(GetCurrentTime()));
        std::string key = operationInfo->GetHashCode() + operationInfo->GetEventId();
        DistributedOperationService::GetInstance().AddOperation(key, callback);
    }
    ANS_LOGI("DistributeOperation trigger hashcode %{public}s.", operationInfo->GetHashCode().c_str());
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        std::string hashCode = operationInfo->GetHashCode();
        for (auto record : notificationList_) {
            if (record->notification->GetKey() != hashCode) {
                continue;
            }
            if (record->notification->GetNotificationRequestPoint() == nullptr) {
                continue;
            }
            auto request = record->notification->GetNotificationRequestPoint();
            if (!request->GetDistributedCollaborate()) {
                ANS_LOGI("Not collaborate hashcode %{public}s.", hashCode.c_str());
                continue;
            }
            result = NotificationSubscriberManager::GetInstance()->DistributeOperation(operationInfo, request);
            return;
        }
        ANS_LOGI("DistributeOperation not exist hashcode.");
        result = ERR_ANS_INVALID_PARAM;
    }));
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK && operationType == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        std::string key = operationInfo->GetHashCode() + operationInfo->GetEventId();
        DistributedOperationService::GetInstance().RemoveOperationResponse(key);
    }
    return result;
}

ErrCode AdvancedNotificationService::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (hashCode.empty()) {
        ANS_LOGE("Hash code is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ANS_LOGI("Reply operation key %{public}s %{public}d.", hashCode.c_str(), result);
    DistributedOperationService::GetInstance().ReplyOperationResponse(hashCode, result);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
    const std::string &deviceId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    uint32_t status_ = status;
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status_,
        DistributedDeviceStatus::DISTURB_DEFAULT_FLAG);
    ANS_LOGI("update %{public}s status %{public}u", deviceType.c_str(), status);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
    uint32_t controlFlag, const std::string &deviceId, int32_t userId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("Check permission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (deviceType == NotificationConstant::PAD_DEVICE_TYPE || deviceType == NotificationConstant::PC_DEVICE_TYPE) {
        return DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status,
            controlFlag, deviceId, userId);
    }

    DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status, controlFlag);
    ANS_LOGI("update %{public}s status %{public}u %{public}u", deviceType.c_str(), status, controlFlag);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetTargetDeviceBundleList(const std::string& deviceType,
    const std::string& deviceId, int operatorType, const std::vector<std::string>& bundleList)
{
    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(deviceType, deviceId,
        operatorType, bundleList);
}

ErrCode AdvancedNotificationService::SetTargetDeviceSwitch(const std::string& deviceType,
    const std::string& deviceId, bool notificaitonEnable, bool liveViewEnable)
{
    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(deviceType, deviceId,
        notificaitonEnable, liveViewEnable);
}

ErrCode AdvancedNotificationService::GetAllDistribuedEnabledBundles(
    const std::string& deviceType, std::vector<NotificationBundleOption> &bundleOption)
{
    ANS_LOGD("Called.");
    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission denied.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }

    int32_t userId = 100;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&, userId, deviceType]() {
        ANS_LOGD("ffrt enter!");
        result = NotificationPreferences::GetInstance()->GetAllDistribuedEnabledBundles(userId,
            deviceType, bundleOption);
        if (result != ERR_OK) {
            ANS_LOGE("Get all notification enable status failed");
            return;
        }
    }));
    notificationSvrQueue_->wait(handler);

    return result;
}

ErrCode AdvancedNotificationService::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_6);
    message.Message(" enabled:" + std::to_string(enabled) + " deviceType:" + deviceType);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append(" Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append(" Permission Denied");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }
    ErrCode result = NotificationPreferences::GetInstance()->SetSmartReminderEnabled(deviceType, enabled);

    ANS_LOGI("enabled: %{public}s, deviceType: %{public}s,Set smart reminder enabled: %{public}d",
        std::to_string(enabled).c_str(), deviceType.c_str(), result);
    message.ErrorCode(result);
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    return result;
}

ErrCode AdvancedNotificationService::IsSmartReminderEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    return NotificationPreferences::GetInstance()->IsSmartReminderEnabled(deviceType, enabled);
}

ErrCode AdvancedNotificationService::SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_13, EventBranchId::BRANCH_10);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundleOption == nullptr) {
        ANS_LOGE("BundleOption is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_INVALID_BUNDLE));
        return ERR_ANS_INVALID_BUNDLE;
    }

    message.Message(bundleOption->GetBundleName() + "_" + std::to_string(bundleOption->GetUid()) +
        " en:" + std::to_string(enabled) + " dT:" + deviceType);
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("IsSystemApp is false.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).BranchId(BRANCH_11));
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("Permission Denied.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(ERR_ANS_PERMISSION_DENIED).BranchId(BRANCH_12));
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        ANS_LOGE("bundle is nullptr");
        return ERR_ANS_INVALID_BUNDLE;
    }
    
    ErrCode result = NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(bundle,
        deviceType, enabled);
    
    ANS_LOGI("%{public}s_%{public}d, deviceType: %{public}s, enabled: %{public}s, "
        "SetDistributedEnabledByBundle result: %{public}d", bundleOption->GetBundleName().c_str(),
        bundleOption->GetUid(), deviceType.c_str(), std::to_string(enabled).c_str(), result);
    NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result).BranchId(BRANCH_13));

    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
    const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    sptr<NotificationBundleOption> bundle = GenerateValidBundleOption(bundleOption);
    if (bundle == nullptr) {
        return ERR_ANS_INVALID_BUNDLE;
    }

    return NotificationPreferences::GetInstance()->IsDistributedEnabledByBundle(bundle, deviceType, enabled);
}

ErrCode AdvancedNotificationService::SetDistributedEnabled(const std::string &deviceType, const bool enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGW("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    auto result = NotificationPreferences::GetInstance()->SetDistributedEnabled(deviceType,
        enabled ? NotificationConstant::ENABLE_STATUS::ENABLE_TRUE : NotificationConstant::ENABLE_STATUS::ENABLE_FALSE);
    if (result == ERR_OK) {
        bool liveViewEnabled = false;
        if (NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(
            NotificationConstant::SlotType::LIVE_VIEW, deviceType, liveViewEnabled) != ERR_OK) {
            ANS_LOGW("Get live view distributed failed %{public}s!", deviceType.c_str());
        }
        DeviceStatueChangeInfo changeInfo;
        changeInfo.enableChange = enabled;
        changeInfo.liveViewChange = liveViewEnabled;
        changeInfo.changeType = DeviceStatueChangeType::NOTIFICATION_ENABLE_CHANGE;
        DistributedExtensionService::GetInstance().DeviceStatusChange(changeInfo);
    }

    if (result == ERR_OK && !enabled) {
        RemoveDistributedNotifications(NotificationConstant::SlotType::LIVE_VIEW,
            NotificationConstant::DISTRIBUTED_ENABLE_CLOSE_DELETE,
            NotificationConstant::DistributedDeleteType::EXCLUDE_ONE_SLOT);
    }
    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGW("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    NotificationConstant::ENABLE_STATUS enableStatus;
    ErrCode errResult = NotificationPreferences::GetInstance()->IsDistributedEnabled(deviceType, enableStatus);
    enabled = (enableStatus == NotificationConstant::ENABLE_STATUS::ENABLE_TRUE);
    return errResult;
}

ErrCode AdvancedNotificationService::GetDistributedAbility(int32_t &abilityId)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    abilityId = static_cast<int32_t>(NotificationConstant::DANS_SUPPORT_STATUS::UNSUPPORT);
    bool isPrivate = false;
    ErrCode result = OsAccountManagerHelper::GetInstance().GetOsAccountPrivateStatus(isPrivate);
    if (result != ERR_OK || isPrivate) {
        return result;
    }
    abilityId = static_cast<int32_t>(NotificationConstant::DANS_SUPPORT_STATUS::SUPPORT);
    return result;
}

ErrCode AdvancedNotificationService::GetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    return NotificationPreferences::GetInstance()->GetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);
}

ErrCode AdvancedNotificationService::SetDistributedAuthStatus(
    const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("IsSystemApp is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    auto result =
        NotificationPreferences::GetInstance()->SetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);
    if (result == ERR_OK && isAuth) {
        std::vector<std::string> deviceTypes;
        if (NotificationPreferences::GetInstance()->GetDistributedDevicelist(deviceTypes) == ERR_OK) {
            auto it = std::find(deviceTypes.begin(), deviceTypes.end(), deviceType);
            if (it == deviceTypes.end()) {
                deviceTypes.push_back(deviceType);
                NotificationPreferences::GetInstance()->SetDistributedDevicelist(deviceTypes, userId);
            }
        }
    }
    return result;
}

ErrCode AdvancedNotificationService::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGW("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return NotificationPreferences::GetInstance()->GetDistributedDevicelist(deviceTypes);
}

ErrCode AdvancedNotificationService::GetDeviceRemindType(int32_t& remindTypeInt)
{
    ANS_LOGD("%{public}s", __FUNCTION__);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ffrt::task_handle handler =
        notificationSvrQueue_->submit_h(std::bind([&]() { remindTypeInt = static_cast<int32_t>(GetRemindType()); }));
    notificationSvrQueue_->wait(handler);
    return ERR_OK;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled)
{
    ANS_LOGD("userId: %{public}d, enabled: %{public}d", userId, enabled);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidity.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = DistributedPreferences::GetInstance()->SetSyncEnabledWithoutApp(userId, enabled);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}

ErrCode AdvancedNotificationService::GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled)
{
    ANS_LOGD("userId: %{public}d", userId);

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalid.");
        return ERR_ANS_INVALID_PARAM;
    }
    ErrCode result = ERR_OK;
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(
        std::bind([&]() {
            ANS_LOGD("ffrt enter!");
            result = DistributedPreferences::GetInstance()->GetSyncEnabledWithoutApp(userId, enabled);
        }));
    notificationSvrQueue_->wait(handler);
    return result;
#else
    return ERR_INVALID_OPERATION;
#endif
}
}  // namespace Notification
}  // namespa OHOS
