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
#include "common_event_manager.h"
#include "common_event_publish_info.h"
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
#ifdef ALL_SCENARIO_COLLABORATION
#include "distributed_extension_service.h"
#endif

namespace OHOS {
namespace Notification {
using namespace OHOS::AccountSA;

const static std::string NOTIFICATION_EVENT_DISTRIBUTED_DEVICE_TYPES_CHANGE =
    "notification.event.DISTRIBUTED_DEVICE_TYPES_CHANGE";

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

    NotificationConstant::SWITCH_STATE enableStatus = enabled ?
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    ErrCode result = NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(slotType,
        deviceType, enableStatus);
#ifdef ALL_SCENARIO_COLLABORATION
    if (result == ERR_OK && slotType == NotificationConstant::SlotType::LIVE_VIEW) {
        NotificationConstant::SWITCH_STATE notification = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        if (NotificationPreferences::GetInstance()->IsDistributedEnabled(deviceType,
            notification) != ERR_OK) {
            ANS_LOGW("Get notification distributed failed %{public}s!", deviceType.c_str());
        }
        DeviceStatueChangeInfo changeInfo;
        changeInfo.enableChange = (notification == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
            notification == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) ? true : false;
        changeInfo.liveViewChange = enabled;
        changeInfo.changeType = DeviceStatueChangeType::NOTIFICATION_ENABLE_CHANGE;
        DistributedExtensionService::GetInstance().DeviceStatusChange(changeInfo);
    }

    // master use current to be switch key for expand later; dont remove on master.
    if (result == ERR_OK && !enabled && deviceType != NotificationConstant::CURRENT_DEVICE_TYPE) {
        RemoveDistributedNotifications(slotType,
            NotificationConstant::DISTRIBUTED_ENABLE_CLOSE_DELETE,
            NotificationConstant::DistributedDeleteType::SLOT);
    }
#endif
    ANS_LOGI("SetDistributedEnabledBySlot %{public}d, deviceType: %{public}s, enabled: %{public}s, "
        "SetDistributedEnabledBySlot result: %{public}d",
        slotType, deviceType.c_str(), std::to_string(enabled).c_str(), result);
    message.ErrorCode(result).Append("st:" + std::to_string(slotTypeInt) +
        ", device:" + deviceType + ", en:" + std::to_string(enabled));
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

    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
    ErrCode result =
        NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(slotType, deviceType, enableStatus);
    enabled = (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
    return result;
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
#ifdef ALL_SCENARIO_COLLABORATION
    ErrCode result = DistributeOperationParamCheck(operationInfo, callback);
    if (result != ERR_OK) {
        return result;
    }

    if (notificationSvrQueue_ == nullptr) {
        ANS_LOGE("Serial queue is invalidated");
        return ERR_ANS_INVALID_PARAM;
    }

    OperationType operationType = operationInfo->GetOperationType();
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_21);
    message.Message("key:" + operationInfo->GetHashCode(), false);
    if (operationType == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        operationInfo->SetEventId(std::to_string(GetCurrentTime()));
        std::string key = operationInfo->GetHashCode() + operationInfo->GetEventId();
        DistributedOperationService::GetInstance().AddOperation(key, callback);
    } else if (operationType == OperationType::DISTRIBUTE_OPERATION_JUMP_BY_TYPE) {
        message.Append(", type:" + std::to_string(operationInfo->GetJumpType()) +
            ", index: " + std::to_string(operationInfo->GetBtnIndex()));
    }
    ANS_LOGI("DistributeOperation trigger hashcode %{public}s.", operationInfo->GetHashCode().c_str());
    ffrt::task_handle handler = notificationSvrQueue_->submit_h(std::bind([&]() {
        result = DistributeOperationInner(operationInfo);
    }));
    notificationSvrQueue_->wait(handler);
    if (result != ERR_OK && operationType == OperationType::DISTRIBUTE_OPERATION_REPLY) {
        std::string key = operationInfo->GetHashCode() + operationInfo->GetEventId();
        DistributedOperationService::GetInstance().RemoveOperationResponse(key);
    }
    NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(result));
    return result;
#else
    return ERR_ANS_INVALID_PARAM;
#endif
}

ErrCode AdvancedNotificationService::DistributeOperationInner(const sptr<NotificationOperationInfo>& operationInfo)
{
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
        return NotificationSubscriberManager::GetInstance()->DistributeOperation(operationInfo, request);
    }
    ANS_LOGI("DistributeOperation not exist hashcode.");
    return ERR_ANS_INVALID_PARAM;
}

ErrCode AdvancedNotificationService::ReplyDistributeOperation(const std::string& hashCode, const int32_t result)
{
#ifdef ALL_SCENARIO_COLLABORATION
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
#else
    return ERR_ANS_INVALID_PARAM;
#endif
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

    if (deviceType == NotificationConstant::PAD_DEVICE_TYPE || deviceType == NotificationConstant::PC_DEVICE_TYPE ||
        deviceType == NotificationConstant::SLAVE_DEVICE_TYPE) {
        return DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status,
            controlFlag, deviceId, userId);
    }

    DelayedSingleton<DistributedDeviceStatus>::GetInstance()->SetDeviceStatus(deviceType, status, controlFlag);
    ANS_LOGI("update %{public}s status %{public}u %{public}u", deviceType.c_str(), status, controlFlag);
    return ERR_OK;
}

ErrCode AdvancedNotificationService::SetTargetDeviceBundleList(const std::string& deviceType,
    const std::string& deviceId, int operatorType, const std::vector<std::string>& bundleList,
    const std::vector<std::string>& labelList)
{
#ifdef ALL_SCENARIO_COLLABORATION
    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return DistributedDeviceDataService::GetInstance().SetTargetDeviceBundleList(deviceType, deviceId,
        operatorType, bundleList, labelList);
#else
    return ERR_ANS_INVALID_PARAM;
#endif
}

ErrCode AdvancedNotificationService::GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
    std::string& deviceId, int32_t& userId)
{
    if (deviceType.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("isSubsystem is bogus.");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    DeviceStatus deviceStatus = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetMultiDeviceStatus(
        deviceType, status);
    userId = deviceStatus.userId;
    deviceId = deviceStatus.deviceId;
    return ERR_OK;
}

ErrCode AdvancedNotificationService::GetTargetDeviceBundleList(const std::string& deviceType,
    const std::string& deviceId, std::vector<std::string>& bundleList, std::vector<std::string>& labelList)
{
    if (deviceType.empty() || deviceId.empty()) {
        return ERR_ANS_INVALID_PARAM;
    }

    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    return DistributedDeviceDataService::GetInstance().GetTargetDeviceBundleList(deviceType, deviceId,
        bundleList, labelList);
}

ErrCode AdvancedNotificationService::SetTargetDeviceSwitch(const std::string& deviceType,
    const std::string& deviceId, bool notificaitonEnable, bool liveViewEnable)
{
#ifdef ALL_SCENARIO_COLLABORATION
    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGD("AccessTokenHelper::CheckPermission is false.");
        return ERR_ANS_PERMISSION_DENIED;
    }
    return DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(deviceType, deviceId,
        notificaitonEnable, liveViewEnable);
#else
    return ERR_ANS_INVALID_PARAM;
#endif
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

ErrCode AdvancedNotificationService::SetDistributedBundleOption(
    const std::vector<sptr<DistributedBundleOption>> &bundles,
    const std::string &deviceType)
{
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_13, EventBranchId::BRANCH_10);
    ANS_LOGD("%{public}s", __FUNCTION__);
    if (bundles.empty()) {
        ANS_LOGE("bundles is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message("bundles null").ErrorCode(ERR_ANS_INVALID_PARAM));
        return ERR_ANS_INVALID_PARAM;
    }

    if (deviceType.empty()) {
        ANS_LOGE("deviceType is null.");
        NotificationAnalyticsUtil::ReportModifyEvent(message.Message("device null").ErrorCode(ERR_ANS_INVALID_PARAM));
        return ERR_ANS_INVALID_PARAM;
    }

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

    std::vector<sptr<DistributedBundleOption>> affectBundleOption;
    ANS_LOGD("deviceType: %{public}s",  deviceType.c_str());
    for (auto distributedBundle : bundles) {
        std::string bundleName = distributedBundle->GetBundle()->GetBundleName();
        if (bundleName.empty()) {
            ANS_LOGE("unaffet bundle. empty bundle");
            continue;
        }
        int32_t uid = distributedBundle->GetBundle()->GetUid();
        sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(bundleName, uid);
        sptr<NotificationBundleOption> returnOption = GenerateValidBundleOption(bundleOption);
        if (returnOption == nullptr) {
            ANS_LOGW("unaffet bundle. %{public}s %{public}d", bundleName.c_str(), uid);
            continue;
        }
        distributedBundle->GetBundle()->SetUid(returnOption->GetUid());
        ANS_LOGI("bundleName = %{public}s uidParam= %{public}d finalUid= %{public}d enable = %{public}s",
            bundleName.c_str(), uid, returnOption->GetUid(), std::to_string(distributedBundle->isEnable()).c_str());
        affectBundleOption.emplace_back(distributedBundle);
    }

    if (affectBundleOption.empty()) {
        ANS_LOGE("no bundle is afffect");
        NotificationAnalyticsUtil::ReportModifyEvent(message.ErrorCode(
            ERR_ANS_DISTRIBUTED_OPERATION_FAILED).BranchId(BRANCH_13));
        return ERR_ANS_DISTRIBUTED_OPERATION_FAILED;
    }

    ErrCode result = NotificationPreferences::GetInstance()->SetDistributedBundleOption(
        affectBundleOption, deviceType);

    ANS_LOGI("SetDistributedBundleOption result: %{public}s, %{public}d",  deviceType.c_str(), result);
    NotificationAnalyticsUtil::ReportModifyEvent(
        message.Message("batch").ErrorCode(result).BranchId(BRANCH_13));

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
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_8, EventBranchId::BRANCH_22);
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGD("Not system app or SA!");
        message.ErrorCode(ERR_ANS_NON_SYSTEM_APP).Append("Not SystemApp");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        message.ErrorCode(ERR_ANS_PERMISSION_DENIED).Append("No permission");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return ERR_ANS_PERMISSION_DENIED;
    }

    auto result = NotificationPreferences::GetInstance()->SetDistributedEnabled(deviceType,
        enabled ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON
        : NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);

    ANS_LOGI("SetDistributedEnabled deviceType:%{public}s,enabled:%{public}s,result:%{public}d",
        deviceType.c_str(), std::to_string(enabled).c_str(), result);

    message.ErrorCode(result).Append("device:" + deviceType + ", en:" + std::to_string(enabled));
    NotificationAnalyticsUtil::ReportModifyEvent(message);
    if (deviceType == NotificationConstant::LITEWEARABLE_DEVICE_TYPE) {
        return result;
    }

#ifdef ALL_SCENARIO_COLLABORATION
    if (result == ERR_OK) {
        NotificationConstant::SWITCH_STATE liveViewEnableStatus =
            NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        if (NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(
            NotificationConstant::SlotType::LIVE_VIEW, deviceType, liveViewEnableStatus) != ERR_OK) {
            ANS_LOGW("Get live view distributed failed %{public}s!", deviceType.c_str());
        }
        DeviceStatueChangeInfo changeInfo;
        changeInfo.enableChange = enabled;
        changeInfo.liveViewChange = (liveViewEnableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON ||
            liveViewEnableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        changeInfo.changeType = DeviceStatueChangeType::NOTIFICATION_ENABLE_CHANGE;
        DistributedExtensionService::GetInstance().DeviceStatusChange(changeInfo);
    }

    // master use current to be switch key for expand later; dont remove on master.
    if (result == ERR_OK && !enabled && deviceType != NotificationConstant::CURRENT_DEVICE_TYPE) {
        RemoveDistributedNotifications(NotificationConstant::SlotType::LIVE_VIEW,
            NotificationConstant::DISTRIBUTED_ENABLE_CLOSE_DELETE,
            NotificationConstant::DistributedDeleteType::EXCLUDE_ONE_SLOT);
    }
#endif
    return result;
}

ErrCode AdvancedNotificationService::IsDistributedEnabled(const std::string &deviceType, bool &enabled)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system app or SA!");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    NotificationConstant::SWITCH_STATE enableStatus;
    ErrCode errResult = NotificationPreferences::GetInstance()->IsDistributedEnabled(deviceType, enableStatus);
    enabled = (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON);
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

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    auto result = NotificationPreferences::GetInstance()->GetDistributedAuthStatus(deviceType, deviceId,
        userId, isAuth);
    if (result == ERR_OK && isAuth) {
        UpdateDistributedDeviceList(deviceType);
    }
    return result;
}

ErrCode AdvancedNotificationService::UpdateDistributedDeviceList(const std::string &deviceType)
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

    int32_t userId = SUBSCRIBE_USER_INIT;
    auto result = OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    if (result != ERR_OK) {
        ANS_LOGD("GetCurrentActiveUserId fail %{public}d.", result);
        return ERR_ANS_GET_ACTIVE_USER_FAILED;
    }

    std::vector<std::string> deviceTypes;
    result = NotificationPreferences::GetInstance()->GetDistributedDevicelist(deviceTypes);
    if (result != ERR_OK) {
        ANS_LOGE("Get distributed device list failed");
        return result;
    }
    auto it = std::find(deviceTypes.begin(), deviceTypes.end(), deviceType);
    if (it != deviceTypes.end()) {
        ANS_LOGI("Distributed %{public}s set Previously", deviceType.c_str());
        return ERR_OK;
    }
    deviceTypes.push_back(deviceType);
    result = NotificationPreferences::GetInstance()->SetDistributedDevicelist(deviceTypes, userId);
    if (result != ERR_OK) {
        ANS_LOGE("Set distributed device list failed");
        return result;
    }
    EventFwk::Want want;
    want.SetAction(NOTIFICATION_EVENT_DISTRIBUTED_DEVICE_TYPES_CHANGE);
    EventFwk::CommonEventData commonData{ want };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberType(EventFwk::SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    if (!EventFwk::CommonEventManager::PublishCommonEventAsUser(commonData, publishInfo, userId)) {
        ANS_LOGW("Publish common event failed");
    }
    return ERR_OK;
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

    if (!AccessTokenHelper::CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        ANS_LOGE("no permission");
        return ERR_ANS_PERMISSION_DENIED;
    }

    auto result =
        NotificationPreferences::GetInstance()->SetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);
    if (result == ERR_OK && isAuth) {
        UpdateDistributedDeviceList(deviceType);
    }
    return result;
}

ErrCode AdvancedNotificationService::GetDistributedDevicelist(std::vector<std::string> &deviceTypes)
{
    ANS_LOGD("%{public}s", __FUNCTION__);
    bool isSubSystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubSystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Not system app or SA!");
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
