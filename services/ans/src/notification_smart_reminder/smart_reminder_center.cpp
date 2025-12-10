/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "smart_reminder_center.h"

#include "ans_log_wrapper.h"
#include "ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_config_parse.h"
#include "notification_local_live_view_content.h"
#include "notification_preferences.h"
#include "os_account_manager.h"
#include "screenlock_manager.h"
#include "string_utils.h"
#include "distributed_device_data_service.h"
#include "bundle_manager_helper.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
#include "notification_extension_wrapper.h"
#endif
#include "os_account_manager_helper.h"
#include "distributed_data_define.h"
#include "nlohmann/json.hpp"
#include "screen_manager.h"
#include "health_white_list_util.h"

namespace OHOS {
namespace Notification {
using namespace std;
constexpr int32_t CONTROL_BY_SMART_REMINDER = 1 << 15;

SmartReminderCenter::SmartReminderCenter()
{
    DelayedSingleton<NotificationConfigParse>::GetInstance()->GetCollaborationFilter();
    if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetCurrentSlotReminder(currentReminderMethods_)) {
        return;
    }
    GetMultiDeviceReminder();
}

void SmartReminderCenter::GetMultiDeviceReminder()
{
    nlohmann::json root;
    string multiJsonPoint = "/";
    multiJsonPoint.append(NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE);
    multiJsonPoint.append("/");
    multiJsonPoint.append(MULTI_DEVICE_REMINDER);
    if (!DelayedSingleton<NotificationConfigParse>::GetInstance()->GetConfigJson(multiJsonPoint, root)) {
        ANS_LOGE("Failed to get multiDeviceReminder CCM config file.");
        return;
    }

    if (root.find(NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE) == root.end()) {
        ANS_LOGE("GetMultiDeviceReminder failed as can not find notificationService.");
        return;
    }

    nlohmann::json multiDeviceRemindJson =
        root[NotificationConfigParse::CFG_KEY_NOTIFICATION_SERVICE][MULTI_DEVICE_REMINDER];
    if (multiDeviceRemindJson.is_null() || !multiDeviceRemindJson.is_array() || multiDeviceRemindJson.empty()) {
        ANS_LOGE("GetMultiDeviceReminder failed as invalid multiDeviceReminder json.");
        return;
    }

    reminderMethods_.clear();
    for (auto &singleDeviceRemindJson : multiDeviceRemindJson) {
        if (singleDeviceRemindJson.is_null() || !singleDeviceRemindJson.is_object()) {
            continue;
        }

        if (singleDeviceRemindJson.find(ReminderAffected::DEVICE_TYPE) == singleDeviceRemindJson.end() ||
            singleDeviceRemindJson[ReminderAffected::DEVICE_TYPE].is_null() ||
            !singleDeviceRemindJson[ReminderAffected::DEVICE_TYPE].is_string()) {
            continue;
        }

        if (singleDeviceRemindJson.find(REMINDER_FILTER_DEVICE) == singleDeviceRemindJson.end() ||
            singleDeviceRemindJson[REMINDER_FILTER_DEVICE].is_null() ||
            !singleDeviceRemindJson[REMINDER_FILTER_DEVICE].is_array() ||
            singleDeviceRemindJson[REMINDER_FILTER_DEVICE].empty()) {
            continue;
        }
        ParseReminderFilterDevice(singleDeviceRemindJson[REMINDER_FILTER_DEVICE],
            singleDeviceRemindJson[ReminderAffected::DEVICE_TYPE].get<string>());
    }

    if (reminderMethods_.size() <= 0) {
        ANS_LOGW("GetMultiDeviceReminder failed as Invalid reminderMethods size.");
    }
}

void SmartReminderCenter::ParseReminderFilterDevice(const nlohmann::json &root, const string &deviceType)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice;
    for (auto &reminderFilterDeviceJson : root) {
        NotificationConstant::SlotType slotType;
        if (reminderFilterDeviceJson.find(SLOT_TYPE) == reminderFilterDeviceJson.end() ||
            reminderFilterDeviceJson[SLOT_TYPE].is_null() ||
            !reminderFilterDeviceJson[SLOT_TYPE].is_string()) {
            continue;
        }

        if (reminderFilterDeviceJson.find(REMINDER_FILTER_SLOT) == reminderFilterDeviceJson.end() ||
            reminderFilterDeviceJson[REMINDER_FILTER_SLOT].is_null() ||
            !reminderFilterDeviceJson[REMINDER_FILTER_SLOT].is_array() ||
            reminderFilterDeviceJson[REMINDER_FILTER_SLOT].empty()) {
            continue;
        }

        std::string slotTypes = reminderFilterDeviceJson[SLOT_TYPE].get<std::string>();
        std::vector<std::string> slotTypeVector;
        StringUtils::Split(slotTypes, SPLIT_FLAG, slotTypeVector);

        for (std::string slotTypeStr : slotTypeVector) {
            if (!NotificationSlot::GetSlotTypeByString(slotTypeStr, slotType)) {
                continue;
            }
            ParseReminderFilterSlot(reminderFilterDeviceJson[REMINDER_FILTER_SLOT],
                to_string(static_cast<int32_t>(slotType)), reminderFilterDevice);
        }
    }
    if (reminderFilterDevice.size() > 0) {
        reminderMethods_[deviceType] = move(reminderFilterDevice);
    } else {
        ANS_LOGI("ParseReminderFilterDevice failed as Invalid reminderFilterDevice size. deviceType = %{public}s.",
            deviceType.c_str());
    }
}

void SmartReminderCenter::ParseReminderFilterSlot(
    const nlohmann::json &root,
    const string &notificationType,
    map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const
{
    vector<shared_ptr<ReminderAffected>> reminderFilterSlot;
    for (auto &reminderFilterSlotJson : root) {
        NotificationContent::Type contentType;
        bool validContentType = true;

        if (reminderFilterSlotJson.find(CONTENT_TYPE) == reminderFilterSlotJson.end() ||
            reminderFilterSlotJson[CONTENT_TYPE].is_null() ||
            !reminderFilterSlotJson[CONTENT_TYPE].is_string() ||
            !NotificationContent::GetContentTypeByString(
                reminderFilterSlotJson[CONTENT_TYPE].get<std::string>(), contentType)) {
            validContentType = false;
        }

        if (reminderFilterSlotJson.find(REMINDER_FILTER_CONTENT) == reminderFilterSlotJson.end() ||
            reminderFilterSlotJson[REMINDER_FILTER_CONTENT].is_null() ||
            !reminderFilterSlotJson[REMINDER_FILTER_CONTENT].is_array() ||
            reminderFilterSlotJson[REMINDER_FILTER_CONTENT].empty()) {
            validContentType = false;
        }

        if (validContentType) {
            string localNotificationType = notificationType;
            localNotificationType.append("#");
            localNotificationType.append(to_string(static_cast<int32_t>(contentType)));
            ParseReminderFilterContent(
                reminderFilterSlotJson[REMINDER_FILTER_CONTENT], localNotificationType, reminderFilterDevice);
            continue;
        }
        shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
        if (reminderAffected->FromJson(reminderFilterSlotJson)) {
            reminderFilterSlot.push_back(reminderAffected);
        }
    }
    if (reminderFilterSlot.size() > 0) {
        reminderFilterDevice[notificationType] = move(reminderFilterSlot);
    }
}

void SmartReminderCenter::ParseReminderFilterContent(
    const nlohmann::json &root,
    const string &notificationType,
    map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const
{
    vector<shared_ptr<ReminderAffected>> reminderFilterContent;
    for (auto &reminderFilterContentJson : root) {
        bool validTypeCode = true;
        if (reminderFilterContentJson.find(TYPE_CODE) == reminderFilterContentJson.end() ||
            reminderFilterContentJson[TYPE_CODE].is_null() ||
            !reminderFilterContentJson[TYPE_CODE].is_number()) {
            validTypeCode = false;
        }

        if (reminderFilterContentJson.find(REMINDER_FILTER_CODE) == reminderFilterContentJson.end() ||
            reminderFilterContentJson[REMINDER_FILTER_CODE].is_null() ||
            !reminderFilterContentJson[REMINDER_FILTER_CODE].is_array() ||
            reminderFilterContentJson[REMINDER_FILTER_CODE].empty()) {
            validTypeCode = false;
        }

        if (validTypeCode) {
            int32_t typeCode = reminderFilterContentJson[TYPE_CODE].get<int32_t>();
            string localNotificationType = notificationType;
            localNotificationType.append("#");
            localNotificationType.append(to_string(typeCode));
            ParseReminderFilterCode(
                reminderFilterContentJson[REMINDER_FILTER_CODE], localNotificationType, reminderFilterDevice);
            continue;
        }
        shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
        if (reminderAffected->FromJson(reminderFilterContentJson)) {
            reminderFilterContent.push_back(reminderAffected);
        }
    }
    if (reminderFilterContent.size() > 0) {
        reminderFilterDevice[notificationType] = move(reminderFilterContent);
    }
}

void SmartReminderCenter::ParseReminderFilterCode(
    const nlohmann::json &root,
    const string &notificationType,
    map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice) const
{
    vector<shared_ptr<ReminderAffected>> reminderFilterCode;
    for (auto &reminderFilterCodeJson : root) {
        shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
        if (reminderAffected->FromJson(reminderFilterCodeJson)) {
            reminderFilterCode.push_back(reminderAffected);
        }
    }
    if (reminderFilterCode.size() > 0) {
        reminderFilterDevice[notificationType] = move(reminderFilterCode);
    }
}

bool SmartReminderCenter::IsCollaborationAllowed(const sptr<NotificationRequest>& request) const
{
    if (!request->IsSystemApp()) {
        ANS_LOGD("IsSystemApp <%{public}d> allowed to collaborate.", request->IsSystemApp());
        return true;
    }
    if (request->IsNotDistributed()) {
        ANS_LOGW("IsNotDistributed <%{public}d> not allowed to collaborate", request->IsNotDistributed());
        return false;
    }
    if (request->IsForceDistributed()) {
        ANS_LOGD("IsForceDistributed <%{public}d> allowed to collaborate", request->IsForceDistributed());
        return true;
    }
    return !DelayedSingleton<NotificationConfigParse>::GetInstance()->IsInCollaborationFilter(
        request->GetOwnerBundleName(), request->GetCreatorUid());
}

void SmartReminderCenter::SetSyncDevice(const sptr<NotificationRequest> &request, set<string> syncDevices) const
{
    int32_t index = 0;
    uint32_t deviceList = 0;
    for (std::string deviceType : NotificationConstant::DEVICESTYPES) {
        if (syncDevices.count(deviceType)) {
            deviceList = deviceList | (1 << index);
        }
        index++;
    }
    std::shared_ptr<AAFwk::WantParams> extendInfo = request->GetExtendInfo();
    if (extendInfo == nullptr) {
        extendInfo = std::make_shared<AAFwk::WantParams>();
    }
    ANS_LOGW("SetSyncDevice %{public}zu, %{public}u.", syncDevices.size(), deviceList);
    extendInfo->SetParam("collaboration_device_list", AAFwk::Integer::Box(deviceList));
    request->SetExtendInfo(extendInfo);
}

void SmartReminderCenter::ReminderDecisionProcess(const sptr<NotificationRequest> &request) const
{
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();
    NotificationConstant::SlotType slotType = request->GetSlotType();

#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
    if (EXTENTION_WRAPPER->IsPrivilegeMessage(request)) {
        ANS_LOGD("Privilege message handle ReminderDecisionProcess.");
        (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = request->GetFlags();
        request->SetDeviceFlags(notificationFlagsOfDevices);
        return;
    }
#endif

    auto iter = currentReminderMethods_.find(slotType);
    if (iter != currentReminderMethods_.end()) {
        // Only config file can set reminder open now. Otherwise, change iter->second to 11111
        auto flag = std::make_shared<NotificationFlags>(iter->second->GetReminderFlags());
        (*notificationFlagsOfDevices)[NotificationConstant::CURRENT_DEVICE_TYPE] = flag;
        defaultFlag = iter->second;
    }
    if (!IsCollaborationAllowed(request)) {
        ANS_LOGW("collabration not allowed");
        request->SetDeviceFlags(notificationFlagsOfDevices);
        return;
    }

    set<string> syncDevices;
    set<string> smartDevices;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    InitValidDevices(syncDevices, smartDevices, statusMap, request);
    if (syncDevices.size() <= 1) {
        request->SetDeviceFlags(notificationFlagsOfDevices);
        return;
    }

    for (auto &reminderMethod : reminderMethods_) {
        HandleReminderMethods(
            reminderMethod.first, reminderMethod.second, request,
            syncDevices, smartDevices, defaultFlag, statusMap,
            notificationFlagsOfDevices);
    }

    SetSyncDevice(request, syncDevices);
    request->SetDeviceFlags(notificationFlagsOfDevices);
}

void SmartReminderCenter::CheckScreenOffForCollaboration(const set<string>& syncDevices,
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> &statusMap) const
{
    if (syncDevices.find(NotificationConstant::PAD_DEVICE_TYPE) == syncDevices.end() &&
        syncDevices.find(NotificationConstant::PC_DEVICE_TYPE) == syncDevices.end()) {
        return;
    }

    if (statusMap.find(NotificationConstant::CURRENT_DEVICE_TYPE) == statusMap.end()) {
        return;
    }

    auto current = statusMap[NotificationConstant::CURRENT_DEVICE_TYPE];
    if (!current.test(DistributedDeviceStatus::LOCK_FLAG)) {
        return;
    }

    Rosen::ScreenPowerState powerState = Rosen::ScreenManager::GetInstance().GetScreenPower();
    current.set(DistributedDeviceStatus::LOCK_FLAG, powerState != Rosen::ScreenPowerState::POWER_OFF);
    statusMap[NotificationConstant::CURRENT_DEVICE_TYPE] = current;
    ANS_LOGW("Check Screen Off current power %{public}d %{public}s", powerState, current.to_string().c_str());
}

void SmartReminderCenter::InitValidDevices(
    set<string> &syncDevices, set<string> &smartDevices,
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> &statusMap,
    const sptr<NotificationRequest> &request) const
{
    auto notificationControlFlags = request->GetNotificationControlFlags();
    syncDevices.insert(NotificationConstant::CURRENT_DEVICE_TYPE);
    smartDevices.insert(NotificationConstant::CURRENT_DEVICE_TYPE);
    bitset<DistributedDeviceStatus::STATUS_SIZE> status;
    GetDeviceStatusByType(NotificationConstant::CURRENT_DEVICE_TYPE, status);
    statusMap.insert(
        pair<string, bitset<DistributedDeviceStatus::STATUS_SIZE>>(NotificationConstant::CURRENT_DEVICE_TYPE, status));

    for (std::string deviceType : NotificationConstant::DEVICESTYPES) {
        bool affordConsume = false;
        NotificationSubscriberManager::GetInstance()->IsDeviceTypeAffordConsume(deviceType, request, affordConsume);
        if (!affordConsume) {
            ANS_LOGD("deviceType = %{public}s", deviceType.c_str());
            continue;
        }

        if (NotificationConstant::PC_DEVICE_TYPE == deviceType || NotificationConstant::PAD_DEVICE_TYPE == deviceType) {
#ifdef ALL_SCENARIO_COLLABORATION
            InitPcPadDevices(deviceType, syncDevices, smartDevices, statusMap, request);
#endif
            continue;
        }

        if (NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE == deviceType) {
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
            InitThirdPartyWearableDevices(syncDevices, request);
#endif
            continue;
        }
        GetDeviceStatusByType(deviceType, status);
        statusMap.insert(pair<string, bitset<DistributedDeviceStatus::STATUS_SIZE>>(deviceType, status));
        request->AdddeviceStatu(deviceType, status.bitset<DistributedDeviceStatus::STATUS_SIZE>::to_string());

        if (NotificationConstant::SlotType::LIVE_VIEW == request->GetSlotType()) {
            NotificationConstant::SWITCH_STATE liveViewEnableStatus =
                NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
            std::string queryDeviceType = deviceType;
            if (deviceType.compare(NotificationConstant::WEARABLE_DEVICE_TYPE) == 0) {
                queryDeviceType = NotificationConstant::LITEWEARABLE_DEVICE_TYPE;
            }
            NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(
                request->GetSlotType(), queryDeviceType, liveViewEnableStatus);
            if (liveViewEnableStatus != NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON &&
                liveViewEnableStatus != NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) {
                ANS_LOGI("liveView smart switch is closed, deviceType = %{public}s", deviceType.c_str());
                continue;
            }
            if (!CheckHealthWhiteList(request, deviceType)) {
                continue;
            }
            syncDevices.insert(deviceType);
            smartDevices.insert(deviceType);
            request->SetNotificationControlFlags(notificationControlFlags | CONTROL_BY_SMART_REMINDER);
        } else {
            if (NotificationConstant::SlotType::SOCIAL_COMMUNICATION != request->GetSlotType() &&
                NotificationConstant::SlotType::SERVICE_REMINDER != request->GetSlotType() &&
                NotificationConstant::SlotType::CUSTOMER_SERVICE != request->GetSlotType()) {
                ANS_LOGD("unaffect slot");
                continue;
            }
            bool distributedSwitch = GetDistributedSwitch(deviceType);
            if (!distributedSwitch) {
                ANS_LOGI("distributed switch is closed, deveiceType = %{public}s", deviceType.c_str());
                continue;
            }
            bool appSwitch = GetAppSwitch(deviceType, request->GetOwnerBundleName(), request->GetOwnerUid());
            // app-close
            if (!appSwitch) {
                ANS_LOGI("app switch is closed, deveiceType = %{public}s", deviceType.c_str());
                continue;
            }

            bool smartSwitch = GetSmartSwitch(deviceType);
            ANS_LOGI("smart switch deviceType = %{public}s status = %{public}d", deviceType.c_str(), smartSwitch);
            // app-open ,smart-open
            if (smartSwitch) {
                syncDevices.insert(deviceType);
                smartDevices.insert(deviceType);
                request->SetNotificationControlFlags(notificationControlFlags | CONTROL_BY_SMART_REMINDER);
                continue;
            }
            // app-open, smart-close
            syncDevices.insert(deviceType);
        }
    }
    CheckScreenOffForCollaboration(syncDevices, statusMap);
    string syncDevicesStr;
    string smartDevicesStr;
    for (auto it = syncDevices.begin(); it != syncDevices.end(); ++it) {
        syncDevicesStr = syncDevicesStr + *it + StringUtils::SPLIT_CHAR;
    }
    for (auto it = smartDevices.begin(); it != smartDevices.end(); ++it) {
        smartDevicesStr = smartDevicesStr + *it + StringUtils::SPLIT_CHAR;
    }
    ANS_LOGI("sync device: %{public}s", syncDevicesStr.c_str());
    ANS_LOGI("smart device: %{public}s", smartDevicesStr.c_str());
    return;
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
void SmartReminderCenter::InitThirdPartyWearableDevices(set<string> &syncDevices,
    const sptr<NotificationRequest> &request) const
{
    if (NotificationConstant::SlotType::LIVE_VIEW == request->GetSlotType()) {
        ANS_LOGD("skip liveview");
        return;
    }
    if (request->GetClassification() == NotificationConstant::ANS_VOIP) {
        ANS_LOGD("skip voip");
        return;
    }
    if (BundleManagerHelper::GetInstance()->GetBundleNameByUid(request->GetCreatorUid()).empty()) {
        ANS_LOGD("skip SA");
        return;
    }
    syncDevices.insert(NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE);
}
#endif
#ifdef ALL_SCENARIO_COLLABORATION
void SmartReminderCenter::InitPcPadDevices(const string &deviceType,
    set<string> &syncDevices, set<string> &smartDevices,
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> &statusMap,
    const sptr<NotificationRequest> &request) const
{
    if (request->GetOwnerBundleName().empty()) {
        ANS_LOGI("PC/PAD init, bundleName null");
        return;
    }
    if (request->GetClassification() == NotificationConstant::ANS_VOIP) {
        ANS_LOGI("PC/PAD init, pc/pad not support voip");
        return;
    }
    if (NotificationConstant::SlotType::LIVE_VIEW == request->GetSlotType() &&
        NotificationConstant::PC_DEVICE_TYPE == deviceType) {
        ANS_LOGI("PC/PAD init, pc not support liveView");
        return;
    }
    // used device
    DeviceStatus deviceStatus = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->
        GetMultiDeviceStatus(deviceType, STATUS_UNLOCKED_USED_FLAG);
    if (deviceStatus.deviceType.empty()) {
        ANS_LOGI("PC/PAD init, not get any used device, type = %{public}s", deviceType.c_str());
        return;
    }
    if (!IsSmartRemindBySwitch(deviceType, deviceStatus, request)) {
        return;
    }
    string deviceId = deviceStatus.deviceId;
    std::string bundleName = request->GetOwnerBundleName();
    int32_t userId = request->GetOwnerUserId();
    if (userId == SUBSCRIBE_USER_INIT) {
        OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    }
    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::ApplicationInfo appInfo;
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
    if (bundleManager != nullptr) {
        // system app
        if (bundleManager->CheckSystemApp(bundleName, userId)) {
            ANS_LOGI("PC/PAD init, application is systemApp, type = %{public}s, bundleName = %{public}s",
                deviceType.c_str(), bundleName.c_str());
            return;
        }
        int32_t flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
        if (!bundleManager->GetBundleInfoV9(bundleName, flags, bundleInfo, userId)) {
            ANS_LOGE("PC/PAD init, GetApplicationInfo error, type = %{public}s, bundleName = %{public}s",
                deviceType.c_str(), bundleName.c_str());
            return;
        }
        appInfo = bundleInfo.applicationInfo;
        if (bundleManager->GetBundleResourceInfo(bundleName, bundleResourceInfo, appInfo.appIndex) != ERR_OK) {
            ANS_LOGE("PC/PAD init, GetBundleResourceInfo error, type = %{public}s, bundleName = %{public}s",
                deviceType.c_str(), bundleName.c_str());
            return;
        }
        // installed bundle
        if (DistributedDeviceDataService::GetInstance().CheckDeviceBundleExist(
            deviceType, deviceId, bundleName, bundleResourceInfo.label)) {
            ANS_LOGI("PC/PAD init, application has installed, type = %{public}s, bundleName = %{public}s",
                deviceType.c_str(), bundleName.c_str());
            return;
        }
    } else {
        ANS_LOGE("get bundleManager fail");
        return;
    }
    FillRequestExtendInfo(deviceType, deviceStatus, request, appInfo, bundleResourceInfo);
    statusMap.insert(pair<string, bitset<DistributedDeviceStatus::STATUS_SIZE>>(
        deviceType, bitset<DistributedDeviceStatus::STATUS_SIZE>(deviceStatus.status)));
    syncDevices.insert(deviceType);
    smartDevices.insert(deviceType);
    return;
}

bool SmartReminderCenter::IsSmartRemindBySwitch(
    const string &deviceType, const DeviceStatus &deviceStatus, const sptr<NotificationRequest> &request) const
{
    string deviceId = deviceStatus.deviceId;
    if (NotificationConstant::SlotType::LIVE_VIEW == request->GetSlotType()) {
        if (!DistributedDeviceDataService::GetInstance().GetDeviceLiveViewEnable(deviceType, deviceId)) {
            ANS_LOGI("PC/PAD init, liveView switch is closed , type = %{public}s", deviceType.c_str());
            return false;
        }
        NotificationConstant::SWITCH_STATE liveViewEnableStatus =
                NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF;
        // master use current to be switch key for expand later
        ErrCode result = NotificationPreferences::GetInstance()->IsDistributedEnabledBySlot(
            request->GetSlotType(), NotificationConstant::CURRENT_DEVICE_TYPE, liveViewEnableStatus);
        if ((liveViewEnableStatus != NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON &&
            liveViewEnableStatus != NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON) || result != ERR_OK) {
            ANS_LOGI("PC/PAD init, current liveView switch is closed");
            return false;
        }
    } else {
        if (!DistributedDeviceDataService::GetInstance().GetDeviceNotificationEnable(deviceType, deviceId)) {
            ANS_LOGI("PC/PAD init, notification switch is closed , type = %{public}s", deviceType.c_str());
            return false;
        }
        NotificationConstant::SWITCH_STATE enableStatus;
        // master use current to be switch key for expand later
        ErrCode result = NotificationPreferences::GetInstance()->IsDistributedEnabled(
            NotificationConstant::CURRENT_DEVICE_TYPE, enableStatus);
        if ((enableStatus != NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON &&
            enableStatus != NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) || result != ERR_OK) {
            ANS_LOGI("PC/PAD init, current distributed switch is closed");
            return false;
        }
    }
    return true;
}
#endif

void SmartReminderCenter::FillRequestExtendInfo(const string &deviceType, DeviceStatus &deviceStatus,
    const sptr<NotificationRequest> &request,
    const AppExecFwk::ApplicationInfo &appInfo,
    const AppExecFwk::BundleResourceInfo &bundleResourceInfo) const
{
    std::string bundleName = request->GetOwnerBundleName();
    int32_t userId = request->GetOwnerUserId();
    if (userId == SUBSCRIBE_USER_INIT) {
        OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    }
    int32_t index = BundleManagerHelper::GetInstance()->GetAppIndexByUid(request->GetOwnerUid());
    std::shared_ptr<AAFwk::WantParams> extendInfo = request->GetExtendInfo();
    if (extendInfo == nullptr) {
        extendInfo = std::make_shared<AAFwk::WantParams>();
    }
    extendInfo->SetParam(EXTEND_INFO_PRE + "_" + EXTEND_INFO_APP_NAME, AAFwk::String::Box(appInfo.name));
    extendInfo->SetParam(EXTEND_INFO_PRE + "_" + EXTEND_INFO_APP_LABEL,
        AAFwk::String::Box(bundleResourceInfo.label));
    extendInfo->SetParam(EXTEND_INFO_PRE + "_" + EXTEND_INFO_APP_INDEX,
        AAFwk::Integer::Box(index));
    extendInfo->SetParam(EXTEND_INFO_PRE + "_" + EXTEND_INFO_APP_UID,
        AAFwk::Integer::Box(request->GetOwnerUid()));

    extendInfo->SetParam(EXTEND_INFO_PRE + "_" + EXTEND_INFO_DEVICE_ID + "_" + deviceType,
        AAFwk::String::Box(deviceStatus.deviceId));
    extendInfo->SetParam(EXTEND_INFO_PRE + "_" + EXTEND_INFO_USER_ID +  "_" + deviceType,
        AAFwk::Integer::Box(deviceStatus.userId));
    request->SetExtendInfo(extendInfo);
    ANS_LOGI("FillRequestExtendInfo result: %{public}s %{public}s %{public}d %{public}s %{public}d %{public}d",
        appInfo.name.c_str(), bundleResourceInfo.label.c_str(), index,
        StringAnonymous(deviceStatus.deviceId).c_str(), deviceStatus.userId, request->GetOwnerUid());
}

void SmartReminderCenter::HandleReminderMethods(
    const string &deviceType,
    const map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice,
    const sptr<NotificationRequest> &request,
    set<string> &syncDevices,
    set<string> &smartDevices,
    shared_ptr<NotificationFlags> defaultFlag,
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> &statusMap,
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices) const
{
    std::string classfication = request->GetClassification();

    if (syncDevices.find(deviceType) == syncDevices.end()) {
        return;
    }

    if (request->GetClassification() == NotificationConstant::ANS_VOIP) {
        ANS_LOGI("VOIP CALL");
        if (deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) == 0) {
            return;
        }
    }

    auto flag = std::make_shared<NotificationFlags>(defaultFlag->GetReminderFlags());
    if (smartDevices.find(deviceType) == smartDevices.end()) {
        (*notificationFlagsOfDevices)[deviceType] = flag;
        ANS_LOGI("default remindFlags, deviceType = %{public}s ,  remindFlags = %{public}d",
            deviceType.c_str(), defaultFlag->GetReminderFlags());
        return;
    }

    if (deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) == 0 &&
       smartDevices.size() <= 1) {
        (*notificationFlagsOfDevices)[deviceType] = flag;
        ANS_LOGI("default remindFlags, deviceType = %{public}s ,  remindFlags = %{public}d",
            deviceType.c_str(), defaultFlag->GetReminderFlags());
        return;
    }

    vector<shared_ptr<ReminderAffected>> reminderAffecteds;
    GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);
    if (reminderAffecteds.size() <= 0) {
        ANS_LOGI("not set any rule for deviceType %{public}s", deviceType.c_str());
        return;
    }

    auto iter = statusMap.find(deviceType);
    if (iter == statusMap.end()) {
        ANS_LOGE("get device status failed. deviceType = %{public}s", deviceType.c_str());
        return;
    }
    bitset<DistributedDeviceStatus::STATUS_SIZE> bitStatus = iter->second;

    for (auto &reminderAffected : reminderAffecteds) {
        if (!CompareStatus(reminderAffected->status_, bitStatus)) {
            continue;
        }
        if (reminderAffected->affectedBy_.size() <= 0) {
            auto flag = std::make_shared<NotificationFlags>(reminderAffected->reminderFlags_->GetReminderFlags());
            (*notificationFlagsOfDevices)[deviceType] = flag;
            ANS_LOGI("smart rule matched, deviceType = %{public}s ,  remindFlags = %{public}d",
                deviceType.c_str(), reminderAffected->reminderFlags_->GetReminderFlags());
            return;
        } else {
            bool matched =
            HandleAffectedReminder(deviceType, reminderAffected, smartDevices, statusMap, notificationFlagsOfDevices);
            if (matched) {
                ANS_LOGI("smart rule matched, deviceType = %{public}s ,  remindFlags = %{public}d",
                    deviceType.c_str(), reminderAffected->reminderFlags_->GetReminderFlags());
                return;
            }
        }
    }
    ANS_LOGI("not match any rule. deviceType = %{public}s", deviceType.c_str());
}

bool SmartReminderCenter::IsNeedSynergy(const NotificationConstant::SlotType &slotType,
    const string &deviceType, const string &ownerBundleName, int32_t ownerUid) const
{
    std::string device = deviceType;
    if (deviceType.compare(NotificationConstant::WEARABLE_DEVICE_TYPE) == 0) {
        device = NotificationConstant::LITEWEARABLE_DEVICE_TYPE;
    }

    bool isEnable = true;
    if (NotificationPreferences::GetInstance()->IsSmartReminderEnabled(device, isEnable) != ERR_OK || !isEnable) {
        ANS_LOGI("switch-status, smartReminderEnable closed. device = %{public}s", device.c_str());
        return false;
    }

    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption(ownerBundleName, ownerUid);
    if (NotificationPreferences::GetInstance()->IsDistributedEnabledByBundle(
        bundleOption, device, isEnable) != ERR_OK || !isEnable) {
        ANS_LOGI("switch-status, app switch closed. device = %{public}s", device.c_str());
        return false;
    }
    return true;
}

bool SmartReminderCenter::GetAppSwitch(const string &deviceType,
    const string &ownerBundleName, int32_t ownerUid) const
{
    std::string device = deviceType;
    if (deviceType.compare(NotificationConstant::WEARABLE_DEVICE_TYPE) == 0) {
        device = NotificationConstant::LITEWEARABLE_DEVICE_TYPE;
    }

    bool isEnable = true;

    sptr<NotificationBundleOption> bundleOption =
        new (std::nothrow) NotificationBundleOption(ownerBundleName, ownerUid);
    if (NotificationPreferences::GetInstance()->IsDistributedEnabledByBundle(
        bundleOption, device, isEnable) != ERR_OK || !isEnable) {
        return false;
    }
    return true;
}

bool SmartReminderCenter::GetSmartSwitch(const string &deviceType) const
{
    std::string device = deviceType;
    if (deviceType.compare(NotificationConstant::WEARABLE_DEVICE_TYPE) == 0) {
        device = NotificationConstant::LITEWEARABLE_DEVICE_TYPE;
    }

    bool isEnable = true;
    if (NotificationPreferences::GetInstance()->IsSmartReminderEnabled(device, isEnable) != ERR_OK || !isEnable) {
        return false;
    }
    return true;
}

bool SmartReminderCenter::GetDistributedSwitch(const string &deviceType) const
{
    std::string device = deviceType;

    if (deviceType.compare(NotificationConstant::WEARABLE_DEVICE_TYPE) != 0 &&
        deviceType.compare(NotificationConstant::LITEWEARABLE_DEVICE_TYPE) != 0) {
            return true;
        }
    NotificationConstant::SWITCH_STATE enableStatus;
    ErrCode errResult = NotificationPreferences::GetInstance()->IsDistributedEnabled(
        NotificationConstant::LITEWEARABLE_DEVICE_TYPE, enableStatus);
    if (errResult != ERR_OK) {
        ANS_LOGE("query distributed switch fail");
        return false;
    }
    if (enableStatus == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON ||
        enableStatus == NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_ON) {
        return true;
    }
    return false;
}

bool SmartReminderCenter::HandleAffectedReminder(
    const string &deviceType,
    const shared_ptr<ReminderAffected> &reminderAffected,
    const set<string> &smartDevices,
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> &statusMap,
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices) const
{
    bool ret = true;
    for (auto &affectedBy : reminderAffected->affectedBy_) {
        if (smartDevices.find(affectedBy.first) == smartDevices.end()) {
            ret = false;
            break;
        }

        auto iter =  statusMap.find(affectedBy.first);
        if (iter == statusMap.end()) {
            ANS_LOGE("get device status failed. deviceType = %{public}s", deviceType.c_str());
            ret = false;
            break;
        }
        bitset<DistributedDeviceStatus::STATUS_SIZE> bitStatus = iter->second;

        if (!CompareStatus(affectedBy.second, bitStatus)) {
            ret = false;
            break;
        }
    }
    if (ret) {
        auto flag = std::make_shared<NotificationFlags>(reminderAffected->reminderFlags_->GetReminderFlags());
        (*notificationFlagsOfDevices)[deviceType] = flag;
    }
    return ret;
}

bool SmartReminderCenter::CompareStatus(
    const string &status, const bitset<DistributedDeviceStatus::STATUS_SIZE> &bitStatus) const
{
    if (status.size() <= 0) {
        return true;
    }
    std::vector<std::string> statusVector;
    StringUtils::Split(status, StringUtils::SPLIT_CHAR, statusVector);
    for (std::string strStatus : statusVector) {
        // bitset.to_string() and config is reverse, bit[0] is behind
        string localStatus = strStatus;
        reverse(localStatus.begin(), localStatus.end());
        for (int32_t seq = 0; seq < DistributedDeviceStatus::STATUS_SIZE; seq++) {
            if (localStatus[seq] != ReminderAffected::STATUS_DEFAULT && bitStatus[seq] != localStatus[seq] - '0') {
                break;
            }
            if (seq == DistributedDeviceStatus::STATUS_SIZE -1) {
                return true;
            }
        }
    }
    return false;
}

__attribute__((no_sanitize("cfi"))) void SmartReminderCenter::GetReminderAffecteds(
    const map<string, vector<shared_ptr<ReminderAffected>>> &reminderFilterDevice,
    const sptr<NotificationRequest> &request,
    vector<shared_ptr<ReminderAffected>> &reminderAffecteds) const
{
    string strSlotType = to_string(static_cast<int32_t>(request->GetSlotType()));
    string contentTypeCombination = strSlotType;
    contentTypeCombination.append("#");
    if (request->GetContent() != nullptr) {
        contentTypeCombination.append(to_string(static_cast<int32_t>(request->GetContent()->GetContentType())));
    }
    string typeCodeCombination = contentTypeCombination;
    typeCodeCombination.append("#");
    if (request->GetContent() != nullptr && request->GetContent()->GetNotificationContent() != nullptr) {
        NotificationLocalLiveViewContent *localLiveView =
            static_cast<NotificationLocalLiveViewContent *>(&(*(request->GetContent()->GetNotificationContent())));
        typeCodeCombination.append(to_string(localLiveView->GetType()));
    }
    auto iter = reminderFilterDevice.find(typeCodeCombination);
    if (iter != reminderFilterDevice.end()) {
        reminderAffecteds = iter->second;
        return;
    }
    iter = reminderFilterDevice.find(contentTypeCombination);
    if (iter != reminderFilterDevice.end()) {
        reminderAffecteds = iter->second;
        return;
    }
    iter = reminderFilterDevice.find(strSlotType);
    if (iter != reminderFilterDevice.end()) {
        reminderAffecteds = iter->second;
        return;
    }
    ANS_LOGD("GetReminderAffecteds fail as wrong notification_config.json possibly. TypeCombination = %{public}s.",
        typeCodeCombination.c_str());
}

void SmartReminderCenter::GetDeviceStatusByType(
    const string &deviceType, bitset<DistributedDeviceStatus::STATUS_SIZE> &bitStatus) const
{
    u_int32_t status = DelayedSingleton<DistributedDeviceStatus>::GetInstance()->GetDeviceStatus(deviceType);
    bitStatus = bitset<DistributedDeviceStatus::STATUS_SIZE>(status);
    Rosen::ScreenPowerState powerState = Rosen::ScreenPowerState::INVALID_STATE;
    if (deviceType.compare(NotificationConstant::CURRENT_DEVICE_TYPE) == 0) {
        bool screenLocked = true;
        screenLocked = ScreenLock::ScreenLockManager::GetInstance()->IsScreenLocked();
        bitStatus.set(DistributedDeviceStatus::LOCK_FLAG, !screenLocked);
        powerState = Rosen::ScreenManager::GetInstance().GetScreenPower();
    }
    ANS_LOGI("deviceType: %{public}s, power %{public}d bitStatus: %{public}s", deviceType.c_str(), powerState,
        bitStatus.to_string().c_str());
}

bool SmartReminderCenter::CheckHealthWhiteList(const sptr<NotificationRequest> &request,
    const string &deviceType) const
{
    if (NotificationConstant::SlotType::LIVE_VIEW != request->GetSlotType()) {
        return true;
    }

    if (deviceType.compare(NotificationConstant::WEARABLE_DEVICE_TYPE) != 0 &&
        deviceType.compare(NotificationConstant::LITEWEARABLE_DEVICE_TYPE) != 0) {
            return true;
    }
    return DelayedSingleton<HealthWhiteListUtil>::GetInstance()->CheckInLiveViewList(request->GetOwnerBundleName());
}
}  // namespace Notification
}  // namespace OHOS
#endif
