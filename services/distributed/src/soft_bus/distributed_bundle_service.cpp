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

#include "distributed_bundle_service.h"

#include "bundle_icon_box.h"
#include "analytics_util.h"
#include "ans_image_util.h"
#include "distributed_client.h"
#include "distributed_data_define.h"
#include "notification_helper.h"
#include "bundle_resource_helper.h"
#include "distributed_device_service.h"
#include "distributed_preference.h"
#include "distributed_subscribe_service.h"
#include "distributed_send_adapter.h"
#include "notification_distributed_bundle.h"
#include "application_change_box.h"

namespace OHOS {
namespace Notification {

DistributedBundleService& DistributedBundleService::GetInstance()
{
    static DistributedBundleService distributedBundleService;
    return distributedBundleService;
}

#ifdef DISTRIBUTED_FEATURE_MASTER
// soft bus max buffer length is 4*1024*1024.
constexpr int32_t MAX_BUFFER_LENGTH = 7 * 512 * 1024;

void DistributedBundleService::SendDistributedBundleInfo(const DistributedDeviceInfo device)
{
    if (!device.IsPadOrPc()) {
        return;
    }
    std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
    std::vector<NotificationDistributedBundle> bundles;
    std::vector<NotificationDistributedBundle> sendBundles;
    NotificationHelper::GetLocalDistributedBundleList(deviceType, bundles);
    std::set<int32_t> launcherBundles;
    int32_t userId = DistributedSubscribeService::GetCurrentActiveUserId();
    DelayedSingleton<BundleResourceHelper>::GetInstance()->GetAllLauncherAbility(userId, launcherBundles);
    for (auto& bundle : bundles) {
        if (!launcherBundles.count(bundle.GetBundleUid())) {
            ANS_LOGI("Dans not launcher %{public}d %{public}s.", bundle.GetBundleUid(), bundle.GetBundleName().c_str());
            continue;
        }
        std::shared_ptr<ApplicationChangeBox> applicationChange = std::make_shared<ApplicationChangeBox>();
        applicationChange->SetApplicationSyncType(DistributedBundleChangeType::MASTER_BUNDLE_ADD);
        if (!GetApplicationResource(bundle)) {
            continue;
        }
        ANS_LOGE("Dans send bundle %{public}d %{public}s.", bundle.GetBundleUid(), bundle.GetBundleName().c_str());
        std::vector<NotificationDistributedBundle> tmpBundles = sendBundles;
        sendBundles.push_back(bundle);
        applicationChange->SetApplicationChangeList(sendBundles);
        if (applicationChange->GetByteLength() < MAX_BUFFER_LENGTH &&
            sendBundles.size() <= ApplicationChangeBox::MAX_LIST_NUM) {
            continue;
        }
        // single application buffer is over size.
        if (tmpBundles.empty()) {
            ANS_LOGW("Dans send over size %{public}s.", bundle.GetBundleName().c_str());
            sendBundles.clear();
            continue;
        }
        // send application info to peer.
        SendDistributedBundleChange(tmpBundles, DistributedBundleChangeType::MASTER_BUNDLE_ADD);
        sendBundles.clear();
        sendBundles.push_back(bundle);
    }
    if (!sendBundles.empty()) {
        SendDistributedBundleChange(sendBundles, DistributedBundleChangeType::MASTER_BUNDLE_ADD);
    }
    SendDistributedBundleChange({}, DistributedBundleChangeType::INIT_DEVICE_CONNECT);
}

void DistributedBundleService::SendDistributedBundleChange(
    const std::vector<NotificationDistributedBundle>& applicationList, DistributedBundleChangeType type)
{
    std::shared_ptr<ApplicationChangeBox> applicationChange = std::make_shared<ApplicationChangeBox>();
    applicationChange->SetApplicationSyncType(static_cast<int32_t>(type));
    applicationChange->SetApplicationChangeList(applicationList);
    if (!applicationChange->Serialize()) {
        ANS_LOGW("Dans application serialize failed.");
        return;
    }

    ANS_LOGI("Dans send change %{public}zu %{public}d.", applicationList.size(), static_cast<int32_t>(type));
    auto peerDevices = DistributedDeviceService::GetInstance().GetDeviceList();
    for (auto& device : peerDevices) {
        if (device.second.peerState_ != DeviceState::STATE_ONLINE ||
            !(device.second.abilityId_ & DistributedAbilityType::APPLICATION_SWITCH)) {
            ANS_LOGI("Dans not send %{public}d %{public}s %{public}d.", device.second.peerState_,
                StringAnonymous(device.second.deviceId_).c_str(), device.second.abilityId_);
            continue;
        }
        // send to pc/pad
        if (device.second.IsPadOrPc()) {
            std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(applicationChange, device.second,
                TransDataType::DATA_TYPE_BYTES, MODIFY_ERROR_EVENT_CODE);
            DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
            ANS_LOGI("Dans send change %{public}s %{public}d.", StringAnonymous(device.second.deviceId_).c_str(),
                device.second.deviceType_);
        }
    }
}

bool DistributedBundleService::GetApplicationResource(NotificationDistributedBundle& info)
{
    std::string bundleName = info.GetBundleName();
    if (bundleName.empty()) {
        ANS_LOGW("Dans get empty resource.");
        return false;
    }
    AppExecFwk::BundleResourceInfo resourceInfo;
    if (DelayedSingleton<BundleResourceHelper>::GetInstance()->GetBundleInfo(bundleName, resourceInfo)
        != ERR_OK) {
        ANS_LOGW("Dans get bundle failed %{public}s.", bundleName.c_str());
        return false;
    }
    info.SetBundleLabel(resourceInfo.label);
    info.SetBundleIcon(AnsImageUtil::CreatePixelMapByString(resourceInfo.icon));

    int32_t index = DelayedSingleton<BundleResourceHelper>::GetInstance()->GetAppIndexByUid(info.GetBundleUid());
    info.SetAppIndex(index);
    bool isAnco = false;
    if (!DelayedSingleton<BundleResourceHelper>::GetInstance()->IsAncoApp(bundleName, info.GetBundleUid(), isAnco)) {
        ANS_LOGW("Dans get bundle anco %{public}s.", bundleName.c_str());
        return false;
    }

    info.SetAncoBundle(isAnco);
    return true;
}

void DistributedBundleService::HandleApplicationEnableChange(
    const std::shared_ptr<NotificationApplicationChangeInfo>& applicationChangeInfo,
    NotificationDistributedBundle distributedBundle, DistributedBundleChangeType changeType)
{
    // for application switch is off.
    if (!applicationChangeInfo->GetEnable()) {
        if (changeType == DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE) {
            distributedBundle.SetNotificationEnable(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
        }
        if (changeType == DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE) {
            distributedBundle.SetLiveViewEnable(NotificationConstant::SWITCH_STATE::SYSTEM_DEFAULT_OFF);
        }
        ANS_LOGI("Dans handle application change %{public}s.", distributedBundle.Dump().c_str());
        SendDistributedBundleChange({ distributedBundle }, changeType);
        return;
    }

    // for application switch is on.
    if (!GetApplicationResource(distributedBundle)) {
        return;
    }
    auto peerDevices = DistributedDeviceService::GetInstance().GetDeviceList();
    for (auto& device : peerDevices) {
        if (device.second.peerState_ != DeviceState::STATE_ONLINE || !device.second.IsPadOrPc() ||
            !(device.second.abilityId_ & DistributedAbilityType::APPLICATION_SWITCH)) {
            ANS_LOGI("Dans application not send %{public}d %{public}s %{public}d.", device.second.peerState_,
                StringAnonymous(device.second.deviceId_).c_str(), device.second.abilityId_);
            continue;
        }
        int32_t enabled;
        bool notification = (changeType == DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE);
        NotificationBundleOption bundleOption =
            NotificationBundleOption(distributedBundle.GetBundleName(), distributedBundle.GetBundleUid());
        std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.second.deviceType_);
        // when application notification or live view switch is on, need send collaboration switch to peer.
        auto result = NotificationHelper::IsDistributedEnabledByBundle(bundleOption, deviceType, notification, enabled);
        if (result == ERR_OK) {
            if (notification) {
                distributedBundle.SetNotificationEnable(static_cast<NotificationConstant::SWITCH_STATE>(enabled));
            } else {
                distributedBundle.SetLiveViewEnable(static_cast<NotificationConstant::SWITCH_STATE>(enabled));
            }
            std::shared_ptr<ApplicationChangeBox> applicationChange = std::make_shared<ApplicationChangeBox>();
            applicationChange->SetApplicationSyncType(static_cast<int32_t>(changeType));
            applicationChange->SetApplicationChangeList({ distributedBundle });
            if (!applicationChange->Serialize()) {
                ANS_LOGW("Dans application serialize failed.");
                return;
            }

            std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(applicationChange,
                device.second, TransDataType::DATA_TYPE_BYTES, MODIFY_ERROR_EVENT_CODE);
            DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
            ANS_LOGI("Dans send change %{public}d %{public}s %{public}d.", device.second.deviceType_,
                StringAnonymous(device.second.deviceId_).c_str(), enabled);
        }
    }
}

void DistributedBundleService::HandleLocalApplicationChanged(
    const std::shared_ptr<NotificationApplicationChangeInfo>& applicationChangeInfo)
{
    auto bundle = applicationChangeInfo->GetBundle();
    if (bundle == nullptr || bundle->GetBundleName().empty()) {
        ANS_LOGW("Dans handle application remove failed.");
        return;
    }
    NotificationDistributedBundle distributedBundle;
    distributedBundle.SetBundleUid(bundle->GetUid());
    distributedBundle.SetBundleName(bundle->GetBundleName());
    auto changeType = applicationChangeInfo->GetChangeType();
    switch (changeType) {
        case DistributedBundleChangeType::MASTER_BUNDLE_REMOVE:
            SendDistributedBundleChange({ distributedBundle }, changeType);
            break;
        case DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE:
        case DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE:
            HandleApplicationEnableChange(applicationChangeInfo, distributedBundle, changeType);
            break;
        default:
            ANS_LOGW("Handle change invalid type %{public}d.", static_cast<int32_t>(changeType));
            break;
    }
}

void DistributedBundleService::SetDeviceBundleList(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t operatorType = 0;
    std::string deviceId;
    BundleIconBox iconBox = BundleIconBox(boxMessage);
    if (!iconBox.GetLocalDeviceId(deviceId)) {
        ANS_LOGW("Dans bundle get deviceid failed.");
        return;
    }

    DistributedDeviceInfo device;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfo(deviceId, device)) {
        ANS_LOGW("Dans bundle get device info failed %{public}s.", StringAnonymous(deviceId).c_str());
        return;
    }

    if (!iconBox.GetIconSyncType(operatorType)) {
        ANS_LOGI("Dans handle bundle icon sync failed.");
        return;
    }

    std::vector<std::string> labelList;
    std::vector<std::string> bundleList;
    if (!iconBox.GetBundlesInfo(bundleList, labelList)) {
        ANS_LOGI("Dans handle bundle list failed.");
        return;
    }

    std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
    if (deviceType.empty()) {
        ANS_LOGW("Dans handle bundle invalid %{public}s %{public}u.", StringAnonymous(deviceId).c_str(),
            device.deviceType_);
        return;
    }
    auto ret = NotificationHelper::SetTargetDeviceBundleList(deviceType, device.udid_, operatorType,
        bundleList, labelList);
    ANS_LOGI("SetDeviceBundleList %{public}s %{public}s %{public}d %{public}zu %{public}d", deviceType.c_str(),
        StringAnonymous(deviceId).c_str(), operatorType, bundleList.size(), ret);
}

void DistributedBundleService::HandleRemoteApplicationChanged(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t changeType;
    ApplicationChangeBox application = ApplicationChangeBox(boxMessage);
    if (!application.GetApplicationSyncType(changeType)) {
        ANS_LOGW("Dans get change type failed.");
        return;
    }

    if (changeType != static_cast<int32_t>(DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE) &&
        changeType != static_cast<int32_t>(DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE)) {
        ANS_LOGI("Handle remote change invalid %{public}d.", changeType);
        return;
    }

    std::string deviceId;
    if (!application.GetLocalDeviceId(deviceId)) {
        ANS_LOGW("Dans get deviceId failed.");
        return;
    }

    DistributedDeviceInfo device;
    if (!DistributedDeviceService::GetInstance().GetDeviceInfo(deviceId, device)) {
        return;
    }
    bool isNotification = true;
    if (changeType == DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE) {
        isNotification = false;
    }
    std::string deviceType = DistributedDeviceService::DeviceTypeToTypeString(device.deviceType_);
    std::vector<NotificationDistributedBundle> applicationList;
    application.GetApplicationChangeList(applicationList);
    ANS_LOGI("Handle remote change %{public}d %{public}zu.", changeType, applicationList.size());
    for (auto application: applicationList) {
        bool enable = (application.GetNotificationEnable() == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        if (!isNotification) {
            bool enable = (application.GetLiveViewEnable() == NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
        }
        NotificationBundleOption bundleOption = NotificationBundleOption(application.GetBundleName(),
            application.GetBundleUid());
        auto result = NotificationHelper::SetDistributedEnabledByBundle(bundleOption, deviceType, enable,
            isNotification);
        ANS_LOGI("Handle remote change %{public}d, %{public}s.", result, application.Dump().c_str());
    }
}

#else

void DistributedBundleService::SendDistributedBundleChange(
    const std::vector<NotificationDistributedBundle>& applicationList, DistributedBundleChangeType type)
{
    auto peerDevices = DistributedDeviceService::GetInstance().GetDeviceList();
    for (auto& device : peerDevices) {
        if (device.second.peerState_ != DeviceState::STATE_ONLINE ||
            !(device.second.abilityId_ & DistributedAbilityType::APPLICATION_SWITCH)) {
            ANS_LOGI("Dans not send %{public}d %{public}s %{public}d.", device.second.peerState_,
                StringAnonymous(device.second.deviceId_).c_str(), device.second.abilityId_);
            continue;
        }

        std::shared_ptr<ApplicationChangeBox> applicationChange = std::make_shared<ApplicationChangeBox>();
        applicationChange->SetLocalDeviceId(device.second.deviceId_);
        applicationChange->SetApplicationSyncType(static_cast<int32_t>(type));
        applicationChange->SetApplicationChangeList(applicationList);
        if (!applicationChange->Serialize()) {
            ANS_LOGW("Dans application serialize failed.");
            return;
        }

        // send to phone
        if (device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
            std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(applicationChange, device.second,
                TransDataType::DATA_TYPE_MESSAGE, MODIFY_ERROR_EVENT_CODE);
            DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
            ANS_LOGI("Dans send change %{public}s %{public}d.", StringAnonymous(device.second.deviceId_).c_str(),
                device.second.deviceType_);
        }
    }
}

void DistributedBundleService::HandleLocalApplicationChanged(
    const std::shared_ptr<NotificationApplicationChangeInfo>& applicationChangeInfo)
{
    auto bundle = applicationChangeInfo->GetBundle();
    if (bundle == nullptr || bundle->GetBundleName().empty()) {
        ANS_LOGW("Dans handle application remove failed.");
        return;
    }
    NotificationDistributedBundle distributedBundle;
    distributedBundle.SetBundleUid(bundle->GetUid());
    distributedBundle.SetBundleName(bundle->GetBundleName());
    auto enble = applicationChangeInfo->GetEnable() ? NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON :
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF;
    auto changeType = applicationChangeInfo->GetChangeType();
    if (changeType == DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE) {
        distributedBundle.SetNotificationEnable(enble);
    }
    if (changeType == DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE) {
        distributedBundle.SetLiveViewEnable(enble);
    }
    switch (changeType) {
        case DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE:
        case DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE:
            SendDistributedBundleChange({ distributedBundle }, changeType);
            break;
        default:
            ANS_LOGW("Handle change invalid type %{public}d.", static_cast<int32_t>(changeType));
            break;
    }
}

void DistributedBundleService::SyncInstalledBundles(const DistributedDeviceInfo& peerDevice, bool isForce)
{
    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    if (!DistributedDeviceService::GetInstance().IsSyncInstalledBundle(peerDevice.deviceId_, isForce)) {
        return;
    }

    std::vector<std::pair<std::string, std::string>> bundlesName;
    int32_t userId = DistributedSubscribeService::GetCurrentActiveUserId();
    int32_t result = DelayedSingleton<BundleResourceHelper>::GetInstance()->GetAllInstalledBundles(
        bundlesName, userId);
    if (result != ERR_OK) {
        ANS_LOGW("Dans get bundls failed.");
        return;
    }

    std::vector<std::pair<std::string, std::string>> bundles;
    for (auto& bundle : bundlesName) {
        bundles.push_back(bundle);
        if (bundles.size() >= BundleIconBox::MAX_BUNDLE_NUM) {
            SendInstalledBundles(peerDevice, localDevice.deviceId_, bundles,
                BundleListOperationType::ADD_BUNDLES);
            bundles.clear();
        }
    }

    if (!bundles.empty()) {
        SendInstalledBundles(peerDevice, localDevice.deviceId_, bundles, BundleListOperationType::ADD_BUNDLES);
    }
    DistributedDeviceService::GetInstance().SetDeviceSyncData(peerDevice.deviceId_,
        DistributedDeviceService::SYNC_INSTALLED_BUNDLE, true);
}

void DistributedBundleService::SendInstalledBundles(const DistributedDeviceInfo& peerDevice,
    const std::string& localDeviceId, const std::vector<std::pair<std::string, std::string>> & bundles, int32_t type)
{
    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    iconBox->SetMessageType(INSTALLED_BUNDLE_SYNC);
    iconBox->SetLocalDeviceId(localDeviceId);
    iconBox->SetIconSyncType(type);
    iconBox->SetBundlesInfo(bundles);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans SendInstalledBundles serialize failed.");
        return;
    }

    std::shared_ptr<PackageInfo> packageInfo = std::make_shared<PackageInfo>(iconBox, peerDevice,
        TransDataType::DATA_TYPE_MESSAGE, MODIFY_ERROR_EVENT_CODE);
    DistributedSendAdapter::GetInstance().SendPackage(packageInfo);
    ANS_LOGI("Dans send bundle %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_);
}

void DistributedBundleService::HandleRemoteApplicationChanged(const std::shared_ptr<TlvBox>& boxMessage)
{
    int32_t changeType;
    ApplicationChangeBox application = ApplicationChangeBox(boxMessage);
    if (!application.GetApplicationSyncType(changeType)) {
        ANS_LOGW("Dans get change type failed.");
        return;
    }

    if (changeType != static_cast<int32_t>(DistributedBundleChangeType::INIT_DEVICE_CONNECT) &&
        changeType != static_cast<int32_t>(DistributedBundleChangeType::MASTER_BUNDLE_ADD) &&
        changeType != static_cast<int32_t>(DistributedBundleChangeType::MASTER_BUNDLE_REMOVE) &&
        changeType != static_cast<int32_t>(DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE) &&
        changeType != static_cast<int32_t>(DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE)) {
        ANS_LOGI("Handle remote change invalid %{public}d.", changeType);
        return;
    }

    std::vector<NotificationDistributedBundle> applicationList;
    if (!application.GetApplicationChangeList(applicationList)) {
        ANS_LOGI("Handle remote change application failed %{public}d.", changeType);
    }

    NotificationHelper::SetDeviceDistributedBundleList(static_cast<DistributedBundleChangeType>(changeType),
        applicationList);
}
#endif

}
}
