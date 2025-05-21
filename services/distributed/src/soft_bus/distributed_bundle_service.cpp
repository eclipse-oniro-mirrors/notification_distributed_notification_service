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

namespace OHOS {
namespace Notification {

DistributedBundleService& DistributedBundleService::GetInstance()
{
    static DistributedBundleService distributedBundleService;
    return distributedBundleService;
}

#ifdef DISTRIBUTED_FEATURE_MASTER
void DistributedBundleService::RequestBundlesIcon(const DistributedDeviceInfo peerDevice, bool isForce)
{
    if (!DistributedDeviceService::GetInstance().CheckDeviceExist(peerDevice.deviceId_)) {
        return;
    }
    bool sync = DistributedDeviceService::GetInstance().IsDeviceSyncData(peerDevice.deviceId_);
    if (!isForce && sync) {
        ANS_LOGI("Dans %{public}d %{public}d.", isForce, sync);
        return;
    }

    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    iconBox->SetIconSyncType(IconSyncType::REQUEST_BUNDLE_ICON);
    iconBox->SetLocalDeviceId(localDevice.deviceId_);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans RequestBundlesIcon serialize failed.");
        return;
    }

    DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, MODIFY_ERROR_EVENT_CODE);
    ANS_LOGI("Dans RequestBundlesIcon %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_);
}

void DistributedBundleService::GenerateBundleIconSync(const DistributedDeviceInfo& device)
{
    std::vector<NotificationBundleOption> bundleOption;
    if (NotificationHelper::GetAllLiveViewEnabledBundles(bundleOption) != 0) {
        ANS_LOGW("Dans get all live view enable bundle failed.");
        return;
    }

    std::vector<NotificationBundleOption> enableBundleOption;
    if (NotificationHelper::GetAllDistribuedEnabledBundles("liteWearable", enableBundleOption) != 0) {
        ANS_LOGW("Dans get all live view enable bundle failed.");
    }

    std::set<std::string> enabledBundles;
    for (auto item : enableBundleOption) {
        enabledBundles.insert(item.GetBundleName());
    }
    std::set<std::string> cachedIcons;
    std::vector<std::string> unCachedBundleList;
    if (bundleIconCache_.find(device.deviceId_) != bundleIconCache_.end()) {
        cachedIcons = bundleIconCache_[device.deviceId_];
    }
    for (auto item : bundleOption) {
        if (enabledBundles.find(item.GetBundleName()) != enabledBundles.end() ||
            cachedIcons.find(item.GetBundleName()) != cachedIcons.end()) {
            continue;
        }
        unCachedBundleList.push_back(item.GetBundleName());
    }

    ANS_LOGI("Dans Generate bundle %{public}zu %{public}zu %{public}zu.", bundleOption.size(),
        enableBundleOption.size(), unCachedBundleList.size());
    std::vector<std::string> sendIcon;
    std::unordered_map<std::string, std::string> icons;
    for (auto bundle : unCachedBundleList) {
        std::string icon;
        if (!GetBundleResourceInfo(bundle, icon)) {
            continue;
        }
        sendIcon.push_back(bundle);
        icons.insert(std::make_pair(bundle, icon));
        if (icons.size() == BundleIconBox::MAX_ICON_NUM) {
            if (UpdateBundlesIcon(icons, device) == ERR_OK) {
                cachedIcons.insert(sendIcon.begin(), sendIcon.end());
            }
            icons.clear();
            sendIcon.clear();
        }
    }
    if (!icons.empty() && UpdateBundlesIcon(icons, device) == ERR_OK) {
        cachedIcons.insert(sendIcon.begin(), sendIcon.end());
    }
    bundleIconCache_[device.deviceId_] = cachedIcons;
}

void DistributedBundleService::HandleBundleRemoved(const std::string& bundleName)
{
    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    auto peerDevices = DistributedDeviceService::GetInstance().GetDeviceList();
    for (auto& device : peerDevices) {
        auto iter = bundleIconCache_.find(device.first);
        if (iter == bundleIconCache_.end() ||
            iter->second.find(bundleName) == iter->second.end()) {
            continue;
        }
        iter->second.erase(bundleName);
        if (device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
            continue;
        }

        std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
        iconBox->SetIconSyncType(IconSyncType::REMOVE_BUNDLE_ICON);
        iconBox->SetBundleList({bundleName});
        iconBox->SetLocalDeviceId(localDevice.deviceId_);
        if (!iconBox->Serialize()) {
            ANS_LOGW("Dans HandleBundleRemove serialize failed.");
            continue;
        }

        DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_MESSAGE,
            device.second.deviceId_, MODIFY_ERROR_EVENT_CODE);
        ANS_LOGI("Dans ReportBundleIconList %{public}s %{public}d.",
            StringAnonymous(device.second.deviceId_).c_str(), device.second.deviceType_);
    }
}

void DistributedBundleService::HandleBundleChanged(const std::string& bundleName, bool updatedExit)
{
    std::vector<DistributedDeviceInfo> updateDeviceList;
    GetNeedUpdateDevice(updatedExit, bundleName, updateDeviceList);
    if (updateDeviceList.empty()) {
        ANS_LOGI("No need update %{public}s.", bundleName.c_str());
        return;
    }
    std::string icon;
    if (!GetBundleResourceInfo(bundleName, icon)) {
        return;
    }
    std::unordered_map<std::string, std::string> icons;
    icons.insert(std::make_pair(bundleName, icon));
    for (auto& device : updateDeviceList) {
        UpdateBundlesIcon(icons, device);
    }
}

int32_t DistributedBundleService::UpdateBundlesIcon(const std::unordered_map<std::string, std::string>& icons,
    const DistributedDeviceInfo peerDevice)
{
    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    iconBox->SetIconSyncType(IconSyncType::UPDATE_BUNDLE_ICON);
    iconBox->SetBundlesIcon(icons);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans UpdateBundlesIcon serialize failed.");
        return -1;
    }

    int32_t result = DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_BYTES,
        peerDevice.deviceId_, MODIFY_ERROR_EVENT_CODE);
    ANS_LOGI("Dans UpdateBundlesIcon %{public}s %{public}d %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_, result);
    return result;
}

bool DistributedBundleService::GetBundleResourceInfo(const std::string bundleName, std::string& icon)
{
    AppExecFwk::BundleResourceInfo resourceInfo;
    if (DelayedSingleton<BundleResourceHelper>::GetInstance()->GetBundleInfo(bundleName, resourceInfo) != 0) {
        ANS_LOGW("Dans get bundle icon failed %{public}s.", bundleName.c_str());
        return false;
    }
    std::shared_ptr<Media::PixelMap> iconPixelmap = AnsImageUtil::CreatePixelMapByString(resourceInfo.icon);
    if (!AnsImageUtil::ImageScale(iconPixelmap, DEFAULT_ICON_WITHE, DEFAULT_ICON_HEIGHT)) {
        return false;
    }
    icon = AnsImageUtil::PackImage(iconPixelmap);
    ANS_LOGI("Dans get bundle icon bundle %{public}s %{public}zu.", bundleName.c_str(), resourceInfo.icon.size());
    return true;
}

void DistributedBundleService::GetNeedUpdateDevice(bool updatedExit, const std::string& bundleName,
    std::vector<DistributedDeviceInfo>& updateDeviceList)
{
    auto peerDevices = DistributedDeviceService::GetInstance().GetDeviceList();
    for (auto& device : peerDevices) {
        if (device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
            continue;
        }
        auto iter = bundleIconCache_.find(device.first);
        if (updatedExit) {
            if (iter == bundleIconCache_.end() ||
                iter->second.find(bundleName) == iter->second.end()) {
                continue;
            }
            updateDeviceList.push_back(device.second);
        } else {
            if (iter != bundleIconCache_.end() &&
                iter->second.find(bundleName) != iter->second.end()) {
                continue;
            }
            if (iter == bundleIconCache_.end()) {
                std::set<std::string> cachedIcons = { bundleName };
                bundleIconCache_.insert(std::make_pair(device.first, cachedIcons));
            } else {
                iter->second.insert(bundleName);
            }
            updateDeviceList.push_back(device.second);
        }
    }
}
#else
void DistributedBundleService::ReportBundleIconList(const DistributedDeviceInfo peerDevice)
{
    std::vector<std::string> bundlesName;
    DistributedPreferences::GetInstance().GetSavedBundlesIcon(bundlesName);
    std::shared_ptr<BundleIconBox> iconBox = std::make_shared<BundleIconBox>();
    auto localDevice = DistributedDeviceService::GetInstance().GetLocalDevice();
    iconBox->SetIconSyncType(IconSyncType::REPORT_SAVED_ICON);
    iconBox->SetBundleList(bundlesName);
    iconBox->SetLocalDeviceId(localDevice.deviceId_);
    if (!iconBox->Serialize()) {
        ANS_LOGW("Dans ReportBundleIconList serialize failed.");
        return;
    }

    DistributedClient::GetInstance().SendMessage(iconBox, TransDataType::DATA_TYPE_MESSAGE,
        peerDevice.deviceId_, MODIFY_ERROR_EVENT_CODE);
    ANS_LOGI("Dans ReportBundleIconList %{public}s %{public}d.",
        StringAnonymous(peerDevice.deviceId_).c_str(), peerDevice.deviceType_);
}
#endif

}
}
