/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "distributed_service.h"

#include "socket.h"
#include "session.h"
#include "distributed_device_data.h"
#include "dm_device_info.h"
#include "ans_log_wrapper.h"
#include "distributed_socket.h"
#include "distributed_preference.h"
#include "bundle_resource_helper.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "distributed_client.h"
#include "ans_image_util.h"

namespace OHOS {
namespace Notification {

bool DistributedService::GetBundleResourceInfo(const std::string bundleName, std::string& icon)
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
    ANS_LOGI("Dans get bundle icon bundle %{public}s %{public}u.", bundleName.c_str(), resourceInfo.icon.size());
    return true;
}

void DistributedService::GetNeedUpdateDevice(bool updatedExit, const std::string& bundleName,
    std::vector<DistributedDeviceInfo>& updateDeviceList)
{
    for (auto& device : peerDevice_) {
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

void DistributedService::HandleBundleChanged(const std::string& bundleName, bool updatedExit)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }

    std::function<void()> task = std::bind([&, bundleName, updatedExit]() {
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
    });
    serviceQueue_->submit(task);
}

void DistributedService::HandleBundleRemoved(const std::string& bundleName)
{
    if (serviceQueue_ == nullptr) {
        ANS_LOGE("Check handler is null.");
        return;
    }

    std::function<void()> task = std::bind([&, bundleName]() {
        for (auto& device : peerDevice_) {
            auto iter = bundleIconCache_.find(device.first);
            if (iter == bundleIconCache_.end() ||
                iter->second.find(bundleName) == iter->second.end()) {
                continue;
            }
            iter->second.erase(bundleName);
            if (device.second.deviceType_ == DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE) {
                continue;
            }
            BundleIconBox iconBox;
            iconBox.SetIconSyncType(IconSyncType::REMOVE_BUNDLE_ICON);
            iconBox.SetBundleList({bundleName});
            iconBox.SetLocalDeviceId(localDevice_.deviceId_);
            if (!iconBox.Serialize()) {
                ANS_LOGW("Dans HandleBundleRemove serialize failed.");
                continue;
            }

            DistributedClient::GetInstance().SendMessage(iconBox.GetByteBuffer(),
                iconBox.GetByteLength(), TransDataType::DATA_TYPE_MESSAGE,
                device.second.deviceId_, device.second.deviceType_);
            ANS_LOGI("Dans ReportBundleIconList %{public}s %{public}d %{public}s %{public}d.",
                device.second.deviceId_.c_str(), device.second.deviceType_, localDevice_.deviceId_.c_str(),
                localDevice_.deviceType_);
        }
    });
    serviceQueue_->submit(task);
}

void DistributedService::HandleBundlesEvent(const std::string& bundleName, const std::string& action)
{
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        HandleBundleChanged(bundleName, true);
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        HandleBundleRemoved(bundleName);
    }
}

}
}
