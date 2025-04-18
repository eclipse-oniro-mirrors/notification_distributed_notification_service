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

#include "bundle_icon_box.h"

#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

namespace {
const int32_t BUNDLE_NAME_TYPE = 1;
const int32_t ICON_TYPE = 2;
const int32_t LENGTH_TYPE = 3;
const int32_t ICON_START_INDEX = 10;
}

BundleIconBox::BundleIconBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(BUNDLE_ICON_SYNC);
}

BundleIconBox::BundleIconBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool BundleIconBox::SetIconSyncType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(BUNDLE_ICON_SYNC_TYPE, type));
}

bool BundleIconBox::SetDataLength(int32_t length)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LENGTH_TYPE, length));
}

bool BundleIconBox::SetBundleList(const std::vector<std::string>& bundleList)
{
    if (box_ == nullptr) {
        return false;
    }
    int32_t index = 0;
    for (auto& bundleName : bundleList) {
        if (box_->PutValue(std::make_shared<TlvItem>(ICON_START_INDEX + index, bundleName))) {
            index++;
        }
    }
    return SetDataLength(index);
}

bool BundleIconBox::SetBundlesIcon(const std::unordered_map<std::string, std::string>& bundles)
{
    if (box_ == nullptr || bundles.size() > MAX_ICON_NUM) {
        return false;
    }
    int32_t index = 0;
    for (auto& bundle : bundles) {
        TlvBox box;
        box.PutValue(std::make_shared<TlvItem>(BUNDLE_NAME_TYPE, bundle.first));
        box.PutValue(std::make_shared<TlvItem>(ICON_TYPE, bundle.second));
        ANS_LOGW("SetBundlesIcon %{public}s %{public}d.", bundle.first.c_str(), (int32_t)(bundle.second.size()));
        if (!box.Serialize(false)) {
            ANS_LOGW("Set bundles icon failed %{public}s.", bundle.first.c_str());
            continue;
        }
        box_->PutValue(std::make_shared<TlvItem>(ICON_START_INDEX + index, box.byteBuffer_, box.bytesLength_));
        index++;
    }
    return SetDataLength(index);
}

bool BundleIconBox::SetLocalDeviceId(const std::string& deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool BundleIconBox::GetIconSyncType(int32_t& type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(BUNDLE_ICON_SYNC_TYPE, type);
}

bool BundleIconBox::GetDataLength(int32_t& length)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LENGTH_TYPE, length);
}

bool BundleIconBox::GetBundleList(std::vector<std::string>& bundleList)
{
    int32_t length = 0;
    if (!GetDataLength(length)) {
        return false;
    }
    for (int i = 0; i < length; i++) {
        std::string bundleName;
        if (box_->GetStringValue(ICON_START_INDEX + i, bundleName))
            bundleList.push_back(bundleName);
    }
    return true;
}

bool BundleIconBox::GetBundlesIcon(std::unordered_map<std::string, std::string>& bundles)
{
    int32_t length = 0;
    if (!GetDataLength(length)) {
        ANS_LOGW("Get GetBundlesIcon failed.");
        return false;
    }
    for (int i = 0; i < MAX_ICON_NUM && i < length; i++) {
        TlvBox box;
        std::string icon;
        std::string bundleName;
        if (!box_->GetObjectValue(ICON_START_INDEX + i, box)) {
            ANS_LOGW("Get bundles icon failed %{public}d.", i);
            continue;
        }
        if (box.GetStringValue(ICON_TYPE, icon) &&
            box.GetStringValue(BUNDLE_NAME_TYPE, bundleName)) {
            ANS_LOGI("GetBundlesIcon %{public}s %{public}d.", bundleName.c_str(), (int32_t)(icon.size()));
            bundles.insert(std::make_pair(bundleName, icon));
        }
    }
    return true;
}

bool BundleIconBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}
}
}
