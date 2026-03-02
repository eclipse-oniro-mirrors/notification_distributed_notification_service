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

#include "application_change_box.h"

#include "ans_log_wrapper.h"
#include "distributed_liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {

namespace {
// Calculate the fixed serialization field length based on the object ApplicationBoxInfo.
const int32_t LENGTH_TYPE = 10;
const int32_t APPLICATION_INFO_START = 100;
const int32_t APPLICATION_ITEM_START = 1000;
}

ApplicationChangeBox::ApplicationChangeBox()
{
    if (box_ == nullptr) {
        return;
    }
    box_->SetMessageType(APPLICATION_INFO_SYNC);
}

ApplicationChangeBox::ApplicationChangeBox(std::shared_ptr<TlvBox> box) : BoxBase(box)
{
}

bool ApplicationChangeBox::SetLocalDeviceId(const std::string &deviceId)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LOCAL_DEVICE_ID, deviceId));
}

bool ApplicationChangeBox::SetApplicationSyncType(int32_t type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(BUNDLE_ICON_SYNC_TYPE, type));
}

bool ApplicationChangeBox::SetDataLength(int32_t length)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->PutValue(std::make_shared<TlvItem>(LENGTH_TYPE, length));
}

bool ApplicationChangeBox::SetApplicationChangeList(const std::vector<NotificationDistributedBundle>& applicationList)
{
    if (box_ == nullptr) {
        return false;
    }
    int32_t index = 0;
    for (auto& application : applicationList) {
        TlvBox box;
        int32_t offset = 0;
        box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset++, application.IsAncoBundle()));
        int32_t liveViewType = static_cast<int32_t>(application.GetLiveViewEnable());
        box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset++, liveViewType));
        int32_t notificationType = static_cast<int32_t>(application.GetNotificationEnable());
        box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset++, notificationType));
        box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset++, application.GetBundleUid()));
        if (application.GetBundleIcon() != nullptr) {
            std::vector<uint8_t> buffer;
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewPiexlMap2BinFile(
                application.GetBundleIcon(), buffer);
            const unsigned char* begin = buffer.data();
            box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset, begin, buffer.size()));
        }
        offset++;
        box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset++, application.GetBundleLabel()));
        box.PutValue(std::make_shared<TlvItem>(APPLICATION_INFO_START + offset++, application.GetBundleName()));
        if (!box.Serialize(false)) {
            ANS_LOGW("Set bundles icon failed %{public}s.", application.GetBundleName().c_str());
            continue;
        }
        box_->PutValue(std::make_shared<TlvItem>(APPLICATION_ITEM_START + index, box.byteBuffer_, box.bytesLength_));
        index++;
    }
    return SetDataLength(index);
}

bool ApplicationChangeBox::GetLocalDeviceId(std::string& deviceId) const
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetStringValue(LOCAL_DEVICE_ID, deviceId);
}

bool ApplicationChangeBox::GetApplicationSyncType(int32_t& type)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(BUNDLE_ICON_SYNC_TYPE, type);
}

bool ApplicationChangeBox::GetDataLength(int32_t& length)
{
    if (box_ == nullptr) {
        return false;
    }
    return box_->GetInt32Value(LENGTH_TYPE, length);
}

bool ApplicationChangeBox::GetApplicationChangeList(std::vector<NotificationDistributedBundle>& applicationList)
{
    int32_t length = 0;
    if (!GetDataLength(length)) {
        ANS_LOGW("Get GetBundlesIcon failed.");
        return false;
    }
    for (int i = 0; i < MAX_LIST_NUM && i < length; i++) {
        TlvBox box;
        NotificationDistributedBundle application;
        if (!box_->GetObjectValue(APPLICATION_ITEM_START + i, box)) {
            ANS_LOGW("Get application failed %{public}d.", i);
            continue;
        }

        int32_t offset = 0;
        bool isAnco = false;
        if (box.GetBoolValue(APPLICATION_INFO_START + offset++, isAnco)) {
            application.SetAncoBundle(isAnco);
        }
        int32_t intType = 0;
        if (box.GetInt32Value(APPLICATION_INFO_START + offset++, intType)) {
            application.SetLiveViewEnable(static_cast<NotificationConstant::SWITCH_STATE>(intType));
        }
        if (box.GetInt32Value(APPLICATION_INFO_START + offset++, intType)) {
            application.SetNotificationEnable(static_cast<NotificationConstant::SWITCH_STATE>(intType));
        }
        if (box.GetInt32Value(APPLICATION_INFO_START + offset++, intType)) {
            application.SetBundleUid(intType);
        }
        std::vector<uint8_t> buffer;
        if (box.GetBytes(APPLICATION_INFO_START + offset++, buffer)) {
            std::shared_ptr<Media::PixelMap> icon;
            DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(icon, buffer);
            application.SetBundleIcon(icon);
        }
        std::string data;
        if (box.GetStringValue(APPLICATION_INFO_START + offset++, data)) {
            application.SetBundleLabel(data);
        }
        if (box.GetStringValue(APPLICATION_INFO_START + offset++, data)) {
            application.SetBundleName(data);
        }
        applicationList.emplace_back(application);
    }
    return true;
}
}
}
