/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_ICON_BOX_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_ICON_BOX_H

#include <string>
#include "tlv_box.h"
#include "box_base.h"

namespace OHOS {
namespace Notification {

enum IconSyncType {
    REPORT_SAVED_ICON = 0,
    UPDATE_BUNDLE_ICON,
    REQUEST_BUNDLE_ICON,
    REMOVE_BUNDLE_ICON,
};

class BundleIconBox : public BoxBase {
public:
    const static int32_t MAX_ICON_NUM = 10;
    const static int32_t MAX_BUNDLE_NUM = 20;

    BundleIconBox();
    BundleIconBox(std::shared_ptr<TlvBox> box);
    bool SetMessageType(int32_t messageType);
    bool SetIconSyncType(int32_t type);
    bool SetDataLength(int32_t length);
    bool SetBundleList(const std::vector<std::string>& bundleList);
    bool SetBundlesIcon(const std::unordered_map<std::string, std::string>& bundles);
    bool SetLocalDeviceId(const std::string& deviceId);
    bool SetBundlesInfo(const std::vector<std::pair<std::string, std::string>>& bundles);

    bool GetIconSyncType(int32_t& type);
    bool GetDataLength(int32_t& length);
    bool GetBundleList(std::vector<std::string>& bundleList);
    bool GetBundlesIcon(std::unordered_map<std::string, std::string>& bundles);
    bool GetLocalDeviceId(std::string& deviceId) const;
    bool GetBundlesInfo(std::vector<std::string>& bundles, std::vector<std::string>& labels);
};
}  // namespace Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_BUNDLE_ICON_BOX_H
