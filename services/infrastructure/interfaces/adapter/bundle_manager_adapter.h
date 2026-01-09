/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANS_BUNDLE_MANAGER_ADAPTER_H
#define ANS_BUNDLE_MANAGER_ADAPTER_H

#include <string>
#include <vector>

namespace OHOS {
namespace Notification {
namespace Infra {
struct NotificationApplicationInfo {
    bool allowEnableNotification = false;
    bool isSystemApp = false;
    int32_t appIndex;
    uint32_t accessTokenId = 0;
    std::string label;
    std::string bundleName;
    std::string installSource;
};

struct NotificationBundleManagerInfo {
    std::string bundleName;
    int32_t uid = -1;
    bool isStageBasedModel = false;
    NotificationApplicationInfo applicationInfo;
};

enum NotificationBundleManagerFlag {
    // get bundle info except abilityInfos
    GET_BUNDLE_DEFAULT = 0x00000000,
    // get bundle info include abilityInfos
    GET_BUNDLE_WITH_ABILITIES = 0x00000001,
    // get bundle info include request permissions
    GET_BUNDLE_WITH_REQUESTED_PERMISSION = 0x00000010,
    // get bundle info include extension info
    GET_BUNDLE_WITH_EXTENSION_INFO = 0x00000020,
    // get bundle info include hash value
    GET_BUNDLE_WITH_HASH_VALUE = 0x00000030,
    // get bundle info inlcude menu, only for dump usage
    GET_BUNDLE_WITH_MENU = 0x00000040,
    // get bundle info inlcude router map, only for dump usage
    GET_BUNDLE_WITH_ROUTER_MAP = 0x00000080,
    // get bundle info include skill info
    GET_BUNDLE_WITH_SKILL = 0x00000800,
    // the flag only for C++ interface passing
    GET_BUNDLE_INFO_EXCLUDE_EXT = 0x00020000,
};

} // Infra
} // namespace Notification
} // namespace OHOS
#endif
