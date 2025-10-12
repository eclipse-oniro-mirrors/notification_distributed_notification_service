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

#ifndef DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_COMMON_H
#define DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_COMMON_H

#include <string>

namespace OHOS {
namespace Notification {
enum class ExtensionServiceConnectionState {
    CREATED,
    CONNECTING,
    CONNECTED,
    FREEZED,
    DISCONNECTED
};

struct ExtensionSubscriberInfo {
    std::string bundleName;
    std::string extensionName;
    int32_t uid = -1;
    int32_t userId = -1;
};
}
}
#endif // DISTRIBUTED_INCLUDE_EXTENSION_EXTENSION_SERVICE_COMMON_H
