/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_NOTIFICATION_DISTRIBUTED_OPTIONS_BUILDER_H
#define MOCK_NOTIFICATION_DISTRIBUTED_OPTIONS_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_distributed_options.h"

namespace OHOS {
namespace Notification {
template<>
NotificationDistributedOptions* ObjectBuilder<NotificationDistributedOptions>::Build(FuzzedDataProvider *fdp)
{
    bool distribute = fdp->ConsumeBool();
    std::vector<std::string> devicesSupportDisplay;
    for (int i = 0; i < fdp->ConsumeIntegralInRange(0, 10); ++i) {
        devicesSupportDisplay.push_back(fdp->ConsumeRandomLengthString());
    }
    std::vector<std::string> devicesSupportOperate;
    for (int i = 0; i < fdp->ConsumeIntegralInRange(0, 10); ++i) {
        devicesSupportOperate.push_back(fdp->ConsumeRandomLengthString());
    }
    ANS_LOGE("Build mock veriables");

    return new NotificationDistributedOptions(distribute, devicesSupportDisplay, devicesSupportOperate);
}
}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_DISTRIBUTED_OPTIONS_BUILDER_H
