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

#ifndef MOCK_NOTIFICATION_SUBSCRIBE_INFO_BUILDER_H
#define MOCK_NOTIFICATION_SUBSCRIBE_INFO_BUILDER_H

#include "mock_fuzz_object.h"
#include "notification_subscribe_info.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {

template <>
NotificationSubscribeInfo* ObjectBuilder<NotificationSubscribeInfo>::Build(FuzzedDataProvider *fdp)
{
    auto subscribeInfo = new NotificationSubscribeInfo();

    subscribeInfo->AddAppName(fdp->ConsumeRandomLengthString());
    subscribeInfo->AddAppUserId(fdp->ConsumeIntegral<int32_t>());
    subscribeInfo->AddDeviceType(fdp->ConsumeRandomLengthString());
    subscribeInfo->SetSubscriberUid(fdp->ConsumeIntegral<int32_t>());
    subscribeInfo->SetFilterType(fdp->ConsumeIntegral<uint32_t>());
    subscribeInfo->SetNeedNotifyResponse(fdp->ConsumeBool());

    std::vector<NotificationConstant::SlotType> slotTypes;
    size_t slotTypeCnt = fdp->ConsumeIntegralInRange<uint32_t>(0, 6);
    for (size_t i = 0; i  < slotTypeCnt; ++i) {
        auto slotType = static_cast<NotificationConstant::SlotType>(
            fdp->ConsumeIntegralInRange<int32_t>(0, 7));
        slotTypes.push_back(slotType);
    }
    subscribeInfo->SetSlotTypes(slotTypes);
    return subscribeInfo;
}

}  // namespace Notification
}  // namespace OHOS

#endif  // MOCK_NOTIFICATION_SUBSCRIBE_INFO_BUILDER_H
