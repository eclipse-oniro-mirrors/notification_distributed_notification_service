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

#include "large_info_container.h"

#include <string>

#include "ans_ipc_common_utils.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
LargeInfoContainer::LargeInfoContainer(
    const RawDataContainer &rawDataContainer): rawDataContainer_(rawDataContainer) {}

void LargeInfoContainer::SetRawDataContainer(const RawDataContainer &rawDataContainer)
{
    rawDataContainer_ = rawDataContainer;
}

RawDataContainer LargeInfoContainer::GetRawDataContainer()
{
    return rawDataContainer_;
}

bool LargeInfoContainer::Marshalling(Parcel &parcel) const
{
    OHOS::MessageParcel &dataParcel = static_cast<OHOS::MessageParcel &>(parcel);
    if (!AnsIpcCommonUtils::WriteLargeInfoIntoParcelable(
        dataParcel, rawDataContainer_, NotificationConstant::MAX_IPC_RAW_DATA_SIZE)) {
        ANS_LOGE("Failed to write large info container");
        return false;
    }
    return true;
}

LargeInfoContainer *LargeInfoContainer::Unmarshalling(Parcel &parcel)
{
    auto pLargeInfoContainer = new (std::nothrow) LargeInfoContainer();
    if (pLargeInfoContainer && !pLargeInfoContainer->ReadFromParcel(parcel)) {
        delete pLargeInfoContainer;
        pLargeInfoContainer = nullptr;
    }

    return pLargeInfoContainer;
}

bool LargeInfoContainer::ReadFromParcel(Parcel &parcel)
{
    OHOS::MessageParcel &dataParcel = static_cast<OHOS::MessageParcel &>(parcel);
    if (!AnsIpcCommonUtils::ReadLargeInfoFromParcelable(dataParcel, rawDataContainer_)) {
        ANS_LOGE("Failed to read large info container");
        return false;
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS