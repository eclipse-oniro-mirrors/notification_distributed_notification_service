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

#include "raw_data_container.h"

#include <string>

#include "ans_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace Notification {
RawDataContainer::RawDataContainer(std::string rawString): rawString_(rawString)
{}

void RawDataContainer::SetRawString(const std::string &rawString)
{
    rawString_ = rawString;
}

std::string RawDataContainer::GetRawString() const
{
    return rawString_;
}

bool RawDataContainer::Marshalling(Parcel &parcel) const
{
    parcel.SetMaxCapacity(NotificationConstant::MAX_IPC_RAW_DATA_SIZE);
    if (!parcel.WriteString16(Str8ToStr16(rawString_))) {
        ANS_LOGE("Failed to write raw string");
        return false;
    }
    return true;
}

RawDataContainer* RawDataContainer::Unmarshalling(Parcel &parcel)
{
    auto pRawDataContainer = new (std::nothrow) RawDataContainer();
    if (pRawDataContainer) {
        pRawDataContainer->ReadFromParcel(parcel);
    }
    return pRawDataContainer;
}

bool RawDataContainer::ReadFromParcel(Parcel &parcel)
{
    rawString_ = Str16ToStr8(parcel.ReadString16());
    return true;
}

}  // namespace Notification
}  // namespace OHOS