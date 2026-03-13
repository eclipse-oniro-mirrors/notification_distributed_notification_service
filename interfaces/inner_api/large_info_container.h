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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LARGE_INFO_CONTAINER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LARGE_INFO_CONTAINER_H

#include "notification_constant.h"
#include "raw_data_container.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class LargeInfoContainer : public Parcelable {
public:
    LargeInfoContainer() = default;

    LargeInfoContainer(const RawDataContainer &rawDataContainer);

    ~LargeInfoContainer() = default;

    void SetRawDataContainer(const RawDataContainer &rawDataContainer);

    RawDataContainer GetRawDataContainer();

    bool Marshalling(Parcel &parcel) const override;

    static LargeInfoContainer* Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);

    RawDataContainer rawDataContainer_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LARGE_INFO_CONTAINER_H