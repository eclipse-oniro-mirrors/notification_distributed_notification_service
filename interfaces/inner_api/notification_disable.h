/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISABLE_PROFILE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISABLE_PROFILE_H

#include "nlohmann/json.hpp"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class NotificationDisable : public Parcelable {
public:
    NotificationDisable() = default;
    ~NotificationDisable() = default;

    void SetDisabled(bool disabled);
    void SetBundleList(const std::vector<std::string> &bundleList);
    void SetUserId(int32_t userId);
    bool GetDisabled() const;
    std::vector<std::string> GetBundleList() const;
    int32_t GetUserId() const;
    bool Marshalling(Parcel &parcel) const override;
    bool ReadFromParcel(Parcel &parcel);

    static NotificationDisable *Unmarshalling(Parcel &parcel);
    std::string ToJson();
    void FromJson(const std::string &jsonObj);

private:
    bool disabled_ = false;
    std::vector<std::string> bundleList_;
    int32_t userId_ = -1;
};
}
}

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_DISABLE_PROFILE_H