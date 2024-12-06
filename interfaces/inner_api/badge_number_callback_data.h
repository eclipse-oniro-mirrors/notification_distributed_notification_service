/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGE_NUMBER_CALLBACK_DATA_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGE_NUMBER_CALLBACK_DATA_H

#include "notification_constant.h"
#include "parcel.h"

namespace OHOS {
namespace Notification {
class BadgeNumberCallbackData : public Parcelable {
public:
    /**
     * Default constructor used to create a BadgeNumberCallbackData instance.
     */
    BadgeNumberCallbackData() = default;

    /**
     * A constructor used to create a BadgeNumberCallbackData instance with the input parameters passed.
     * @param bundle Indicates the name of the application.
     * @param uid Indicates the uid of the application.
     * @param badgeNumber badge number.
     */
    BadgeNumberCallbackData(const std::string &bundle, int32_t uid, int32_t badgeNumber);

    /**
     * A constructor used to create a BadgeNumberCallbackData instance with the input parameters passed.
     * @param bundle Indicates the name of the application.
     * @param appInstanceKey Indicates the application instance key.
     * @param uid Indicates the uid of the application.
     * @param badgeNumber badge number.
     * @param instanceKey application instance key.
     */
    BadgeNumberCallbackData(const std::string &bundle, const std::string &appInstanceKey_, int32_t uid,
        int32_t badgeNumber, int32_t instanceKey = 0);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~BadgeNumberCallbackData() = default;

    void SetBundle(const std::string &bundle);

    std::string GetBundle() const;

    void SetUid(int32_t uid);

    int32_t GetUid() const;

    void SetBadgeNumber(int32_t badgeNumber);

    int32_t GetBadgeNumber() const;

    void SetInstanceKey(int32_t key);

    int32_t GetInstanceKey() const;

    void SetAppInstanceKey(const std::string &key);

    std::string GetAppInstanceKey() const;

    /**
     * Returns a string representation of the BadgeNumberCallbackData object.
     */
    std::string Dump();

    /**
     * Marshal a object into a Parcel.
     * @param parcel the object into the parcel
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * Unmarshal object from a Parcel.
     * @return the BadgeNumberCallbackData
     */
    static BadgeNumberCallbackData *Unmarshalling(Parcel &parcel);

private:
    bool ReadFromParcel(Parcel &parcel);

    std::string bundle_;
    std::string appInstanceKey_;
    int32_t uid_;
    int32_t badgeNumber_;
    int32_t instanceKey_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_BADGE_NUMBER_CALLBACK_DATA_H