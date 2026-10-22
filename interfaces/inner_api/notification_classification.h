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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CLASSIFICATION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CLASSIFICATION_H

#include <string>

#include "parcel.h"
#include "notification_constant.h"

namespace OHOS {
namespace Notification {
class NotificationClassification : public Parcelable {
public:
    NotificationClassification() = default;
    NotificationClassification(const std::string &classification, const std::string &subClassification);
    ~NotificationClassification() override = default;

    void SetClassification(const std::string &classification);
    std::string GetClassification() const;

    void SetSubClassification(const std::string &subClassification);
    std::string GetSubClassification() const;

    std::string Dump();

    bool Marshalling(Parcel &parcel) const override;
    static NotificationClassification *Unmarshalling(Parcel &parcel);

    class PriorityInfo {
    public:
        PriorityInfo() = default;
        ~PriorityInfo() = default;

        /**
         * Sets the priority notification type. The value is accepted as-is on this internal
         * channel; the validation against
         * NotificationConstant::PriorityNotificationType::VALID_PRIORITY_TYPE_LIST is owned by
         * the third-party entry NotificationRequest::SetPriorityNotificationType.
         * @param priorityNotificationType Indicates the priority notification type to set.
         */
        void SetPriorityNotificationType(const std::string &priorityNotificationType);

        /**
         * Gets the priority notification type, OTHER by default.
         * @return the priority notification type.
         */
        std::string GetPriorityNotificationType() const;

        /**
         * Sets the expire time of the priority state. It is an absolute time point in epoch
         * milliseconds (UTC) at which the notification degrades to OTHER, not a relative delay;
         * 0 means undetermined.
         * @param expiredTime Indicates the absolute expire time to set.
         */
        void SetExpiredTime(int64_t expiredTime);

        /**
         * Gets the expire time of the priority state, 0 (undetermined) by default.
         * @return the absolute expire time in epoch milliseconds.
         */
        int64_t GetExpiredTime() const;

        /**
         * Sets the source of the priority tagging result. Only values of
         * NotificationConstant::PrioritySourceResult from PARAM_IN to PUSH_RULE are accepted.
         * @param source Indicates the tagging source to set.
         */
        void SetSource(int32_t source);

        /**
         * Gets the source of the priority tagging result, INVALID_RESULT by default.
         * @return the tagging source.
         */
        int32_t GetSource() const;

        /**
         * Marshals the priority info into the parcel tail in the order of type, expiredTime
         * and source. The marshalling is unconditional to keep the parcel format symmetric no
         * matter the priority notification feature switch is on or off.
         * @param parcel Indicates the parcel to write.
         * @return true if succeeded, false otherwise.
         */
        bool Marshalling(Parcel &parcel) const;

        /**
         * Unmarshals the priority info from the parcel tail. For old format data which only
         * contains the two classification strings, keeps default values with a warning and
         * does not fail the whole unmarshalling.
         * @param parcel Indicates the parcel to read.
         * @return true if succeeded or tolerated, false otherwise.
         */
        bool ReadFromParcel(Parcel &parcel);

        /**
         * Dumps the priority info triple for DFX.
         * @return the dumped string.
         */
        std::string Dump();

    private:
        std::string priorityNotificationType_ {NotificationConstant::PriorityNotificationType::OTHER};
        int64_t expiredTime_ {0};
        int32_t source_ {static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT)};
    };

    /**
     * Sets the priority info by copy assignment (value member semantics).
     * @param priorityInfo Indicates the priority info to set.
     */
    void SetPriorityInfo(const PriorityInfo &priorityInfo);

    /**
     * Gets the priority info.
     * @return the priority info.
     */
    const PriorityInfo &GetPriorityInfo() const;

    /**
     * Checks whether the classification dimension was explicitly set by the tagging
     * source: a landing round that did not set a dimension keeps the cached value of
     * that dimension instead of overwriting it with the unset default.
     * @return true if the classification dimension was set.
     */
    bool IsClassificationSet() const;

    /**
     * Checks whether the priority dimension was explicitly set by the tagging source
     * (an unset round keeps the cached triple untouched).
     * @return true if the priority info was set.
     */
    bool IsPriorityInfoSet() const;

private:
    bool ReadFromParcel(Parcel &parcel);

    std::string classification_;
    std::string subClassification_;
    PriorityInfo priorityInfo_;
    bool classificationSet_ {false};
    bool priorityInfoSet_ {false};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CLASSIFICATION_H