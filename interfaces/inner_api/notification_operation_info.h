/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_OPERATION_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_OPERATION_INFO_H

#include "parcel.h"
#include <cstdint>
#include <string>

namespace OHOS {
namespace Notification {

enum OperationType {
    DISTRIBUTE_OPERATION_JUMP = 0,
    DISTRIBUTE_OPERATION_REPLY
};

class NotificationOperationInfo : public Parcelable {
public:
    NotificationOperationInfo() = default;

    ~NotificationOperationInfo() = default;

    /**
     * @brief Obtains the initialTime.
     *
     * @return Returns the initialTime.
     */
    std::string GetActionName() const;

    void SetActionName(const std::string& actionName);

    /**
     * @brief Obtains the initialTime.
     *
     * @return Returns the initialTime.
     */
    std::string GetUserInput() const;

    void SetUserInput(const std::string& userInput);

    std::string GetHashCode() const;

    void SetHashCode(const std::string& hashCode);

    std::string GetEventId() const;

    void SetEventId(const std::string& eventId);

    OperationType GetOperationType() const;

    void SetOperationType(const OperationType& operationType);

    std::string Dump();

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationOperationInfo.
     */
    static NotificationOperationInfo *Unmarshalling(Parcel &parcel);

private:

    bool ReadFromParcel(Parcel &parcel);

    std::string actionName_;
    std::string userInput_;
    std::string hashCode_;
    std::string eventId_;
    OperationType operationType_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_TIME_H
