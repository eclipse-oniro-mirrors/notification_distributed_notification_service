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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_PARAMETERS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_PARAMETERS_H

#include <memory>

#include "parcel.h"
#include "want_params.h"
#include <string>

namespace OHOS {
namespace Notification {
/**
 * @brief Notification parameters containing WantAgent information.
 */
class NotificationParameters : public Parcelable {
public:
    /**
     * @brief Constructor.
     */
    NotificationParameters() = default;

    /**
     * @brief Destructor.
     */
    ~NotificationParameters() = default;

    /**
     * @brief Set want action.
     *
     * @param action Want action string.
     */
    void SetWantAction(const std::string &action);

    /**
     * @brief Get want action.
     *
     * @return Returns want action string.
     */
    std::string GetWantAction() const;

    /**
     * @brief Set want uri.
     *
     * @param uri Want uri string.
     */
    void SetWantUri(const std::string &uri);

    /**
     * @brief Get want uri.
     *
     * @return Returns want uri string.
     */
    std::string GetWantUri() const;

    /**
     * @brief Set want parameters.
     *
     * @param parameters Want parameters.
     */
    void SetWantParameters(const std::shared_ptr<AAFwk::WantParams> parameters);

    /**
     * @brief Get want parameters.
     *
     * @return Returns want parameters.
     */
    const std::shared_ptr<AAFwk::WantParams> GetWantParameters() const;

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Marshal a NotificationParameters object into a Parcel.
     *
     * @param parcel Indicates object into parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates parcel object.
     * @return Returns NotificationParameters.
     */
    static NotificationParameters *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read a NotificationParameters object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    std::string wantAction_;
    std::string wantUri_;
    std::shared_ptr<AAFwk::WantParams> wantParameters_;
};

}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_PARAMETERS_H