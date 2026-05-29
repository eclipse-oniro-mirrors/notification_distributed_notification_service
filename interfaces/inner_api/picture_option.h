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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PICTURE_OPTION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PICTURE_OPTION_H

#include "parcel.h"
#include <string>
#include <vector>

namespace OHOS {
namespace Notification {
/**
 * @brief PictureOption class for specifying pictures to be pre-parsed in live view notifications.
 *
 * This class allows subscribers to specify which pictures should be parsed
 * in the native thread before being delivered to the subscriber callback,
 * reducing peak memory usage by avoiding UI thread image decoding.
 */
class PictureOption : public Parcelable {
public:
    /**
     * @brief Default constructor.
     */
    PictureOption();

    /**
     * @brief Constructor with pre-parse picture list.
     * @param picList List of picture keys to be pre-parsed from live view extra info.
     */
    explicit PictureOption(const std::vector<std::string> &picList);

    /**
     * @brief Copy constructor.
     * @param option The PictureOption object to copy from.
     */
    PictureOption(const PictureOption &option);

    /**
     * @brief Destructor.
     */
    ~PictureOption();

    /**
     * @brief Sets the list of picture keys to be pre-parsed.
     * @param picList List of picture keys.
     */
    void SetPreparseLiveViewPicList(const std::vector<std::string> &picList);

    /**
     * @brief Gets the list of picture keys to be pre-parsed.
     * @return Returns the list of picture keys.
     */
    std::vector<std::string> GetPreparseLiveViewPicList() const;

    /**
     * @brief Marshals the object into a parcel.
     * @param parcel The parcel to write to.
     * @return Returns true if successful, false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshals an object from a parcel.
     * @param parcel The parcel to read from.
     * @return Returns the unmarshalled PictureOption object.
     */
    static PictureOption *Unmarshalling(Parcel &parcel);

    /**
     * @brief Assignment operator.
     * @param option The PictureOption object to assign from.
     * @return Returns the reference to this object.
     */
    PictureOption& operator=(const PictureOption &option);

private:
    bool ReadFromParcel(Parcel &parcel);

    std::vector<std::string> preparseLiveViewPicList_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_PICTURE_OPTION_H