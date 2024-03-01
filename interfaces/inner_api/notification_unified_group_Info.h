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


#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_UNIFIED_GROUP_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_UNIFIED_GROUP_INFO_H

#include "parcel.h"
#include "want_params.h"
#include <string>

namespace OHOS {
namespace Notification {
class NotificationUnifiedGroupInfo : public Parcelable {
public:
    NotificationUnifiedGroupInfo() = default;

    ~NotificationUnifiedGroupInfo() = default;

    /**
     * @brief Obtains the key of unified group info.
     *
     * @return Returns the key that aggregated across applications.
     */
    std::string GetKey() const;

    /**
     * @brief Set the key of unified group info.
     *
     * @param key Indicates the key of unified group info.
     */
    void SetKey(const std::string &key);

    /**
     * @brief Obtains the title of unified group info.
     *
     * @return Returns the title that aggregated across applications.
     */
    std::string GetTitle() const;

    /**
     * @brief Set the title of unified group info.
     *
     * @param title the title of unified group info.
     */
    void SetTitle(const std::string &title);

    /**
     * @brief Obtains the content of unified group info.
     *
     * @return Returns the content that aggregated across applications.
     */
    std::string GetContent() const;

    /**
     * @brief Set the content of unified group info.
     *
     * @param content the content of unified group info.
     */
    void SetContent(const std::string &content);

    /**
     * @brief Obtains the sceneName of unified group info.
     *
     * @return Returns the sceneName of aggregation scenario.
     */
    std::string GetSceneName() const;

    /**
     * @brief Set the sceneName of unified group info.
     *
     * @param sceneName the sceneName of unified group info.
     */
    void SetSceneName(const std::string &sceneName);

    /**
     * @brief Obtains the WantParams object set in the unified group info.
     *
     * @return Returns the WantParams object.
     */
    std::shared_ptr<AAFwk::WantParams> GetExtraInfo() const;

    /**
     * @brief Sets extra parameters that are stored as key-value pairs for the unified group info.
     *
     * @param extras Indicates the WantParams object containing the extra parameters in key-value pair format.
     */
    void SetExtraInfo(const std::shared_ptr<AAFwk::WantParams> &extras);

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Marshal a object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationUnifiedGroupInfo.
     */
    static NotificationUnifiedGroupInfo *Unmarshalling(Parcel &parcel);

private:
    /**
     * @brief Read a NotificationUnifiedGroupInfo object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

private:
    std::string key_ {};
    std::string title_ {};
    std::string content_ {};
    std::string sceneName_ {};
    std::shared_ptr<AAFwk::WantParams> extraInfo_ {};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_UNIFIED_GROUP_INFO_H
