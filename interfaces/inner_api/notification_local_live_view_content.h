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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LOCAL_LIVE_VIEW_CONTENT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_LOCAL_LIVE_VIEW_CONTENT_H

#include "notification_capsule.h"
#include "notification_progress.h"
#include "notification_local_live_view_button.h"
#include "message_user.h"
#include "notification_basic_content.h"
#include "notification_conversational_message.h"
#include "notification_json_convert.h"
#include "notification_time.h"
#include "parcel.h"
#include <vector>
#include "ans_const_define.h"

namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewContent : public NotificationBasicContent {
public:
    enum LiveViewContentInner {
        CAPSULE = 1,
        BUTTON,
        PROGRESS,
        TIME,
        INITIAL_TIME,
        CARD_BUTTON,
    };

    NotificationLocalLiveViewContent() = default;
    ~NotificationLocalLiveViewContent() = default;

    /*
     * @brief Sets the type to be included in a local live view notification.
     *
     * @param type Indicates the type to be included.
     */
    void SetType(int32_t type);

    /*
     * @brief Get the type of a local live view notification.
     *
     */
    int32_t GetType();

    /*
     * @brief Sets the capsule to be included in a local live view notification.
     *
     * @param capsule Indicates the type to be included.
     */
    void SetCapsule(NotificationCapsule capsule);

    /*
     * @brief Get the capsule of a local live view notification.
     *
     */
    NotificationCapsule GetCapsule();

    /*
     * @brief Sets the button to be included in a local live view notification.
     *
     * @param button Indicates the type to be included.
     */
    void SetButton(NotificationLocalLiveViewButton button);

    /*
     * @brief Get the button of a local live view notification.
     *
     */
    NotificationLocalLiveViewButton GetButton();

    /*
     * @brief Sets the card button to be included in a local live view notification.
     *
     * @param button Indicates the type to be included.
     */
    void SetCardButton(std::vector<NotificationIconButton> buttons);

    /*
     * @brief Get the card button of a local live view notification.
     *
     */
    std::vector<NotificationIconButton> GetCardButton();

    /*
     * @brief Sets the progress to be included in a local live view notification.
     *
     * @param progress Indicates the type to be included.
     */
    void SetProgress(NotificationProgress progress);

    /*
     * @brief Get the progress of a local live view notification.
     *
     */
    NotificationProgress GetProgress();

    /*
     * @brief Sets the time to be included in a local live view notification.
     *
     * @param time Indicates the type to be included.
     */
    void SetTime(NotificationTime time);

    /*
     * @brief Get the time of a local live view notification.
     *
     */
    NotificationTime GetTime();

    /*
     * @add flag function.
     *
     * @param flag Indicates the flag to be added.
     */
    void addFlag(int32_t flag);

    /*
     * @return is the given flag exist.
     *
     * @param flag Indicates the flag to be added.
     */
    bool isFlagExist(int32_t flag);

    /*
     * @brief Sets the type to be included in a local live view notification.
     *
     * @param type Indicates the type to be included.
     */
    void SetLiveviewType(int32_t type);

    /*
     * @brief Get the type of a local live view notification.
     *
     */
    int32_t GetLiveviewType();

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump() override;

    /**
     * @brief Converts a NotificationConversationalContent object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationConversationalContent object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationConversationalContent.
     */
    static NotificationLocalLiveViewContent *FromJson(const nlohmann::json &jsonObject);

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
     * @return Returns the NotificationConversationalContent.
     */
    static NotificationLocalLiveViewContent *Unmarshalling(Parcel &parcel);

    void ClearButton();

    void ClearCapsuleIcon();

protected:
    /**
     * @brief Read a NotificationConversationalContent object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel) override;

private:
    int32_t type_ {0};
    NotificationCapsule capsule_ {};
    NotificationLocalLiveViewButton button_ {};
    std::vector<NotificationIconButton> card_button_ {};
    NotificationProgress progress_ {};
    NotificationTime time_ {};
    std::vector<int32_t> flags_ {};
    int32_t liveviewType_ {-1};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_CONVERSATIONAL_CONTENT_H
