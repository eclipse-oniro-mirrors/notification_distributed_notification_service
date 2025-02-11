/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_REQUEST_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_REQUEST_H

#include "ans_const_define.h"
#include "message_user.h"
#include "notification_action_button.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_distributed_options.h"
#include "notification_flags.h"
#include "notification_json_convert.h"
#include "notification_template.h"
#include "parcel.h"
#include "pixel_map.h"
#include "want_agent.h"
#include "want_params.h"
#include "notification_check_request.h"
#include "notification_bundle_option.h"
#include "notification_unified_group_Info.h"
#include <string>
#include <map>

namespace OHOS {
namespace Notification {

inline const std::string REQUEST_STORAGE_KEY_PREFIX {"ans_live_view"};
inline const std::string REQUEST_STORAGE_SECURE_KEY_PREFIX {"secure_live_view"};

struct NotificationKey {
    int32_t id {};
    std::string label {};
};

struct LiveViewFilter {
    NotificationBundleOption bundle;
    NotificationKey notificationKey;
    std::vector<std::string> extraInfoKeys;
};

class NotificationRequest : public Parcelable, public NotificationJsonConvertionBase {
public:
    enum class BadgeStyle {
        /**
         * displays only numbers.
         */
        NONE,
        /**
         * displayed as a large icon.
         */
        BIG,
        /**
         * displayed as a small icon.
         */
        LITTLE,
        /**
         * invalid type
         * It is used as the upper limit of the enumerated value.
         */
        ILLEGAL_TYPE
    };

    enum class GroupAlertType {
        /**
         * all notifications in a group have sound or vibration if sound or vibration is enabled
         * for the associated NotificationSlot objects.
         */
        ALL,
        /**
         * child notifications have sound or vibration but the overview notification is muted (no sound or vibration)
         * in a group if sound or vibration is enabled for the associated NotificationSlot objects.
         */
        CHILD,
        /**
         * the overview notification has sound or vibration but child notifications are muted (no sound or vibration)
         * in a group if sound or vibration is enabled for the associated NotificationSlot objects.
         */
        OVERVIEW,
        /**
         * invalid type
         * It is used as the upper limit of the enumerated value.
         */
        ILLEGAL_TYPE
    };

    /**
     * Indicates the classification of notifications for alarms or timers.
     */
    static const std::string CLASSIFICATION_ALARM;
    /**
     * Indicates the classification of notifications for incoming calls or similar synchronous communication requests.
     */
    static const std::string CLASSIFICATION_CALL;
    /**
     * Indicates the classification of notifications for emails.
     */
    static const std::string CLASSIFICATION_EMAIL;
    /**
     * Indicates the classification of notifications for errors occurred during background operations or identity
     * authentication.
     */
    static const std::string CLASSIFICATION_ERROR;
    /**
     * Indicates the classification of notifications for calendar events.
     */
    static const std::string CLASSIFICATION_EVENT;
    /**
     * Indicates the classification of notifications for short messages or instant messages.
     */
    static const std::string CLASSIFICATION_MESSAGE;
    /**
     * Indicates the classification of notifications for map navigation.
     */
    static const std::string CLASSIFICATION_NAVIGATION;
    /**
     * Indicates the classification of notifications for processes that are operated in the background for a long time.
     */
    static const std::string CLASSIFICATION_PROGRESS;
    /**
     * Indicates the classification of notifications for advertisement or promotion information.
     */
    static const std::string CLASSIFICATION_PROMO;
    /**
     * Indicates the classification of notifications for specific and timely recommendations of a particular
     * transaction.
     */
    static const std::string CLASSIFICATION_RECOMMENDATION;
    /**
     * Indicates the classification of notifications for reminders previously set by the user.
     */
    static const std::string CLASSIFICATION_REMINDER;
    /**
     * Indicates the classification of notifications for ongoing background services.
     */
    static const std::string CLASSIFICATION_SERVICE;
    /**
     * Indicates the classification of notifications for social network or sharing updates.
     */
    static const std::string CLASSIFICATION_SOCIAL;
    /**
     * Indicates the classification of notifications for ongoing information about the device and contextual status.
     */
    static const std::string CLASSIFICATION_STATUS;
    /**
     * Indicates the classification of notifications for system or device status updates.
     */
    static const std::string CLASSIFICATION_SYSTEM;
    /**
     * Indicates the classification of notifications for media transport control during playback.
     */
    static const std::string CLASSIFICATION_TRANSPORT;

    /**
     * Indicates the default notification background color, which means that no color is displayed.
     */
    static const uint32_t COLOR_DEFAULT;

public:
    NotificationRequest() = default;

    /**
     * @brief A constructor used to create a NotificationRequest instance with the input parameter notificationId
     * passed.
     *
     * @param notificationId Indicates notification ID.
     */
    explicit NotificationRequest(int32_t notificationId);

    /**
     * @brief A constructor used to create a NotificationRequest instance by copying parameters from an existing one.
     *
     * @param other Indicates the existing object.
     */
    NotificationRequest(const NotificationRequest &other);

    /**
     * @brief A constructor used to create a NotificationRequest instance by copying parameters from an existing one.
     *
     * @param other Indicates the existing object.
     */
    NotificationRequest &operator=(const NotificationRequest &other);

    virtual ~NotificationRequest();

    /**
     * @brief Checks whether this notification is in progress.
     *
     * @return Returns true if this notification is in progress; returns false otherwise.
     */
    bool IsInProgress() const;

    /**
     * @brief Sets whether this notification is in progress.
     * Users cannot directly dismiss notifications in progress because
     * they usually contain some ongoing background services such as music playback.
     *
     * @param isOngoing Specifies whether this notification is in progress.
     */
    void SetInProgress(bool isOngoing);

    /**
     * @brief Checks whether this notification is unremovable.
     *
     * @return Returns true if this notification is unremovable; returns false otherwise.
     */
    bool IsUnremovable() const;

    /**
     * @brief Sets whether this notification is unremovable.
     * If it is set to be unremovable, it cannot be removed by users.
     *
     * @param isUnremovable Specifies whether this notification is unremovable.
     */
    void SetUnremovable(bool isUnremovable);

    /**
     * @brief Sets the number to be displayed for this notification.
     *
     * @param number Indicates the number to set.
     */
    void SetBadgeNumber(uint32_t number);

    /**
     * @brief Obtains the number to be displayed for this notification.
     *
     * @return Returns the number to be displayed for this notification.
     */
    uint32_t GetBadgeNumber() const;

    /**
     * @brief Sets the notification control flags for this notification.
     *
     * @param notificationControlFlags Indicates the flags to set.
     */
    void SetNotificationControlFlags(uint32_t notificationControlFlags);

    /**
     * @brief Obtains the notification control flags for this notification.
     *
     * @return Returns the notification control flags for this notification.
     */
    uint32_t GetNotificationControlFlags() const;

    /**
     * @brief Sets the current notification ID to uniquely identify the notification in the application.
     * After a notification is received, its ID is obtained by using the getNotificationId() method.
     *
     * @param notificationId Indicates the ID of the notification to be set.
     */
    void SetNotificationId(int32_t notificationId);

    /**
     * @brief Obtains the notification ID, which is unique in the current application.
     *
     * @return the notification ID.
     */
    int32_t GetNotificationId() const;

    /**
     * @brief Adds an WantAgent to this notification.
     * After a notification is tapped, subsequent operations such as ability and common events will be triggered as
     * set by WantAgent.
     *
     * @param wantAgent Indicates the operation triggered by tapping the notification, which can be set by
     * WantAgent.
     */
    void SetWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent);

    /**
     * @brief Obtains the WantAgent contained in this notification.
     *
     * @return Returns the WantAgent contained in this notification.
     */
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetWantAgent() const;

    /**
     * @brief Sets an WantAgent object that is triggered when the user explicitly removes this notification.
     *
     * @param wantAgent Indicates the WantAgent object to be triggered.
     */
    void SetRemovalWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent);

    /**
     * @brief Obtains the WantAgent object that is triggered when the user explicitly removes this notification.
     *
     * @return Returns the WantAgent object to be triggered.
     */
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetRemovalWantAgent() const;

    /**
     * @brief Sets the WantAgent to start when the device is not in use,
     * instead of showing this notification in the status bar.
     * When the device is in use, the system UI displays a pop-up notification
     * instead of starting the WantAgent specified by maxScreenWantAgent.
     * Your application must have the ohos.permission.USE_WHOLE_SCREEN permission to use this method.
     *
     * @param wantAgent Indicates the WantAgent object containing information about the to-be-started ability that
     * uses the Page template.
     */
    void SetMaxScreenWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent);

    /**
     * @brief Obtains the full-screen WantAgent set by calling setMaxScreenWantAgent(WantAgent).
     *
     * @return Returns the full-screen WantAgent.
     */
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> GetMaxScreenWantAgent() const;

    /**
     * @brief Sets extra parameters that are stored as key-value pairs for the notification.
     *
     * @param extras Indicates the WantParams object containing the extra parameters in key-value pair format.
     */
    void SetAdditionalData(const std::shared_ptr<AAFwk::WantParams> &extras);

    /**
     * @brief Obtains the WantParams object set in the notification.
     *
     * @return Returns the WantParams object.
     */
    const std::shared_ptr<AAFwk::WantParams> GetAdditionalData() const;

    /**
     * @brief Sets the time to deliver a notification.
     *
     * @param deliveryTime Indicates the time in milliseconds.
     */
    void SetDeliveryTime(int64_t deliveryTime);

    /**
     * @brief Obtains the time when a notification is delivered.
     *
     * @return Returns the time in milliseconds.
     */
    int64_t GetDeliveryTime() const;

    /**
     * @brief Checks whether the notification delivery time is displayed for this notification.
     *
     * @return Returns true if the time is displayed; returns false otherwise.
     */
    bool IsShowDeliveryTime() const;

    /**
     * @brief Sets whether to show the notification delivery time for this notification.
     * This method is valid only when the notification delivery time has been set by calling setDeliveryTime(int64_t).
     *
     * @param showDeliveryTime Specifies whether to show the notification delivery time.
     */
    void SetShowDeliveryTime(bool showDeliveryTime);

    /**
     * @brief Adds a NotificationActionButton to this notification.
     * An operation button is usually placed next to the notification content by the system.
     * Each action button must contain an icon, a title, and an WantAgent. When a notification is expanded,
     * a maximum of three action buttons can be displayed from left to right in the order they were added.
     * When the notification is collapsed, no action buttons will be displayed.
     *
     * @param actionButton Indicates the NotificationActionButton object to add.
     */
    void AddActionButton(const std::shared_ptr<NotificationActionButton> &actionButton);

    /**
     * @brief Obtains the list of all NotificationActionButton objects included in this notification.
     *
     * @return Returns the list of NotificationActionButton objects.
     */
    const std::vector<std::shared_ptr<NotificationActionButton>> GetActionButtons() const;

    /**
     * @brief Clear the list of all NotificationActionButton objects included in this notification.
     */
    void ClearActionButtons();

    /**
     * @brief Checks whether the platform is allowed to generate contextual NotificationActionButton objects for this
     * notification.
     *
     * @return Returns true if the platform is allowed to generate contextual NotificationActionButton objects;
     * returns false otherwise.
     */
    bool IsPermitSystemGeneratedContextualActionButtons() const;

    /**
     * @brief Sets whether to allow the platform to generate contextual NotificationActionButton objects for this
     * notification.
     *
     * @param permitted Specifies whether to allow the platform to generate contextual NotificationActionButton objects.
     * The default value true indicates that the platform is allowed to generate contextual action buttons,
     * and the value false indicates not.
     */
    void SetPermitSystemGeneratedContextualActionButtons(bool permitted);

    bool IsAgentNotification() const;

    void SetIsAgentNotification(bool isAgent);

    /**
     * @brief Adds a MessageUser object and associates it with this notification.
     *
     * @param messageUser Indicates the MessageUser object to add.
     */
    void AddMessageUser(const std::shared_ptr<MessageUser> &messageUser);

    /**
     * @brief Obtains all MessageUser objects associated with this notification.
     *
     * @return Returns the list of MessageUser objects associated with this notification.
     */
    const std::vector<std::shared_ptr<MessageUser>> GetMessageUsers() const;

    /**
     * @brief Checks whether this notification is set to alert only once,
     * which means that sound or vibration will no longer be played
     * for notifications with the same ID upon their updates.
     *
     * @return Returns true if this notification is set to alert only once; returns false otherwise.
     */
    bool IsAlertOneTime() const;

    /**
     * @brief Sets whether to have this notification alert only once.
     * If a notification alerts only once, sound or vibration will no longer be played
     * for notifications with the same ID upon their updates after they are published.
     *
     * @param isAlertOnce Specifies whether to have this notification alert only once.
     */
    void SetAlertOneTime(bool isAlertOnce);

    /**
     * @brief Sets the time to delete a notification.
     *
     * @param deletedTime Indicates the time in milliseconds.
     * The default value is 0, indicating that the notification will not be automatically deleted.
     * To enable the notification to be automatically deleted, set this parameter to an integer greater than 0.
     */
    void SetAutoDeletedTime(int64_t deletedTime);

    /**
     * @brief Obtains the period during which a notification is deleted.
     *
     * @return Returns the period in milliseconds.
     */
    int64_t GetAutoDeletedTime() const;

    /**
     * @brief Sets the update deadline time before deleting a notification.
     *
     * @param updateDeadLine Indicates the time in milliseconds.
     * The default value is 0, indicating that the notification will not be automatically deleted.
     * To enable the notification to be automatically deleted, set this parameter to an integer greater than 0.
     */
    void SetUpdateDeadLine(int64_t updateDeadLine);

    /**
     * @brief Obtains the time point which a notification must be updated.
     *
     * @return Returns the time point in milliseconds.
     */
    int64_t GetUpdateDeadLine() const;

    /**
     * @brief Sets the finish deadline time before deleting a notification.
     *
     * @param finishDeadLine Indicates the time in milliseconds.
     * The default value is 0, indicating that the notification will not be automatically deleted.
     * To enable the notification to be automatically deleted, set this parameter to an integer greater than 0.
     */
    void SetFinishDeadLine(int64_t finishDeadLine);

    /**
     * @brief Obtains the time point which a notification must be finished.
     *
     * @return Returns the time point in milliseconds.
     */
    int64_t GetFinishDeadLine() const;

    /**
     * @brief Sets the finish deadline time before deleting a notification.
     *
     * @param finishDeadLine Indicates the time in milliseconds.
     * The default value is 0, indicating that the notification will not be automatically deleted.
     * To enable the notification to be automatically deleted, set this parameter to an integer greater than 0.
     */
    void SetArchiveDeadLine(int64_t archiveDeadLine);

    /**
     * @brief Obtains the time point which a notification must be finished.
     *
     * @return Returns the time point in milliseconds.
     */
    int64_t GetArchiveDeadLine() const;

    /**
     * @brief Sets the little icon of the notification.
     *
     * @param littleIcon Indicates the icon of the notification.
     */
    void SetLittleIcon(const std::shared_ptr<Media::PixelMap> &littleIcon);

    /**
     * @brief Obtains the icon of the notification.
     *
     * @return Returns the notification icon.
     */
    const std::shared_ptr<Media::PixelMap> GetLittleIcon() const;

    /**
     * @brief Obtains the icon type of the notification.
     *
     * @return Returns the notification icon type
     */
    const std::string GetLittleIconType() const;

    /**
     * @brief Sets the large icon of this notification, which is usually displayed on the right of the notification.
     *
     * @param bigIcon Indicates the large icon to set. It must be a PixelMap object.
     */
    void SetBigIcon(const std::shared_ptr<Media::PixelMap> &bigIcon);

    /**
     * @brief reset the large icon of this notification, which is usually displayed on the right of the notification.
     *
     */
    void ResetBigIcon() const;

    /**
     * @brief Obtains the large icon of this notification.
     *
     * @return Returns the large icon of this notification.
     */
    const std::shared_ptr<Media::PixelMap> GetBigIcon() const;

    /**
     * @brief Sets the overlay icon of this notification.
     *
     * @param overlayIcon Indicates the overlay icon of the notification.
     */
    void SetOverlayIcon(const std::shared_ptr<Media::PixelMap> &overlayIcon);

    /**
     * @brief Obtains the overlay icon of this notification.
     *
     * @return Returns the overlay icon of this notification.
     */
    const std::shared_ptr<Media::PixelMap> GetOverlayIcon() const;

    /**
     * @brief Sets the classification of this notification, which describes the purpose of this notification.
     * Notification classifications are used to filter and sort notifications.
     *
     * @param classification Indicates the notification classification predefined in the system,
     * such as CLASSIFICATION_CALL or CLASSIFICATION_NAVIGATION etc.
     */
    void SetClassification(const std::string &classification);

    /**
     * @brief Obtains the classification of this notification.
     *
     * @return Returns the classification of this notification.
     */
    std::string GetClassification() const;

    /**
     * @brief Sets the background color of this notification.
     * This method is valid only when background color has been enabled by calling setColorEnabled(bool).
     *
     * @param color Indicates the background color to set. For details about the value range, see Color.
     */
    void SetColor(uint32_t color);

    /**
     * @brief Obtains the background color of this notification.
     * The return value, except for the default color COLOR_DEFAULT,
     * is the bitwise OR operation result of 0xFF000000 and the ARGB value set by setColor(uint32_t).
     *
     * @return Returns the background color of this notification.
     */
    uint32_t GetColor() const;

    /**
     * @brief Checks whether background color is enabled for this notification.
     *
     * @return Returns true if background color is enabled; returns false otherwise.
     */
    bool IsColorEnabled() const;

    /**
     * @brief Sets whether to enable background color for this notification.
     * If colorEnabled is set to true, this method takes effect only
     * when the notification content type has been set to NotificationRequest.
     * NotificationMediaContent in the NotificationRequest object through
     * NotificationRequest::setContent(NotificationContent) and an AVToken has been attached to
     * that NotificationMediaContent object through NotificationMediaContent::setAVToken(AVToken).
     *
     * @param colorEnabled Specifies whether to enable background color.
     */
    void SetColorEnabled(bool colorEnabled);

    /**
     * @brief Sets the notification content type to NotificationNormalContent, NotificationLongTextContent,
     * or NotificationPictureContent etc.
     * Each content type indicates a particular notification content.
     *
     * @param content Indicates the notification content type.
     */
    void SetContent(const std::shared_ptr<NotificationContent> &content);

    /**
     * @brief Obtains the notification content set by calling the setContent(NotificationContent) method.
     *
     * @return Returns the notification content.
     */
    const std::shared_ptr<NotificationContent> GetContent() const;

    /**
     * @brief Obtains the notification type.
     *
     * @return Returns the type of the current notification, which can be
     * NotificationContent::Type::BASIC_TEXT,
     * NotificationContent::Type::LONG_TEXT,
     * NotificationContent::Type::PICTURE,
     * NotificationContent::Type::CONVERSATION,
     * NotificationContent::Type::MULTILINE,
     * NotificationContent::Type::MEDIA,
     * or NotificationContent::Type::LIVE_VIEW
     */
    NotificationContent::Type GetNotificationType() const;

    /**
     * @brief Checks whether the notification creation time is displayed as a countdown timer.
     *
     * @return Returns true if the time is displayed as a countdown timer; returns false otherwise.
     */
    bool IsCountdownTimer() const;

    /**
     * @brief Sets whether to show the notification creation time as a countdown timer.
     * This method is valid only when setShowStopwatch(boolean) is set to true.
     *
     * @param isCountDown Specifies whether to show the notification creation time as a countdown timer.
     */
    void SetCountdownTimer(bool isCountDown);

    /**
     * @brief Sets the group alert type for this notification,
     * which determines how the group overview and other notifications in a group are published.
     * The group information must have been set by calling setGroupValue(string).
     * Otherwise, this method does not take effect.
     *
     * @param type Indicates the group alert type to set. which can be GroupAlertType::ALL (default value),
     * GroupAlertType::OVERVIEW, or GroupAlertType::CHILD etc.
     */
    void SetGroupAlertType(NotificationRequest::GroupAlertType type);

    /**
     * @brief Obtains the group alert type of this notification.
     *
     * @return Returns the group alert type of this notification.
     */
    NotificationRequest::GroupAlertType GetGroupAlertType() const;

    /**
     * @brief Checks whether this notification is the group overview.
     *
     * @return Returns true if this notification is the group overview; returns false otherwise.
     */
    bool IsGroupOverview() const;

    /**
     * @brief Sets whether to use this notification as the overview of its group.
     * This method helps display the notifications that are assigned the same group name by calling
     * setGroupName(string) as one stack in the notification bar.
     * Each group requires only one group overview. After a notification is set as the group overview,
     * it becomes invisible if another notification in the same group is published.
     *
     * @param overView Specifies whether to set this notification as the group overview.
     */
    void SetGroupOverview(bool overView);

    /**
     * @brief Sets the group information for this notification.
     * If no groups are set for notifications, all notifications from the same application will appear
     * in the notification bar as one stack with the number of stacked notifications displayed.
     * If notifications are grouped and there are multiple groups identified by different groupName,
     * notifications with different groupName will appear in separate stacks.
     * Note that one of the notifications in a group must be set as the overview of its group by calling
     * setGroupOverview(bool), and other notifications are considered as child notifications.
     * Otherwise, notifications will not be displayed as one group even if they are assigned the same groupName by
     * calling setGroupName(string).
     *
     * @param groupName Specifies whether to set this notification as the group overview.
     */
    void SetGroupName(const std::string &groupName);

    /**
     * @brief Obtains the group information about this notification.
     *
     * @return Returns the group information about this notification.
     */
    std::string GetGroupName() const;

    /**
     * @brief Checks whether this notification is relevant only to the local device and cannot be displayed on remote
     * devices.
     *
     * @return Returns true if this notification is relevant only to the local device; returns false otherwise.
     */
    bool IsOnlyLocal() const;

    /**
     * @brief Sets whether this notification is relevant only to the local device and cannot be displayed on remote
     * devices.This method takes effect only for notifications published by calling
     * NotificationHelper::publishNotification(NotificationRequest) or
     * NotificationHelper#publishNotification(string, NotificationRequest).
     * Notifications published using NotificationHelper::publishNotification(NotificationRequest, string)
     * in a distributed system will not be affected.
     *
     * @param flag Specifies whether this notification can be displayed only on the local device.
     */
    void SetOnlyLocal(bool flag);

    /**
     * @brief Sets the text that will be displayed as a link to the settings of the application.
     * Calling this method is invalid if the notification content type has been set to NotificationLongTextContent
     * or NotificationPictureContent in the NotificationRequest object through setContent(NotificationContent).
     *
     * @param text Indicates the text to be included. You can set it to any valid link.
     */
    void SetSettingsText(const std::string &text);

    /**
     * @brief Obtains the text that will be displayed as a link to the settings of the application.
     *
     * @return Returns the text displayed as the link to the application settings.
     */
    std::string GetSettingsText() const;

    /**
     * @brief Deprecated. Obtains the time when a notification is created.
     *
     * @return Returns the time in milliseconds.
     */
    int64_t GetCreateTime() const;

    /**
     * @brief Sets the time to create a notification.
     *
     * @param createTime Indicates the time in milliseconds.
     */
    void SetCreateTime(int64_t createTime);

    /**
     * @brief Checks whether the notification creation time is displayed as a stopwatch.
     *
     * @return Returns true if the time is displayed as a stopwatch; returns false otherwise.
     */
    bool IsShowStopwatch() const;

    /**
     * @brief Sets whether to show the notification creation time as a stopwatch.
     * This method is valid only when the notification creation time has been set by calling setDeliveryTime(int64_t).
     * When the notification creation time is set to be shown as a stopwatch, the interval between the current time
     * and the creation time set by setDeliveryTime(int64_t) is dynamically displayed for this notification
     * in Minutes: Seconds format. If the interval is longer than 60 minutes, it will be displayed
     * in Hours: Minutes: Seconds format. If this method and setShowDeliveryTime(boolean) are both set to true, only
     * this method takes effect, that is, the notification creation time will be shown as a stopwatch.
     *
     * @param isShow Specifies whether to show the notification creation time as a stopwatch.
     */
    void SetShowStopwatch(bool isShow);

    /**
     * @brief Sets the slot type of a notification to bind the created NotificationSlot object.
     * You can use NotificationSlot to create a slot object,
     * then set the notification vibration and lock screen display, and use the current method to bind the slot.
     * The value must be the type of an existing NotificationSlot object.
     *
     * @param slotType Indicates the unique type of the NotificationSlot object.
     */
    void SetSlotType(NotificationConstant::SlotType slotType);

    /**
     * @brief Obtains the slot type of a notification set by calling the setSlotType(string) method.
     *
     * @return Returns the notification slot type.
     */
    NotificationConstant::SlotType GetSlotType() const;

    /**
     * @brief Sets a key used for sorting notifications from the same application bundle.
     *
     * @param key Indicates the key to set.
     */
    void SetSortingKey(const std::string &key);

    /**
     * @brief Obtains the key used for sorting notifications from the same application bundle.
     *
     * @return Returns the key for sorting notifications.
     */
    std::string GetSortingKey() const;

    /**
     * @brief Sets the scrolling text to be displayed in the status bar when this notification is received.
     *
     * @param text Indicates the scrolling text to be displayed.
     */
    void SetStatusBarText(const std::string &text);

    /**
     * @brief Obtains the scrolling text that will be displayed in the status bar when this notification is received.
     *
     * @return Returns the scrolling notification text.
     */
    std::string GetStatusBarText() const;

    /**
     * @brief Checks whether the current notification will be automatically dismissed after being tapped.
     *
     * @return Returns true if the notification will be automatically dismissed; returns false otherwise.
     */
    bool IsTapDismissed() const;

    /**
     * @brief Sets whether to automatically dismiss a notification after being tapped.
     * If you set tapDismissed to true,
     * you must call the setWantAgent(WantAgent) method to make the settings take effect.
     *
     * @param isDismissed Specifies whether a notification will be automatically dismissed after being tapped.
     */
    void SetTapDismissed(bool isDismissed);

    /**
     * @brief Sets the notification display effect, including whether to display this notification on the lock screen,
     * and how it will be presented if displayed.
     * For details, see NotificationSlot::setLockscreenVisibleness(int).
     * If the lock screen display effect is set for a NotificationRequest object
     * and its associated NotificationSlot object, the display effect set in the NotificationRequest object prevails.
     *
     * @param type Indicates the notification display effect on the lock screen.
     */
    void SetVisibleness(NotificationConstant::VisiblenessType type);

    /**
     * @brief Obtains the display effect of this notification on the lock screen.
     *
     * @return Returns the display effect of this notification on the lock screen.
     */
    NotificationConstant::VisiblenessType GetVisibleness() const;

    /**
     * @brief Sets the badge icon style for this notification.
     * This method does not take effect if the home screen does not support badge icons.
     *
     * @param style Indicates the type of the badge icon to be displayed for this notification.
     * The value must be BadgeStyle::NONE, BadgeStyle::LITTLE, or BadgeStyle::BIG.
     */
    void SetBadgeIconStyle(NotificationRequest::BadgeStyle style);

    /**
     * @brief Obtains the badge icon style of this notification.
     *
     * @return Returns the badge icon style of this notification.
     */
    NotificationRequest::BadgeStyle GetBadgeIconStyle() const;

    /**
     * @brief Sets the shortcut ID for this notification.
     * After a shortcut ID is set for a notification, the notification will be associated with the corresponding
     * home-screen shortcut, and the shortcut will be hidden when the Home application displays the badge or content
     * of the notification.
     *
     * @param shortcutId Indicates the shortcut ID to set.
     */
    void SetShortcutId(const std::string &shortcutId);

    /**
     * @brief Obtains the shortcut ID associated with this notification.
     *
     * @return Returns the shortcut ID of this notification.
     */
    std::string GetShortcutId() const;

    /**
     * @brief Sets whether this notification is displayed as a floating icon on top of the screen.
     *
     * @param floatingIcon Specifies whether a notification is displayed as a floating icon on top of the screen.
     */
    void SetFloatingIcon(bool floatingIcon);

    /**
     * @brief Checks whether this notification is displayed as a floating icon on top of the screen.
     *
     * @return Returns true if this notification is displayed as a floating icon; returns false otherwise.
     */
    bool IsFloatingIcon() const;

    /**
     * @brief Sets how the progress bar will be displayed for this notification.
     * A progress bar is usually used in notification scenarios such as download.
     *
     * @param progress Indicates the current value displayed for the notification progress bar.
     * @param progressMax Indicates the maximum value displayed for the notification progress bar.
     * @param indeterminate Specifies whether the progress bar is indeterminate. The value true indicates that
     * the progress bar is indeterminate, and users cannot see its current and maximum values.
     */
    void SetProgressBar(int32_t progress, int32_t progressMax, bool indeterminate);

    /**
     * @brief Obtains the maximum value displayed for the progress bar of this notification.
     *
     * @return Returns the maximum value of the notification progress bar.
     */
    int32_t GetProgressMax() const;

    /**
     * @brief Obtains the current value displayed for the progress bar of this notification.
     *
     * @return Returns the current value of the notification progress bar.
     */
    int32_t GetProgressValue() const;

    /**
     * @brief Checks whether the progress bar of this notification is indeterminate.
     *
     * @return Returns true if the notification progress bar is indeterminate; returns false otherwise.
     */
    bool IsProgressIndeterminate() const;

    /**
     * @brief Sets the most recent NotificationUserInput records that have been sent through this notification.
     * The most recent input must be stored in index 0,
     * the second most recent input must be stored in index 1, and so on.
     * The system displays a maximum of five inputs.
     *
     * @param text Indicates the list of inputs to set.
     */
    void SetNotificationUserInputHistory(const std::vector<std::string> &text);

    /**
     * @brief Obtains the most recent NotificationUserInput records.
     *
     * @return Returns the most recent NotificationUserInput records.
     */
    std::vector<std::string> GetNotificationUserInputHistory() const;

    /**
     * @brief Obtains the unique hash code of a notification in the current application.
     * To obtain a valid hash code, you must have subscribed to and received the notification.
     * A valid notification hash code is a string composed of multiple attributes separated by an underscore (_),
     * including the notification ID, creator bundle name, creator UID, and owner bundle name.
     *
     * @return Returns the hash code of the notification.
     */
    std::string GetNotificationHashCode() const;

    /**
     * @brief Sets the bundle name of the notification owner.
     * The notification owner refers to the application that subscribes to the notification.
     *
     * @param ownerName Indicates the bundle name of the notification owner.
     */
    void SetOwnerBundleName(const std::string &ownerName);

    /**
     * @brief Obtains the bundle name of the notification owner.
     * The notification owner refers to the application that subscribes to the notification.
     *
     * @return Returns the bundle name of the notification owner.
     */
    std::string GetOwnerBundleName() const;

    /**
     * @brief Sets the bundle name of the notification creator.
     * The notification creator refers to the application that publishes the notification.
     *
     * @param creatorName Indicates the bundle name of the notification creator.
     */
    void SetCreatorBundleName(const std::string &creatorName);

    /**
     * @brief Obtains the bundle name of the notification creator.
     * The notification creator refers to the application that publishes the notification.
     *
     * @return Returns the bundle name of the notification creator.
     */
    std::string GetCreatorBundleName() const;

    /**
     * @brief Sets the PID of the notification creator.
     *
     * @param pid Indicates the PID of the notification creator.
     */
    void SetCreatorPid(pid_t pid);

    /**
     * @brief Obtains the PID of the notification creator.
     *
     * @return Returns the PID of the notification creator.
     */
    pid_t GetCreatorPid() const;

    /**
     * @brief Sets the UID of the notification creator.
     *
     * @param uid Indicates the UID of the notification creator.
     */
    void SetCreatorUid(int32_t uid);

    /**
     * @brief Obtains the UID of the notification creator.
     *
     * @return Returns the UID of the notification creator.
     */
    int32_t GetCreatorUid() const;

    /**
     * @brief Sets the UID of the notification owner.
     *
     * @param uid the UID of the notification owner.
     */
    void SetOwnerUid(int32_t uid);

    /**
     * @brief Obtains the UID of the notification owner.
     *
     * @return the UID of the notification owner.
     */
    int32_t GetOwnerUid() const;

    /**
     * @brief Sets the label of this notification.
     *
     * @param label Indicates the label of this notification.
     */
    void SetLabel(const std::string &label);

    /**
     * @brief Obtains the label of this notification.
     * The label is set via NotificationHelper::publishNotification(string, NotificationRequest).
     * This method returns null if no specific label is set for this notification.
     *
     * @return Returns the label of this notification.
     */
    std::string GetLabel() const;

    /**
     * @brief Sets whether this notification is distributed.
     *
     * @param distribute Specifies whether a notification is displayed as a floating icon on top of the screen.
     */
    void SetDistributed(bool distribute);

    /**
     * @brief Sets devices that support display.
     *
     * @param devices Indicates the devices that support display.
     */
    void SetDevicesSupportDisplay(const std::vector<std::string> &devices);

    /**
     * @brief Sets devices that support operate.
     *
     * @param devices Indicates the devices that support operate.
     */
    void SetDevicesSupportOperate(const std::vector<std::string> &devices);

    /**
     * @brief Obtains the distributed Options.
     *
     * @return Returns the distributed Options.
     */
    NotificationDistributedOptions GetNotificationDistributedOptions() const;

    /**
     * @brief Sets the UserId of the notification creator.
     *
     * @param userId Indicates the UserId of the notification creator.
     */
    void SetCreatorUserId(int32_t userId);

    /**
     * @brief Obtains the UserId of the notification creator.
     *
     * @return Returns the UserId of the notification creator.
     */
    int32_t GetCreatorUserId() const;

    /**
     * @brief Sets the InstanceKey of the notification creator.
     *
     * @param key Indicates the InstanceKey of the notification creator.
     */
    void SetCreatorInstanceKey(int32_t key);

    /**
     * @brief Obtains the InstanceKey of the notification creator.
     *
     * @return Returns the InstanceKey of the notification creator.
     */
    int32_t GetCreatorInstanceKey() const;

    /**
     * @brief Sets the InstanceKey of the notification creator.
     *
     * @param key Indicates the InstanceKey of the notification creator.
     */
    void SetAppInstanceKey(const std::string &key);
 
    /**
     * @brief Obtains the InstanceKey of the notification creator.
     *
     * @return Returns the InstanceKey of the notification creator.
     */
    std::string GetAppInstanceKey() const;

    /**
     * @brief Sets the UserId of the notification owner.
     *
     * @param userId the UserId of the notification owner.
     */
    void SetOwnerUserId(int32_t userId);

    /**
     * @brief Obtains the UserId of the notification owner.
     *
     * @return the UserId of the notification owner.
     */
    int32_t GetOwnerUserId() const;

    /**
     * @brief Returns a string representation of the object.
     *
     * @return Returns a string representation of the object.
     */
    std::string Dump();

    /**
     * @brief Converts a NotificationRequest object into a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ToJson(nlohmann::json &jsonObject) const override;

    /**
     * @brief Creates a NotificationRequest object from a Json.
     *
     * @param jsonObject Indicates the Json object.
     * @return Returns the NotificationRequest.
     */
    static NotificationRequest *FromJson(const nlohmann::json &jsonObject);

    /**
     * @brief Marshal a NotificationRequest object into a Parcel.
     *
     * @param parcel Indicates the object into the parcel.
     * @return Returns true if succeed; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns the NotificationRequest.
     */
    static NotificationRequest *Unmarshalling(Parcel &parcel);

    /**
     * @brief Sets the template of this notification.
     *
     * @param template Indicates the template of this notification.
     */
    void SetTemplate(const std::shared_ptr<NotificationTemplate> &templ);

    /**
     * @brief Obtains the Template of the notification.
     *
     * @return Returns the Template of the notification.
     */
    std::shared_ptr<NotificationTemplate> GetTemplate() const;

    /**
     * @brief Sets the flags of this notification.
     *
     * @param flags Indicates the flags of this notification.
     */
    void SetFlags(const std::shared_ptr<NotificationFlags> &flags);

    /**
     * @brief Obtains the flags of the notification.
     *
     * @return Returns the flags of the notification.
     */
    std::shared_ptr<NotificationFlags> GetFlags() const;

     /**
     * @brief Sets the flags of this notification and device.
     *
     * @param flags Indicates the flags of this notification and device.
     */
    void SetDeviceFlags(const std::shared_ptr<std::map<std::string, std::shared_ptr<NotificationFlags>>> &mapFlags);

    /**
     * @brief Obtains the flags of the notification and device.
     *
     * @return Returns the flags of the notification and device.
     */
    std::shared_ptr<std::map<std::string, std::shared_ptr<NotificationFlags>>> GetDeviceFlags() const;

    /**
     * @brief Sets the userId of the notification receiver.
     *
     * @param userId Indicates the userId of the notification receiver.
     */
    void SetReceiverUserId(int32_t userId);

    /**
     * @brief Obtains the userId of the notification receiver.
     *
     * @return Returns the userId of the notification receiver.
     */
    int32_t GetReceiverUserId() const;

    bool IsRemoveAllowed() const;

    void SetRemoveAllowed(bool isRemoveAllowed);

    bool IsForceDistributed() const;

    void SetForceDistributed(bool forceDistributed);

    bool IsNotDistributed() const;

    void SetNotDistributed(bool notDistributed);

    bool IsSystemApp() const;

    void SetIsSystemApp(bool isSystemApp);

    bool IsCommonLiveView() const;

    bool IsSystemLiveView() const;

    /**
     * @brief Checks whether the image size exceeds the limit in content.
     *
     * @param pixelMap Indicates the image smart pointer.
     * @param maxSize The max size of image.
     * @return Returns the ErrCode.
     */
    static bool CheckImageOverSizeForPixelMap(const std::shared_ptr<Media::PixelMap> &pixelMap, uint32_t maxSize);

    /**
     * @brief Checks whether the picture size exceeds the limit in content.
     *
     * @param request Indicates the specified request.
     * @return Returns the ErrCode.
     */
    ErrCode CheckNotificationRequest(const sptr<NotificationRequest> &oldRequest) const;

    /**
     * @brief Fill missing parameters of the current notification request.
     *
     * @param oldRequest Indicates the old request.
     */
    void FillMissingParameters(const sptr<NotificationRequest> &oldRequest);

    /**
     * @brief Get notification request key.
     *
     * @return Return the unique key of notification request.
     */
    std::string GetKey();

    /**
     * @brief Get notification request key.
     *
     * @return Return the unique key of notification request.
     */
    std::string GetSecureKey();

    /**
     * @brief Get notification request base key.
     *
     * @return Return the base key of notification request.
     */
    std::string GetBaseKey(const std::string &deviceId);

    /**
     * @brief Check the image size in content.
     *
     * @return Return the check result, ERR_OK: check pass, others: not pass.
     */
    ErrCode CheckImageSizeForContent() const;

    /**
     * @brief Set notification isCoverActionButtons value.
     *
     * @param isCoverActionButtons the value of isCoverActionButtons.
     */
    void SetIsCoverActionButtons(bool isCoverActionButtons);

    /**
     * @brief Get notification isCoverActionButtons value.
     *
     * @return Return the value of isCoverActionButtons.
     */
    bool IsCoverActionButtons() const;

    /**
     * @brief Sets the bundleOption of this notification.
     *
     * @param bundleOption Indicates the bundleOption of this notification.
     */
    void SetBundleOption(const std::shared_ptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Obtains the bundleOption of the notification.
     *
     * @return Returns the bundleOption of the notification.
     */
    std::shared_ptr<NotificationBundleOption> GetBundleOption() const;

    /**
     * @brief Sets the agentBundle of this notification.
     *
     * @param bundleOption Indicates the agentBundle of this notification.
     */
    void SetAgentBundle(const std::shared_ptr<NotificationBundleOption> &agentBundle);

    /**
     * @brief Obtains the agentBundle of the notification.
     *
     * @return Returns the agentBundle of the notification.
     */
    std::shared_ptr<NotificationBundleOption> GetAgentBundle() const;

    /**
     * @brief Set notification appMessageId value.
     *
     * @param appMessageId the value of appMessageId.
     */
    void SetAppMessageId(const std::string &appMessageId);

    /**
     * @brief Get notification appMessageId value.
     *
     * @return Return the value of appMessageId.
     */
    std::string GetAppMessageId() const;

    /**
     * @brief Set notification sound value.
     *
     * @param sound the value of sound.
     */
    void SetSound(const std::string &sound);

    /**
     * @brief Get notification sound value.
     *
     * @return Return the value of sound.
     */
    std::string GetSound() const;

    /**
     * @brief Generate notification request unique key.
     *
     * @return Return the unique key of notification request.
     */
    std::string GenerateUniqueKey();

    /**
     * @brief Sets the unifiedGroupInfo of this notification.
     *
     * @param flags Indicates the unifiedGroupInfo of this notification.
     */
    void SetUnifiedGroupInfo(const std::shared_ptr<NotificationUnifiedGroupInfo> &unifiedGroupInfo);

    /**
     * @brief Obtains the unifiedGroupInfo of the notification.
     *
     * @return Returns the unifiedGroupInfo of the notification.
     */
    std::shared_ptr<NotificationUnifiedGroupInfo> GetUnifiedGroupInfo() const;

    /**
     * @brief Sets the delay time of this notification.
     *
     * @param delayTime Indicates the delay time of this notification.
     */
    void SetPublishDelayTime(uint32_t delayTime);

    /**
     * @brief Obtains the delay time of the notification.
     *
     * @return Returns the delay time of the notification.
     */
    uint32_t GetPublishDelayTime() const;

    /**
     * @brief Set notification isUpdateByOwnerAllowed value.
     *
     * @param isUpdateByOwnerAllowed Indicates the isUpdateByOwnerAllowed value of this notification.
     */
    void SetUpdateByOwnerAllowed(bool isUpdateByOwnerAllowed);

    /**
     * @brief Obtains the value of isUpdateByOwnerAllowed.
     *
     * @return Returns the isUpdateByOwnerAllowed value of the notification.
     */
    bool IsUpdateByOwnerAllowed() const;

    /**
     * @brief Set notification updateOnly value.
     *
     * @param updateOnly Indicates the updateOnly value of this notification.
     */
    void SetUpdateOnly(bool updateOnly);

    /**
     * @brief Obtains the value of updateOnly.
     *
     * @return Returns the updateOnly value of the notification.
     */
    bool IsUpdateOnly() const;

    bool GetDistributedCollaborate() const;

    void SetDistributedCollaborate(bool distributedCollaborate);

    const std::string GetDistributedHashCode() const;

    void SetDistributedHashCode(const std::string hashCode);

    bool HasUserInputButton();

    void AdddeviceStatu(const std::string &deviceType, const std::string deviceStatu);
    
    const std::map<std::string, std::string> GetdeviceStatus() const;

    void SetHashCodeGenerateType(uint32_t type);

    uint32_t GetHashCodeGenerateType() const;

private:
    /**
     * Indicates the color mask, used for calculation with the ARGB value set by setColor(int32_t).
     */
    static const uint32_t COLOR_MASK;

    /**
     * the maximum number of user input history is 5.
     */
    static const std::size_t MAX_USER_INPUT_HISTORY;

    /**
     * the maximum number of action buttons is 3.
     */
    static const std::size_t MAX_ACTION_BUTTONS;

    /**
     * the maximum number of message users is 1000.
     */
    static const std::size_t MAX_MESSAGE_USERS;

private:
    /**
     * @brief Read a NotificationRequest object from a Parcel.
     *
     * @param parcel Indicates the parcel object.
     * @return Returns true if succeed; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel);

    /**
     * @brief Obtains the current system time in milliseconds.
     *
     * @return Returns the current system time in milliseconds.
     */
    int64_t GetNowSysTime();

    void CopyBase(const NotificationRequest &other);
    void CopyOther(const NotificationRequest &other);

    bool ConvertObjectsToJson(nlohmann::json &jsonObject) const;
    ErrCode CheckVersion(const sptr<NotificationRequest> &oldRequest) const;

    static void ConvertJsonToNum(NotificationRequest *target, const nlohmann::json &jsonObject);
    static void ConvertJsonToNumExt(NotificationRequest *target, const nlohmann::json &jsonObject);
    static void ConvertJsonToString(NotificationRequest *target, const nlohmann::json &jsonObject);
    static void ConvertJsonToEnum(NotificationRequest *target, const nlohmann::json &jsonObject);
    static void ConvertJsonToBool(NotificationRequest *target, const nlohmann::json &jsonObject);
    static void ConvertJsonToBoolExt(NotificationRequest *target, const nlohmann::json &jsonObject);
    static void ConvertJsonToPixelMap(NotificationRequest *target, const nlohmann::json &jsonObject);
    static bool ConvertJsonToNotificationContent(NotificationRequest *target, const nlohmann::json &jsonObject);
    static bool ConvertJsonToNotificationActionButton(NotificationRequest *target, const nlohmann::json &jsonObject);
    static bool ConvertJsonToNotificationDistributedOptions(
        NotificationRequest *target, const nlohmann::json &jsonObject);
    static bool ConvertJsonToNotificationFlags(NotificationRequest *target, const nlohmann::json &jsonObject);
    static ErrCode CheckImageSizeForConverSation(std::shared_ptr<NotificationBasicContent> &content);
    static ErrCode CheckImageSizeForPicture(std::shared_ptr<NotificationBasicContent> &content);
    static ErrCode CheckImageSizeForLiveView(std::shared_ptr<NotificationBasicContent> &content);
    static bool ConvertJsonToNotificationBundleOption(NotificationRequest *target, const nlohmann::json &jsonObject);
    static bool ConvertJsonToAgentBundle(NotificationRequest *target, const nlohmann::json &jsonObject);
    static ErrCode CheckLockScreenPictureSizeForLiveView(std::shared_ptr<NotificationBasicContent> &content);

private:
    int32_t notificationId_ {0};
    uint32_t color_ {NotificationRequest::COLOR_DEFAULT};
    uint32_t badgeNumber_ {0};
    uint32_t notificationControlFlags_ {0};
    int32_t progressValue_ {0};
    int32_t progressMax_ {0};
    int64_t createTime_ {0};
    int64_t deliveryTime_ {0};

    int64_t autoDeletedTime_ {NotificationConstant::INVALID_AUTO_DELETE_TIME};
    int64_t updateDeadLine_ {0};
    int64_t finishDeadLine_ {0};
    int64_t archiveDeadLine_ {0};
    pid_t creatorPid_ {0};
    int32_t creatorUid_ {DEFAULT_UID};
    int32_t ownerUid_ {DEFAULT_UID};
    int32_t creatorUserId_ {SUBSCRIBE_USER_INIT};
    int32_t ownerUserId_ {SUBSCRIBE_USER_INIT};
    int32_t receiverUserId_ {SUBSCRIBE_USER_INIT};
    int32_t creatorInstanceKey_ {DEFAULT_UID};
    uint32_t hashCodeGenerateType_ {0};

    std::string appInstanceKey_ {};
    std::string settingsText_ {};
    std::string creatorBundleName_ {};
    std::string ownerBundleName_ {};
    std::string groupName_ {};
    std::string statusBarText_ {};
    std::string label_ {};
    std::string shortcutId_ {};
    std::string sortingKey_ {};
    std::string classification_ {};
    std::string appMessageId_ {};
    std::string sound_ {};
    std::string distributedHashCode_ {};
    std::map<std::string, std::string> deviceStatus_ {};

    NotificationConstant::SlotType slotType_ {NotificationConstant::SlotType::OTHER};
    NotificationRequest::GroupAlertType groupAlertType_ {NotificationRequest::GroupAlertType::ALL};
    NotificationConstant::VisiblenessType visiblenessType_ {NotificationConstant::VisiblenessType::NO_OVERRIDE};
    NotificationRequest::BadgeStyle badgeStyle_ {NotificationRequest::BadgeStyle::NONE};
    NotificationContent::Type notificationContentType_ {NotificationContent::Type::NONE};

    bool showDeliveryTime_ {false};
    bool tapDismissed_ {true};
    bool colorEnabled_ {false};
    bool alertOneTime_ {false};
    bool showStopwatch_ {false};
    bool isCountdown_ {false};
    bool inProgress_ {false};
    bool groupOverview_ {false};
    bool progressIndeterminate_ {false};
    bool unremovable_ {false};
    bool floatingIcon_ {false};
    bool onlyLocal_ {false};
    bool permitted_ {true};
    bool isAgent_ {false};
    bool isRemoveAllowed_ {true};
    bool isCoverActionButtons_ {false};
    bool isUpdateByOwnerAllowed_ {false};
    bool distributedCollaborate_ {false};
    bool updateOnly_ {false};
    bool forceDistributed_ {false};
    bool notDistributed_ {false};
    bool isSystemApp_ {false};

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent_ {};
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> removalWantAgent_ {};
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> maxScreenWantAgent_ {};
    std::shared_ptr<AAFwk::WantParams> additionalParams_ {};
    std::shared_ptr<Media::PixelMap> littleIcon_ {};
    std::string littleIconType_ {};
    mutable std::shared_ptr<Media::PixelMap> bigIcon_ {};
    std::shared_ptr<Media::PixelMap> overlayIcon_ {};
    std::shared_ptr<NotificationContent> notificationContent_ {};

    std::vector<std::shared_ptr<NotificationActionButton>> actionButtons_ {};
    std::vector<std::shared_ptr<MessageUser>> messageUsers_ {};
    std::vector<std::string> userInputHistory_ {};

    NotificationDistributedOptions distributedOptions_;

    std::shared_ptr<NotificationTemplate> notificationTemplate_ {};
    std::shared_ptr<NotificationFlags> notificationFlags_ {};
    std::shared_ptr<NotificationBundleOption> notificationBundleOption_ {};
    std::shared_ptr<NotificationBundleOption> agentBundle_ {};
    std::shared_ptr<NotificationUnifiedGroupInfo> unifiedGroupInfo_ {};
    std::shared_ptr<std::map<std::string, std::shared_ptr<NotificationFlags>>> notificationFlagsOfDevices_ {};

    uint32_t publishDelayTime_ {0};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_REQUEST_H
