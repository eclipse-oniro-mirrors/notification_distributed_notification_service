/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_H

#include <map>
#include <string>

#include "notification_constant.h"
#include "notification_request.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {

#define READ_STRING_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadString(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);             \
        return false;                                    \
    }                                                    \

#define READ_BOOL_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadBool(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);           \
        return false;                                  \
    }                                                  \

#define READ_INT64_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadInt64(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);            \
        return false;                                   \
    }                                                   \

#define READ_INT32_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadInt32(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);            \
        return false;                                   \
    }                                                   \

#define READ_UINT64_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadUint64(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);             \
        return false;                                    \
    }                                                    \

#define READ_UINT32_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadUint32(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);             \
        return false;                                    \
    }                                                    \

#define READ_UINT16_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadUint16(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);             \
        return false;                                    \
    }                                                    \

#define READ_UINT8_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).ReadUint8(value))) {                 \
        ANSR_LOGE("Failed to read %s", msg);            \
        return false;                                   \
    }                                                   \

#define WRITE_STRING_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteString(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);             \
        return false;                                     \
    }                                                     \

#define WRITE_BOOL_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteBool(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);           \
        return false;                                   \
    }                                                   \

#define WRITE_INT64_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteInt64(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);            \
        return false;                                    \
    }                                                    \

#define WRITE_INT32_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteInt32(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);            \
        return false;                                    \
    }                                                    \

#define WRITE_UINT64_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteUint64(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);             \
        return false;                                     \
    }                                                     \

#define WRITE_UINT32_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteUint32(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);             \
        return false;                                     \
    }                                                     \

#define WRITE_UINT16_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteUint16(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);             \
        return false;                                     \
    }                                                     \

#define WRITE_UINT8_RETURN_FALSE_LOG(parcel, value, msg) \
    if (!((parcel).WriteUint8(value))) {                 \
        ANSR_LOGE("Failed to write %s", msg);            \
        return false;                                    \
    }                                                    \

class ReminderRequest : public Parcelable {
public:
    /**
     * @brief Supported reminder type.
     */
    enum class ReminderType : uint8_t {
        /**
         * Indicates the classification of reminder for timer.
         */
        TIMER,

        /**
         * Indicates the classification of reminder for calendar.
         */
        CALENDAR,

        /**
         * Indicates the classification of reminder for alarm.
         */
        ALARM,
        INVALID
    };

    /**
     * @brief Supported action button type.
     */
    enum class ActionButtonType : uint8_t {
        /**
         * @brief Indicates that this action button is used to close reminder's notification.
         * It always works well, whether the application is running at the time.
         *
         */
        CLOSE,

        /**
         * @brief Indicates that this action button is used to snooze reminder.
         * It always work well, whether the application is running at the time.
         *
         */
        SNOOZE,

        /**
         * @brief Indicates that this action button is custom.
         *
         */
        CUSTOM,
        INVALID
    };

    /**
     * @brief Supported notification update type.
     */
    enum class UpdateNotificationType : uint8_t {
        COMMON,
        REMOVAL_WANT_AGENT,
        WANT_AGENT,
        MAX_SCREEN_WANT_AGENT,
        BUNDLE_INFO,
        CONTENT
    };

    /**
     * @brief Enumerates the Time type for converting between c time and acture time.
     */
    enum class TimeTransferType : uint8_t {
        YEAR,
        MONTH,
        WEEK
    };

    /**
     * @brief Enumerates the Time format for print.
     */
    enum class TimeFormat : uint8_t {
        YMDHMS,
        HM
    };

    /**
     * @brief audio stream type
     */
    enum class RingChannel : uint8_t {
        ALARM,
        MEDIA,
    };

    struct ButtonWantAgent {
        std::string pkgName = "";
        std::string abilityName = "";
    };

    struct ButtonDataShareUpdate {
        std::string uri = "";
        std::string equalTo = "";
        std::string valuesBucket = "";
    };
    /**
     * @brief Attributes of action button.
     */
    struct ActionButtonInfo {
        /**
         * Type of the button.
         */
        ActionButtonType type;

        /**
         * Content show on the button.
         */
        std::string title = "";

        /**
         * resource key(for language)
         */
        std::string resource = "";

        /**
         * The ability that is redirected to when the button is clicked.
         */
        std::shared_ptr<ButtonWantAgent> wantAgent;

        /**
         * The ability that is updata App rdb.
         */
        std::shared_ptr<ButtonDataShareUpdate> dataShareUpdate;
    };

    /**
     * @brief Want agent information. Indicates the package and the ability to switch to.
     */
    struct WantAgentInfo {
        std::string pkgName = "";
        std::string abilityName = "";
        std::string uri = "";
        AAFwk::WantParams parameters;
    };

    struct MaxScreenAgentInfo {
        std::string pkgName = "";
        std::string abilityName = "";
    };

    /**
     * @brief Copy construct from an exist reminder.
     *
     * @param Indicates the exist reminder.
     */
    explicit ReminderRequest(const ReminderRequest &other);

    /**
     * @brief This constructor should only be used in background proxy service process
     * when reminder instance recovery from database.
     *
     * @param reminderId Indicates reminder id.
     */
    explicit ReminderRequest(int32_t reminderId);
    ReminderRequest& operator = (const ReminderRequest &other);
    virtual ~ReminderRequest() override {};

    /**
     * @brief Marshal a NotificationRequest object into a Parcel.
     *
     * @param parcel the object into the parcel
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshal object from a Parcel.
     *
     * @return the NotificationRequest
     */
    static ReminderRequest *Unmarshalling(Parcel &parcel);
    virtual bool ReadFromParcel(Parcel &parcel);
    virtual bool WriteParcel(Parcel &parcel) const;
    /**
     * @brief If the reminder is showing on the notification panel, it should not be removed automatically.
     *
     * @return true if it can be removed automatically.
     */
    bool CanRemove() const;

    bool CanShow() const;

    /**
     * @brief Obtains all the information of the reminder.
     *
     * @return Information of the reminder.
     */
    std::string Dump() const;

    /**
     * @brief Obtains the configured action buttons.
     *
     * @return map of action buttons.
     */
    std::map<ActionButtonType, ActionButtonInfo> GetActionButtons() const;

    /**
     * @brief Set the reminder action buttons.
     */
    void SetActionButtons(const std::map<ActionButtonType, ActionButtonInfo>& buttons);

    /**
     * @brief Obtains creator bundle name
     *
     * @return creator bundle name
     */
    std::string GetCreatorBundleName() const;

    /**
     * @brief Obtains creator uid
     *
     * @return creator uid
     */
    int32_t GetCreatorUid() const;

    /**
     * @brief Obtains the configured content.
     *
     * @return content text.
     */
    std::string GetContent() const;

    /**
     * @brief Obtains the configured expired content.
     *
     * @return expired content text.
     */
    std::string GetExpiredContent() const;

    std::shared_ptr<MaxScreenAgentInfo> GetMaxScreenWantAgentInfo() const;

    /**
     * @brief Obtains notification id.
     *
     * @return notification id.
     */
    int32_t GetNotificationId() const;

    /**
     * @brief Obtains group id.
     *
     * @return group id.
     */
    std::string GetGroupId() const;

    /**
     * @brief Obtains reminder id.
     *
     * @return reminder id.
     */
    int32_t GetReminderId() const;

    uint64_t GetReminderTimeInMilli() const;

    /**
     * @brief Obtains reminder type.
     *
     * @return reminder type.
     */
    ReminderType GetReminderType() const;

    /**
     * @brief Obtains the ringing or vibration duration configured for this reminder.
     *
     * @return uint16_t The ringing or vibration duration in seconds.
     */
    uint16_t GetRingDuration() const;

    /**
     * @brief Obtains slot type.
     *
     * @return slot type.
     */
    NotificationConstant::SlotType GetSlotType() const;

    /**
     * @brief Obtains snoozeSlot type.
     *
     * @return snoozeSlot type.
     */
    NotificationConstant::SlotType GetSnoozeSlotType() const;

    std::string GetSnoozeContent() const;
    uint8_t GetSnoozeTimes() const;
    uint8_t GetSnoozeTimesDynamic() const;
    uint8_t GetState() const;

    /**
     * @brief Obtains the Time Interval in seconds.
     *
     * @return uint64_t Time Interval in seconds.
     */
    uint64_t GetTimeInterval() const;

    /**
     * @brief Obtains title.
     *
     * @return title.
     */
    std::string GetTitle() const;

    /**
     * @brief Obtains trigger time in milli.
     *
     * @return trigger time.
     */
    uint64_t GetTriggerTimeInMilli() const;

    int32_t GetTitleResourceId() const
    {
        return titleResourceId_;
    }
    int32_t GetContentResourceId() const
    {
        return contentResourceId_;
    }
    int32_t GetExpiredContentResourceId() const
    {
        return expiredContentResourceId_;
    }
    int32_t GetSnoozeContentResourceId() const
    {
        return snoozeContentResourceId_;
    }

    void SetTitleResourceId(const int32_t titleResourceId)
    {
        titleResourceId_ = titleResourceId;
    }
    void SetContentResourceId(const int32_t contentResourceId)
    {
        contentResourceId_ = contentResourceId;
    }
    void SetExpiredContentResourceId(const int32_t expiredContentResourceId)
    {
        expiredContentResourceId_ = expiredContentResourceId;
    }
    void SetSnoozeContentResourceId(const int32_t snoozeContentResourceId)
    {
        snoozeContentResourceId_ = snoozeContentResourceId;
    }

    /**
     * @brief Set/Get ring channel.
     */
    void SetRingChannel(const RingChannel channel);
    RingChannel GetRingChannel() const;

    /**
     * @brief Set/Get ring loop.
     */
    void SetRingLoop(const bool isRingLoop);
    bool IsRingLoop() const;

    int32_t GetUserId() const;
    int32_t GetUid() const;

    /**
     * @brief Obtains bundle name
     *
     * @return bundle name
     */
    std::string GetBundleName() const;

    /**
     * @brief Set the reminder type.
     *
     * @param reminderType the reminder type.
     */
    void SetReminderType(const ReminderType type);

    /**
     * @brief Set the reminder state.
     *
     * @param state the reminder state.
     */
    void SetState(const uint8_t state);

    /**
     * @brief Set the reminder repeat days of week.
     *
     * @param state the reminder repeat days of week.
     */
    void SetRepeatDaysOfWeek(const uint8_t repeatDaysOfWeek);

    /**
     * @brief Set the app system.
     *
     */
    void SetSystemApp(bool isSystem);

    /**
     * @brief Check the app is system or not.
     *
     * @return true is the app is system.
     */
    bool IsSystemApp() const;

    /**
     * @brief Obtains want agent information.
     *
     * @return want agent information.
     */
    std::shared_ptr<WantAgentInfo> GetWantAgentInfo() const;

    /**
     * @brief Inites reminder creator bundle name when publish reminder success.
     *
     * @param creatorBundleName Indicates the creator bundle name which the reminder belong to
     */
    void InitCreatorBundleName(const std::string &creatorBundleName);

    /**
     * @brief Inites reminder creator uid when publish reminder success.
     *
     * @param uid Indicates the creator uid which the reminder belong to
     */
    void InitCreatorUid(const int32_t creatorUid);

    /**
     * @brief Inits reminder id when publish reminder success.
     * Assign a unique reminder id for each reminder.
     */
    void InitReminderId();

    /**
     * @brief Inits reminder userId when publish reminder success.
     *
     * When package remove, user id is sended by wantAgent, but we cannot get the uid according user id as the
     * package has been removed, and the bundleOption can not be create with correct uid. so we need to record
     * the user id, and use it to judge which user the reminder belong to.
     *
     * @param userId Indicates the userId which the reminder belong to.
     */
    void InitUserId(const int32_t &userId);

    /**
     * @brief Inites reminder uid when publish reminder success.
     *
     * When system reboot and recovery from database, we cannot get the uid according user id as BMS has not be
     * ready. So we need to record the uid in order to create correct bundleOption.
     *
     * @param uid Indicates the uid which the reminder belong to.
     */
    void InitUid(const int32_t &uid);

    /**
     * @brief Inites reminder bundle name when publish reminder success.
     *
     * @param bundleName Indicates the bundle name which the reminder belong to
     */
    void InitBundleName(const std::string &bundleName);

    /**
     * @brief Check the reminder is alerting or not.
     *
     * @return true if the reminder is playing sound or vibrating.
     */
    bool IsAlerting() const;

    /**
     * @brief Check the reminder is expired or not.
     *
     * @return true is the reminder is expired.
     */
    bool IsExpired() const;

    /**
     * @brief Check the reminder is showing on the panel.
     *
     * @return true if the reminder is showing on the panel.
     */
    bool IsShowing() const;

    /**
     * @brief Closes the reminder by manual.
     *
     * 1) Resets the state of "Alering/Showing/Snooze"
     * 2) Resets snoozeTimesDynamic_ if update to next trigger time, otherwise set reminder to expired.
     *
     * @param updateNext Whether to update to next reminder.
     */
    void OnClose(bool updateNext);

    /**
     * @brief When date/time change, reminder need to refresh next trigger time.
     *
     * @return true if need to show reminder immediately.
     */
    virtual bool OnDateTimeChange();

    /**
     * When shown notification is covered by a new notification with the same id, we should remove
     * the state of showing, so that the reminder can be removed automatically when it is expired.
     */
    void OnSameNotificationIdCovered();

    /**
     * Set the reminder state is InActive, so that it will be removed when expired
     */
    void SetStateToInActive();

    /**
     * @brief Shows the reminder on panel. TriggerTime will be updated to next.
     *
     * @param isPlaySoundOrVibration true means it is play sound or vibration.
     * @param isSysTimeChanged true means it is called when the system time is changed by user, otherwise false.
     * @param allowToNotify true means that the notification will be shown as normal, otherwise false.
     */
    void OnShow(bool isPlaySoundOrVibration, bool isSysTimeChanged, bool allowToNotify);

    /**
     * @brief Reset the state of "Showing" when the reminder is shown failed.
     */
    void OnShowFail();

    /**
     * @brief Snooze the reminder by manual.
     *
     * 1) Updates the trigger time to the next one.
     * 2) Updates the notification content for "Snooze".
     * 3) Switches the state from "Showing[, Alerting]" to "Snooze".
     */
    bool OnSnooze();

    /**
     * @brief Starts the reminder
     *
     * Sets the state from "Inactive" to "Active".
     */
    void OnStart();

    /**
     * @brief Stops the reminder.
     *
     * Sets the state from "Active" to "Inactive".
     */
    void OnStop();

    /**
     * @brief Terminate the alerting reminder, which is executed when the ring duration is over.
     *
     * 1) Disables the state of "Alerting".
     * 2) Updates the notification content for "Alert".
     *
     * @return false if alerting state has already been set false before calling the method.
     */
    bool OnTerminate();

    /**
     * @brief When timezone change, reminder need to refresh next trigger time.
     *
     * @return true if need to show reminder immediately.
     */
    virtual bool OnTimeZoneChange();

    /**
     * @brief Sets action button.
     *
     * @param title Indicates the title of the button.
     * @param type Indicates the type of the button.
     * @param resource Indicates the resource of the button.
     * @return Current reminder self.
     */
    ReminderRequest& SetActionButton(const std::string &title, const ActionButtonType &type,
        const std::string &resource, const std::shared_ptr<ButtonWantAgent> &buttonWantAgent = nullptr,
        const std::shared_ptr<ButtonDataShareUpdate> &buttonDataShareUpdate = nullptr);

    /**
     * @brief Sets reminder content.
     *
     * @param content Indicates content text.
     * @return Current reminder self.
     */
    ReminderRequest& SetContent(const std::string &content);

    /**
     * @brief Sets reminder is expired or not.
     *
     * @param isExpired Indicates the reminder is expired or not.
     */
    void SetExpired(bool isExpired);

    /**
     * @brief Sets expired content.
     *
     * @param expiredContent Indicates expired content.
     * @return Current reminder self.
     */
    ReminderRequest& SetExpiredContent(const std::string &expiredContent);

    ReminderRequest& SetMaxScreenWantAgentInfo(const std::shared_ptr<MaxScreenAgentInfo> &maxScreenWantAgentInfo);

    /**
     * @brief Sets notification id.
     *
     * @param notificationId Indicates notification id.
     * @return Current reminder self.
     */
    ReminderRequest& SetNotificationId(int32_t notificationId);

    /**
     * @brief Sets group id.
     *
     * @param notificationId Indicates group id.
     * @return Current reminder self.
     */
    ReminderRequest& SetGroupId(const std::string &groupId);

    /**
     * @brief Sets reminder id.
     *
     * @param reminderId Indicates reminder id.
     */
    void SetReminderId(int32_t reminderId);

    void SetReminderTimeInMilli(const uint64_t reminderTimeInMilli);

    /**
     * @brief Sets the ringing or vibration duration for this reminder, in seconds.
     *
     * @param ringDurationInSeconds Indicates the duration. The default is 1 second.
     * @return Current reminder self.
     */
    ReminderRequest& SetRingDuration(const uint64_t ringDurationInSeconds);

    /**
     * @brief Sets slot type.
     *
     * @param slotType Indicates slot type.
     * @return Current reminder self.
     */
    ReminderRequest& SetSlotType(const NotificationConstant::SlotType &slotType);
    ReminderRequest& SetSnoozeSlotType(const NotificationConstant::SlotType &snoozeSlotType);
    ReminderRequest& SetSnoozeContent(const std::string &snoozeContent);

    /**
     * @brief Set the number of snooze times for this reminder.
     *
     * @note If the value of snoozeTimes is less than or equals to 0, this reminder is a one-shot
     * reminder and will not be snoozed.
     *
     * It the value of snoozeTimes is greater than 0, for example, snoozeTimes=3, this reminder
     * will be snoozed three times after the first alarm, that is, this reminder will be triggered
     * for four times.
     *
     * This method does not take affect on the reminders for countdown timers.
     *
     * @param snoozeTimes Indicates the number of times that the reminder will be snoozed.
     * @return ReminderRequest& Current reminder self.
     */
    ReminderRequest& SetSnoozeTimes(const uint8_t snoozeTimes);

    ReminderRequest& SetSnoozeTimesDynamic(const uint8_t snooziTimes);

    /**
     * @brief Sets the Time Interval for this reminder, in seconds. The default value is 0.
     *
     * @note The minimum snooze interval is 5 minute. If the snooze interval is set to a value greater
     * than 0 and less than 5 minutes, the system converts it to 5 minutes by default.
     *
     * This method does not take effect on the reminders for countdown timers.
     *
     * @param timeIntervalInSeconds Indicates the snooze interval to set. If the value is less or equals to 0,
     * the reminder will not be snoozed.
     * @return ReminderRequest& Current reminder self.
     */
    ReminderRequest& SetTimeInterval(const uint64_t timeIntervalInSeconds);

    /**
     * @brief Sets title.
     *
     * @param title Indicates title.
     * @return Current reminder self.
     */
    ReminderRequest& SetTitle(const std::string &title);

    /**
     * @brief Sets trigger time.
     *
     * @param triggerTimeInMilli Indicates trigger time in milli.
     */
    void SetTriggerTimeInMilli(uint64_t triggerTimeInMilli);

    void SetIdentifier(const std::string& identifier)
    {
        identifier_ = identifier;
    }

    std::string GetIdentifier() const
    {
        return identifier_;
    }

    /**
     * @brief Sets want agent information.
     *
     * @param wantAgentInfo Indicates want agent information.
     * @return Current reminder self.
     */
    ReminderRequest& SetWantAgentInfo(const std::shared_ptr<WantAgentInfo> &wantAgentInfo);

    bool ShouldShowImmediately() const;

    /**
     * @brief Updates {@link triggerTimeInMilli_} to next.
     * @note If next trigger time not exist, {@link isExpired_} flag will be set with true.
     *
     * @return true if next trigger time exist and set success.
     */
    virtual bool UpdateNextReminder();
    virtual bool SetNextTriggerTime();

    /**
     * @brief Check reminder request is repeat
     */
    virtual bool IsRepeat() const
    {
        return false;
    }

    /**
     * @brief Check reminder request is in exclude date
     */
    virtual bool CheckExcludeDate()
    {
        return false;
    }

    /**
     * @brief Check rrule want agent, pull up service extension
     *
     * @return true if need pull up service extension
     */
    virtual bool IsPullUpService()
    {
        return false;
    }

    /**
     * @brief Check need notification reminder. due to system timer.
     * When change system time to later, more than the trigger time, system timer must trigger.
     */
    virtual bool IsNeedNotification()
    {
        return true;
    }

    void SetWantAgentStr(const std::string& wantStr);
    std::string GetWantAgentStr();
    void SetMaxWantAgentStr(const std::string& maxWantStr);
    std::string GetMaxWantAgentStr();

    /**
     * @brief Sets tapDismissed.
     *
     * @param tapDismissed Indicates tapDismissed.
     */
    void SetTapDismissed(bool tapDismissed);

    /**
     * @brief Gets tapDismissed.
     *
     * @return True if tapDismissed.
     */
    bool IsTapDismissed() const;

    /**
     * @brief Sets autoDeletedTime.
     *
     * @param autoDeletedTime Indicates autoDeletedTime.
     */
    void SetAutoDeletedTime(int64_t autoDeletedTime);

    /**
     * @brief Gets autoDeletedTime.
     *
     * @return AutoDeletedTime.
     */
    int64_t GetAutoDeletedTime() const;

    /**
     * @brief Sets custom button uri.
     *
     * @param uri Indicates uri.
     */
    void SetCustomButtonUri(const std::string &uri);

    /**
     * @brief Gets custom button uri.
     *
     * @return custom button uri.
     */
    std::string GetCustomButtonUri() const;

    /**
     * @brief Is the reminder from datashare.
     */
    bool IsShare() const;

    /**
     * @brief Set the reminder from datashare.
     */
    void SetShare(const bool isShare);

    /**
     * @brief Gets custom ring uri.
     *
     * @return custom ring uri.
     */
    std::string GetCustomRingUri() const;

     /**
     * @brief Sets custom ring uri.
     *
     * @param uri Indicates uri.
     */
    void SetCustomRingUri(const std::string &uri);

    /**
     * @brief Update notification attributes.
     *
     * Some attributes need to be updated after the reminder published or before the notification publish.
     * For example, action button should not init until the reminder is published successfully, as the reminder id is
     * assigned after that.
     *
     * @param notificationRequest notification request object
     * @param isSnooze isSnooze
     */
    void UpdateNotificationRequest(NotificationRequest& notificationRequest, bool isSnooze);

    /**
     * @brief Get repeated days of the week.
     *
     * @return  Array of the int type.
     */
    std::vector<int32_t> GetDaysOfWeek() const;

    /**
     * @brief Gets repeat days of week
     */
    uint8_t GetRepeatDaysOfWeek() const;

    /**
     * @brief When system language change, will call this function.
     *     need load resource to update button title
     * @param resMgr Indicates the resource manager for get button title
     */
    void OnLanguageChange(const std::shared_ptr<Global::Resource::ResourceManager> &resMgr);

public:
    /**
     * @brief Serialize want agent info and max want agent info to string.
     * Persist to the rdb.
     */
    void SerializeWantAgent(std::string& wantInfoStr, std::string& maxWantInfoStr);

    /**
     * @brief Deserialize want agent info and max want agent info from string.
     * Recover from the rdb.
     */
    void DeserializeWantAgent(const std::string& wantAgentInfo, const uint8_t type);

    /**
     * @brief Serialize action button info to string.
     * Persist to the rdb.
     */
    std::string SerializeButtonInfo() const;

    /**
     * @brief Deserialize action button info from string.
     * Recover from the rdb.
     */
    void DeserializeButtonInfo(const std::string& buttonInfoStr);
    void DeserializeButtonInfoFromJson(const std::string& jsonString);

    static int32_t GetActualTime(const TimeTransferType &type, int32_t cTime);
    static int32_t GetCTime(const TimeTransferType &type, int32_t actualTime);
    static uint64_t GetDurationSinceEpochInMilli(const time_t target);
    static std::vector<std::string> StringSplit(std::string source, const std::string &split);
    static double StringToDouble(const std::string& str);
    static int32_t StringToInt(const std::string& str);

    static bool ReadReminderTypeFormParcel(Parcel &parcel, ReminderType& tarReminderType);

    static int32_t GLOBAL_ID;
    static const uint64_t INVALID_LONG_LONG_VALUE;
    static const uint16_t INVALID_U16_VALUE;
    static const uint8_t INVALID_U8_VALUE;
    static const uint16_t MILLI_SECONDS;
    static const uint16_t SAME_TIME_DISTINGUISH_MILLISECONDS;
    static const std::string NOTIFICATION_LABEL;
    static const uint8_t MONDAY;
    static const uint8_t SUNDAY;
    static const uint8_t DAYS_PER_WEEK;
    static const uint8_t HOURS_PER_DAY;
    static const uint16_t SECONDS_PER_HOUR;
    static const uint8_t MINUTES_PER_HOUR;
    /**
     * @brief Show the reminder with a notification.
     */
    static const std::string REMINDER_EVENT_ALARM_ALERT;

    /**
     * @brief Close the reminder when click the close button of notification.
     */
    static const std::string REMINDER_EVENT_CLOSE_ALERT;

    /**
     * @brief Snooze the reminder when click the snooze button of notification.
     */
    static const std::string REMINDER_EVENT_SNOOZE_ALERT;

    static const std::string REMINDER_EVENT_CUSTOM_ALERT;

    /**
     * @biref Close the reminder when click the notification, not button.
     */
    static const std::string REMINDER_EVENT_CLICK_ALERT;

    /**
     * @brief Used to control ring duration.
     */
    static const std::string REMINDER_EVENT_ALERT_TIMEOUT;

    /**
     * @brief Update the reminder when remove notification from the systemUI.
     */
    static const std::string REMINDER_EVENT_REMOVE_NOTIFICATION;
    static const std::string PARAM_REMINDER_ID;
    static const std::string PARAM_REMINDER_SHARE;
    static const uint8_t REMINDER_STATUS_INACTIVE;
    static const uint8_t REMINDER_STATUS_ACTIVE;
    static const uint8_t REMINDER_STATUS_ALERTING;
    static const uint8_t REMINDER_STATUS_SHOWING;
    static const uint8_t REMINDER_STATUS_SNOOZE;
    static const uint8_t TIME_HOUR_OFFSET;

    // For ActionButtonDataShare.
    static const std::string SEP_BUTTON_VALUE_TYPE;
    static const std::string SEP_BUTTON_VALUE;
    static const std::string SEP_BUTTON_VALUE_BLOB;

    // no object in parcel
    static constexpr int32_t VALUE_NULL = -1;
    // object exist in parcel
    static constexpr int32_t VALUE_OBJECT = 1;
    // wantAgent flag
    static constexpr int32_t WANT_AGENT_FLAG = 0;
    // maxWantAgent flag
    static constexpr int32_t MAX_WANT_AGENT_FLAG = 1;

    // max ring duration
    static constexpr uint64_t MAX_RING_DURATION = 30 * 60 * 1000;  // 30 min

protected:
    enum class DbRecoveryType : uint8_t {
        INT,
        LONG
    };
    ReminderRequest();
    explicit ReminderRequest(ReminderType reminderType);
    std::string GetDateTimeInfo(const time_t &timeInSecond) const;
    virtual uint64_t PreGetNextTriggerTimeIgnoreSnooze(bool ignoreRepeat, bool forceToGetNext)
    {
        return INVALID_LONG_LONG_VALUE;
    }

    uint8_t repeatDaysOfWeek_{0};

    /**
     * Obtains the next triggerTime if it is a week repeat.
     *
     * @param now Indicates current time.
     * @param now Indicatet target time.
     * @return nextTriggerTime.
     */
    int64_t GetNextDaysOfWeek(const time_t now, const time_t target) const;
    void SetRepeatDaysOfWeek(bool set, const std::vector<uint8_t> &daysOfWeek);
    time_t GetTriggerTimeWithDST(const time_t now, const time_t nextTriggerTime) const;
    uint64_t GetTriggerTime(const time_t now, const time_t nextTriggerTime) const;
    uint64_t GetNowInstantMilli() const;

private:

    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> CreateWantAgent(AppExecFwk::ElementName &element) const;
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> CreateMaxWantAgent(AppExecFwk::ElementName &element) const;
    std::string GetShowTime(const uint64_t showTime) const;
    std::string GetTimeInfoInner(const time_t &timeInSecond, const TimeFormat &format, bool keep24Hour) const;
    std::string GetState(const uint8_t state) const;
    bool HandleSysTimeChange(uint64_t oriTriggerTime, uint64_t optTriggerTime);
    bool HandleTimeZoneChange(uint64_t oldZoneTriggerTime, uint64_t newZoneTriggerTime, uint64_t optTriggerTime);
    void InitServerObj();
    void SetMaxScreenWantAgent(AppExecFwk::ElementName &element);
    void SetState(bool deSet, const uint8_t newState, std::string function);
    void SetWantAgent(AppExecFwk::ElementName &element);
    void SetExtraInfo(const AAFwk::WantParams& params);
    void UpdateActionButtons(NotificationRequest& notificationRequest, const bool &setSnooze);
    bool UpdateNextReminder(const bool &force);
    void AddActionButtons(NotificationRequest& notificationRequest, const bool includeSnooze);
    void UpdateNotificationContent(NotificationRequest& notificationRequest, const bool &setSnooze);
    void UpdateNotificationCommon(NotificationRequest& notificationRequest, bool isSnooze);
    void UpdateNotificationAddRemovalWantAgent(NotificationRequest& notificationRequest);
    void UpdateNotificationWantAgent(NotificationRequest& notificationRequest);
    void UpdateNotificationMaxScreenWantAgent(NotificationRequest& notificationRequest);
    void UpdateNotificationBundleInfo(NotificationRequest& notificationRequest);

    /**
     * @brief Determine whether it is repeated every week.
     *
     * @return  True if repeate.
     */
    bool IsRepeatDaysOfWeek(int32_t day) const;

    /**
     * @brief Update the notification, which will be shown for the "Alerting" reminder.
     * 1. Update the notification label/content.
     * 2. Restore the snooze action button.
     */
    void UpdateNotificationStateForAlert(NotificationRequest& notificationRequest);

    /**
     * @brief Update the notification, which will be shown when user do a snooze.
     * 1. Update the notification label/content.
     * 2. Remove the snooze action button.
     */
    void UpdateNotificationStateForSnooze(NotificationRequest& notificationRequest);

    bool MarshallingWantParameters(Parcel& parcel, const AAFwk::WantParams& params) const;
    bool MarshallingActionButton(Parcel& parcel) const;
    bool ReadWantParametersFromParcel(Parcel& parcel, AAFwk::WantParams& wantParams);
    bool ReadActionButtonFromParcel(Parcel& parcel);

    void RecoverActionButtonJsonMode(const std::string& jsonString);
    void RecoverWantAgentByJson(const std::string& wantAgentInfo, const uint8_t& type);

    static const uint32_t MIN_TIME_INTERVAL_IN_MILLI;
    static const std::string SEP_BUTTON_SINGLE;
    static const std::string SEP_BUTTON_MULTI;
    static const std::string SEP_WANT_AGENT;

    std::string content_ {};
    std::string expiredContent_ {};
    std::string snoozeContent_ {};
    std::string displayContent_ {};
    std::string title_ {};
    std::string bundleName_ {};
    bool isExpired_ {false};
    bool isShare_ {false};
    uint8_t snoozeTimes_ {0};
    uint8_t snoozeTimesDynamic_ {0};
    uint8_t state_ {0};
    RingChannel ringChannel_ {RingChannel::ALARM};
    int32_t notificationId_ {0};
    std::string groupId_ {};
    int32_t reminderId_ {-1};
    int32_t userId_ {-1};
    int32_t uid_ {-1};
    bool isSystemApp_ {false};
    bool tapDismissed_ {true};
    bool isRingLoop_ {true};
    int64_t autoDeletedTime_ {0};
    std::string customButtonUri_ {};
    std::string customRingUri_ {};
    std::string creatorBundleName_ {};
    int32_t creatorUid_ {-1};

    // Indicates the reminder has been shown in the past time.
    // When the reminder has been created but not showed, it is equals to 0.
    uint64_t reminderTimeInMilli_ {0};
    uint64_t ringDurationInMilli_ {MILLI_SECONDS};
    uint64_t triggerTimeInMilli_ {0};
    uint64_t timeIntervalInMilli_ {0};
    ReminderType reminderType_ {ReminderType::INVALID};
    NotificationConstant::SlotType slotType_ {NotificationConstant::SlotType::SOCIAL_COMMUNICATION};
    NotificationConstant::SlotType snoozeSlotType_ {NotificationConstant::SlotType::OTHER};
    std::shared_ptr<WantAgentInfo> wantAgentInfo_ = nullptr;
    std::shared_ptr<MaxScreenAgentInfo> maxScreenWantAgentInfo_ = nullptr;
    std::map<ActionButtonType, ActionButtonInfo> actionButtonMap_ {};

    std::vector<std::shared_ptr<NotificationActionButton>> actionButtons_ {};
    std::string wantAgentStr_{};
    std::string maxWantAgentStr_{};
    std::string identifier_;

    int32_t titleResourceId_ {0};
    int32_t contentResourceId_ {0};
    int32_t expiredContentResourceId_ {0};
    int32_t snoozeContentResourceId_ {0};
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_REMINDER_REQUEST_H