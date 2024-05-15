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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_MANAGER_INTERFACE_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_MANAGER_INTERFACE_H

#include <string>
#include <vector>

#include "ans_dialog_callback_interface.h"
#include "ans_subscriber_interface.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "iremote_broker.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_do_not_disturb_date.h"
#include "notification_do_not_disturb_profile.h"
#include "notification_request.h"
#include "notification_slot.h"
#include "notification_subscribe_info.h"
#include "reminder_request.h"

namespace OHOS {
namespace Notification {
class AnsManagerInterface : public IRemoteBroker {
public:
    AnsManagerInterface() = default;
    virtual ~AnsManagerInterface() = default;
    DISALLOW_COPY_AND_MOVE(AnsManagerInterface);

    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Notification.AnsManagerInterface");

    /**
     * @brief Publishes a notification with a specified label.
     * @note If a notification with the same ID has been published by the current application and has not been deleted,
     *       this method will update the notification.
     *
     * @param label Indicates the label of the notification to publish.
     * @param notification Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Publish(const std::string &label, const sptr<NotificationRequest> &notification) = 0;

    /**
     * @brief Cancels a published notification matching the specified label and notificationId.
     *
     * @param notificationId Indicates the ID of the notification to cancel.
     * @param label Indicates the label of the notification to cancel.
     * @return Returns cancel notification result.
     */
    virtual ErrCode Cancel(int notificationId, const std::string &label) = 0;

    /**
     * @brief Cancels all the published notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelAll() = 0;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @param representativeBundle Indicates the name of application bundle your application is representing.
     * @param userId Indicates the specific user.
     * @return Returns cancel notification result.
     */
    virtual ErrCode CancelAsBundle(
        int32_t notificationId, const std::string &representativeBundle, int32_t userId) = 0;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle of application your application is representing.
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @return Returns cancel notification result.
     */
    virtual ErrCode CancelAsBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId) = 0;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle of application bundle your application is representing.
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @param userId Indicates the specific user.
     * @return Returns cancel notification result.
     */
    virtual ErrCode CancelAsBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId) = 0;

    /**
     * @brief Adds a notification slot by type.
     *
     * @param slotType Indicates the notification slot type to be added.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddSlotByType(NotificationConstant::SlotType slotType) = 0;

    /**
     * @brief Creates multiple notification slots.
     *
     * @param slots Indicates the notification slots to create.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddSlots(const std::vector<sptr<NotificationSlot>> &slots) = 0;

    /**
     * @brief Deletes a created notification slot based on the slot ID.
     *
     * @param slotType Indicates the type of the slot, which is created by AddNotificationSlot
     *                 This parameter must be specified.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveSlotByType(const NotificationConstant::SlotType &slotType) = 0;

    /**
     * @brief Deletes all notification slots.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveAllSlots() = 0;

    /**
     * @brief Queries a created notification slot.
     *
     * @param slotType Indicates the ID of the slot, which is created by AddNotificationSlot(NotificationSlot). This
     *        parameter must be specified.
     * @param slot Indicates the created NotificationSlot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotByType(const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot) = 0;

    /**
     * @brief Obtains all notification slots of this application.
     *
     * @param slots Indicates the created NotificationSlot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlots(std::vector<sptr<NotificationSlot>> &slots) = 0;

    /**
     * @brief Obtains the number of slot.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param num Indicates the number of slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotNumAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num) = 0;

    /**
     * @brief Obtains active notifications of the current application in the system.
     *
     * @param notifications Indicates active NotificationRequest objects of the current application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetActiveNotifications(std::vector<sptr<NotificationRequest>> &notifications) = 0;

    /**
     * @brief Obtains the number of active notifications of the current application in the system.
     *
     * @param num Indicates the number of active notifications of the current application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetActiveNotificationNums(uint64_t &num) = 0;

    /**
     * @brief Obtains all active notifications in the current system. The caller must have system permissions to
     * call this method.
     *
     * @param notifications Indicates all active notifications of this application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications) = 0;

    /**
     * @brief Obtains the active notifications corresponding to the specified key in the system. To call this method
     * to obtain particular active notifications, you must have received the notifications and obtained the key
     * via {Notification::GetKey()}.
     *
     * @param key Indicates the key array for querying corresponding active notifications.
     *            If this parameter is null, this method returns all active notifications in the system.
     * @param notification Indicates the set of active notifications corresponding to the specified key.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSpecialActiveNotifications(
        const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications) = 0;

    /**
     * @brief Obtains the live view notification extra info by the extraInfoKeys. To call this method
     * to obtain particular live view notification extra info, you must have received the
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param notificationId Indicates the id of the notification to get the extra info by extra info keys.
     * @param extraInfoKeys
     * @param extraInfo
     * @return
     */
    virtual ErrCode GetActiveNotificationByFilter(
        const sptr<NotificationBundleOption> &bundleOption, const int32_t notificationId, const std::string &label,
        std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &request) = 0;

    /**
     * @brief Allows another application to act as an agent to publish notifications in the name of your application
     * bundle.
     *
     * @param agent Indicates the name of the application bundle that can publish notifications for your application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationAgent(const std::string &agent) = 0;

    /**
     * @brief Obtains the name of the application bundle that can publish notifications in the name of your application.
     *
     * @param agent Indicates the name of the application bundle that can publish notifications for your application if
     * any; returns null otherwise.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetNotificationAgent(std::string &agent) = 0;

    /**
     * @brief Checks whether your application has permission to publish notifications by calling
     * PublishNotificationAsBundle(string, NotificationRequest) in the name of another application indicated by the
     * given representativeBundle.
     *
     * @param representativeBundle Indicates the name of application bundle your application is representing.
     * @param canPublish Indicates whether your application has permission to publish notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish) = 0;

    /**
     * @brief Publishes a notification in the name of a specified application bundle.
     * @note If the notification to be published has the same ID as a published notification that has not been canceled,
     * the existing notification will be replaced by the new one.
     *
     * @param notification Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @param representativeBundle Indicates the name of the application bundle that allows your application to publish
     *                             notifications for it by calling setNotificationAgent.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode PublishAsBundle(
        const sptr<NotificationRequest> notification, const std::string &representativeBundle) = 0;

    /**
     * @brief Sets the number of active notifications of the current application as the number to be displayed on the
     * notification badge.
     *
     * @param num Indicates the badge number.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationBadgeNum(int num) = 0;

    /**
     * @brief Obtains the importance level of this application.
     *
     * @param importance Indicates the importance level of this application, which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetBundleImportance(int &importance) = 0;

    /**
     * @brief Checks whether this application has permission to modify the Do Not Disturb (DND) notification policy.
     *
     * @param granted True if the application has permission; false for otherwise.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode HasNotificationPolicyAccessPermission(bool &granted) = 0;

    /**
     * @brief Trigger the local live view after the button has been clicked.
     * @note Your application must have platform signature to use this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application whose notifications has been clicked.
     * @param notificationId Indicates the id of the notification.
     * @param buttonOption Indicates which button has been clicked.
     * @return Returns trigger localLiveView result.
     */
    virtual ErrCode TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
        const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption) = 0;

    /**
     * @brief Delete notification based on key.
     *
     * @param key Indicates the key to delete notification.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Delete(const std::string &key, int32_t removeReason) = 0;

    /**
     * @brief Delete notification.
     *
     * @param bundleOption Indicates the NotificationBundleOption of the notification.
     * @param notificationId Indicates the id of the notification.
     * @param label Indicates the label of the notification.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveNotification(const sptr<NotificationBundleOption> &bundleOption, int notificationId,
        const std::string &label, int32_t removeReason) = 0;

    /**
     * @brief Delete all notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption of notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption) = 0;

    virtual ErrCode RemoveNotifications(const std::vector<std::string> &hashcodes, int32_t removeReason) = 0;

    /**
     * @brief Remove notifications based on bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption of notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption) = 0;

    /**
     * @brief Remove all notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DeleteAll() = 0;

    /**
     * @brief Get all the slots corresponding to the bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slots Indicates the notification slots.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotsByBundle(
        const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots) = 0;

    /**
     * @brief Get the specified slot corresponding to the bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slotType Indicates the ID of the slot, which is created by AddNotificationSlot(NotificationSlot). This
     *        parameter must be specified.
     * @param slot Indicates the notification slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
        sptr<NotificationSlot> &slot) = 0;

    /**
     * @brief Update slots according to bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slots Indicates the notification slots to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UpdateSlots(
        const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots) = 0;

    /**
     * @brief Allow notifications to be sent based on the deviceId.
     *
     * @param deviceId Indicates the device Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RequestEnableNotification(const std::string &deviceId,
        const sptr<AnsDialogCallback> &callback,
        const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Set whether to allow the specified deviceId to send notifications for current bundle.
     *
     * @param deviceId Indicates the device Id.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled) = 0;

    /**
     * @brief Set whether to allow the specified deviceId to send notifications for all bundles.
     *
     * @param deviceId Indicates the device Id.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled) = 0;

    /**
     * @brief Set whether to allow the specified bundle to send notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledForSpecialBundle(
        const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled) = 0;

    /**
     * @brief Sets whether the bundle allows the banner to display notification.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled) = 0;

    /**
     * @brief Gets whether the bundle allows the badge to display the status of notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled) = 0;

    /**
     * @brief Gets whether allows the badge to display the status of notifications.
     *
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetShowBadgeEnabled(bool &enabled) = 0;

    /**
     * @brief Subscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Subscribe(const sptr<AnsSubscriberInterface> &subscriber,
        const sptr<NotificationSubscribeInfo> &info) = 0;

    /**
     * @brief Subscribes notifications self.
     *
     * @param subscriber Indicates the subscriber.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SubscribeSelf(const sptr<AnsSubscriberInterface> &subscriber) = 0;

    /**
     * @brief Subscribes local live view notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SubscribeLocalLiveView(const sptr<AnsSubscriberLocalLiveViewInterface> &subscriber,
        const sptr<NotificationSubscribeInfo> &info, const bool isNative) = 0;

    /**
     * @brief Unsubscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Unsubscribe(
        const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info) = 0;

    /**
     * @brief Checks whether this device is allowed to publish notifications.
     *
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsAllowedNotify(bool &allowed) = 0;

    /**
     * @brief Checks whether this application is allowed to publish notifications.
     *
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsAllowedNotifySelf(bool &allowed) = 0;

    /**
     * @brief Checks whether notifications are allowed for a specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsSpecialBundleAllowedNotify(const sptr<NotificationBundleOption> &bundleOption, bool &allowed) = 0;

    /**
     * @brief Set do not disturb date.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date) = 0;

    /**
     * @brief Get do not disturb date.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date) = 0;

    /**
     * @brief Add do not disturb profiles.
     *
     * @param profiles Indicates the NotificationDoNotDisturbProfile objects.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) = 0;

    /**
     * @brief Remove do not disturb profiles.
     *
     * @param profiles Indicates the NotificationDoNotDisturbProfile objects.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) = 0;

    /**
     * @brief Get whether Do Not Disturb mode is supported.
     *
     * @param doesSupport Indicates the flag that supports DND mode.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DoesSupportDoNotDisturbMode(bool &doesSupport) = 0;

    /**
     * @brief Cancel notifications according to group.
     *
     * @param groupName Indicates the group name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelGroup(const std::string &groupName) = 0;

    /**
     * @brief Delete notifications according to bundle and group.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param groupName Indicates the group name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveGroupByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName) = 0;

    /**
     * @brief Gets whether distributed notification is enabled.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsDistributedEnabled(bool &enabled) = 0;

    /**
     * @brief Sets distributed notification enabled or disabled.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode EnableDistributed(bool enabled) = 0;

    /**
     * @brief Sets distributed notification enabled or disabled for specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode EnableDistributedByBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled) = 0;

    /**
     * @brief Sets distributed notification enabled or disabled for current bundle.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode EnableDistributedSelf(bool enabled) = 0;

    /**
     * @brief Gets whether distributed notification is enabled for specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsDistributedEnableByBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled) = 0;

    /**
     * @brief Get the reminder type of the current device.
     *
     * @param remindType Reminder type for the device.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDeviceRemindType(NotificationConstant::RemindType &remindType) = 0;

    /**
     * @brief Publishes a continuous notification.
     *
     * @param request Notification requests that need to be posted.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode PublishContinuousTaskNotification(const sptr<NotificationRequest> &request) = 0;

    /**
     * @brief Cancels a continuous notification.
     *
     * @param label Identifies the label of the specified notification.
     * @param notificationId Identifies the id of the specified notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelContinuousTaskNotification(const std::string &label, int32_t notificationId) = 0;

    /**
     * @brief Publishes a reminder notification.
     *
     * @param reminder Identifies the reminder notification request that needs to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode PublishReminder(sptr<ReminderRequest> &reminder) = 0;

    /**
     * @brief Cancel a reminder notifications.
     *
     * @param reminderId Identifies the reminders id that needs to be canceled.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelReminder(const int32_t reminderId) = 0;

    /**
     * @brief Get all valid reminder notifications.
     *
     * @param reminders Identifies the list of all valid notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetValidReminders(std::vector<sptr<ReminderRequest>> &reminders) = 0;

    /**
     * @brief Cancel all reminder notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelAllReminders() = 0;

    /**
     * @brief Add exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param date exclude date
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddExcludeDate(const int32_t reminderId, const uint64_t date) = 0;

    /**
     * @brief Clear exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DelExcludeDates(const int32_t reminderId) = 0;

    /**
     * @brief Get exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param dates exclude dates
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetExcludeDates(const int32_t reminderId, std::vector<uint64_t>& dates) = 0;

    /**
     * @brief Checks whether this device is support template.
     *
     * @param templateName Identifies the template name for searching as a condition.
     * @param support Identifies the support flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsSupportTemplate(const std::string &templateName, bool &support) = 0;

    /**
     * @brief Checks Whether the specified users is allowed to publish notifications.
     *
     * @param userId Identifies the user's id.
     * @param allowed Identifies the allowed flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed) = 0;

    /**
     * @brief Sets whether to allow all applications to publish notifications on a specified device. The caller must
     * have system permissions to call this method.
     *
     * @param deviceId Indicates the ID of the device running the application. At present, this parameter can only
     *                 be null or an empty string, indicating the current device.
     * @param enabled Specifies whether to allow all applications to publish notifications. The value true
     *                indicates that notifications are allowed, and the value false indicates that notifications
     *                are not allowed.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledByUser(const int32_t &deviceId, bool enabled) = 0;

    /**
     * @brief Delete all notifications by user.
     *
     * @param userId Indicates the user id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DeleteAllByUser(const int32_t &userId) = 0;

    /**
     * @brief Set do not disturb date by user.
     *
     * @param userId Indicates the user id.
     * @param date Indicates NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetDoNotDisturbDate(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date) = 0;

    /**
     * @brief Get the do not disturb date by user.
     *
     * @param userId Indicates the user id.
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDoNotDisturbDate(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date) = 0;
    virtual ErrCode SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, bool enabled,  bool isForceControl) = 0;
    virtual ErrCode GetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, bool &enabled) = 0;
    virtual ErrCode GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled) = 0;

    /**
     * @brief Obtains specific datas via specified dump option.
     *
     * @param cmd Indicates the specified dump command.
     * @param bundle Indicates the specified bundle name.
     * @param userId Indicates the specified userId.
     * @param recvUserId Indicates the specified receiver UserId
     * @param dumpInfo Indicates the container containing datas.
     * @return Returns check result.
     */
    virtual ErrCode ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo) = 0;

    /**
     * @brief Set whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns set enabled result.
     */
    virtual ErrCode SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled) = 0;

    /**
     * @brief Obtains whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns get enabled result.
     */
    virtual ErrCode GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled) = 0;

    /**
     * @brief Set badge number.
     *
     * @param badgeNumber The badge number.
     * @return Returns set badge number result.
     */
    virtual ErrCode SetBadgeNumber(int32_t badgeNumber) = 0;

    /**
     * @brief Set badge number by bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param badgeNumber The badge number.
     * @return Returns set badge number by bundle result.
     */
    virtual ErrCode SetBadgeNumberByBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber) = 0;

    /**
     * @brief Obtains the number of slotFlags.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slot      Indicates the specified slot object
     * @param slotFlags Indicates the slogFlags of slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint32_t &slotFlags) = 0;

    /**
     * @brief Set the slotFlags of slot.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slot      Indicates the specified slot object
     * @param slotFlags Indicates the slogFlags of slot to set.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption, uint32_t slotFlags) = 0;

    /**
     * @brief Obtains allow notification application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption) = 0;

    /**
     * @brief Register Push Callback.
     *
     * @param pushCallback PushCallBack.
     * @return Returns register PushCallback result.
     */
    virtual ErrCode RegisterPushCallback(
        const sptr<IRemoteObject> &pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest) = 0;

    /**
     * @brief Unregister Push Callback.
     *
     * @return Returns unregister push Callback result.
     */
    virtual ErrCode UnregisterPushCallback() = 0;

    /**
     * @brief Set agent relationship.
     *
     * @param key Indicates storing agent relationship if the value is "PROXY_PKG".
     * @param value Indicates key-value pair of agent relationship.
     * @return Returns set result.
     */
    virtual ErrCode SetAdditionConfig(const std::string &key, const std::string &value) = 0;

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    virtual ErrCode SetDistributedEnabledByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &deviceType, const bool enabled) = 0;

    /**
     * @brief Get Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given device to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    virtual ErrCode IsSmartReminderEnabled(const std::string &deviceType, bool &enabled) = 0;

    /**
     * @brief Set Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given device to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    virtual ErrCode SetSmartReminderEnabled(const std::string &deviceType, const bool enabled) = 0;

    /**
     * @brief get whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    virtual ErrCode IsDistributedEnabledByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &deviceType, bool &enabled) = 0;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param id Indicates the unique notification ID in the application.
     * @return Returns cancel result.
     */
    virtual ErrCode CancelAsBundleWithAgent(const sptr<NotificationBundleOption> &bundleOption, const int32_t id) = 0;

    /**
     * @brief Set the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    virtual ErrCode SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status) = 0;

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    /**
     * @brief Register Swing Callback.
     *
     * @param swingCallback SwingCallBack.
     * @return Returns register SwingCallback result.
     */
    virtual ErrCode RegisterSwingCallback(const sptr<IRemoteObject>& swingCallback) = 0;
#endif
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_MANAGER_INTERFACE_H
