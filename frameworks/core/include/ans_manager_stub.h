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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_MANAGER_STUB_H
#define BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_MANAGER_STUB_H

#include <functional>
#include <map>

#include "ans_manager_interface.h"
#include "ans_subscriber_local_live_view_interface.h"
#include "distributed_notification_service_ipc_interface_code.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Notification {
class AnsManagerStub : public IRemoteStub<AnsManagerInterface> {
public:
    AnsManagerStub();
    ~AnsManagerStub() override;
    DISALLOW_COPY_AND_MOVE(AnsManagerStub);

    /**
     * @brief Handle remote request.
     *
     * @param data Indicates the input parcel.
     * @param reply Indicates the output parcel.
     * @param option Indicates the message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

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
    virtual ErrCode Publish(const std::string &label, const sptr<NotificationRequest> &notification) override;

    /**
     * @brief Publishes a notification.
     * @note If a notification with the same ID has been published by the current application and has not been deleted,
     *       this method will update the notification.
     *
     * @param notification Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &notification) override;

    /**
     * @brief Cancels a published notification matching the specified label and notificationId.
     *
     * @param notificationId Indicates the ID of the notification to cancel.
     * @param label Indicates the label of the notification to cancel.
     * @param instanceKey Indicates the application instance key.
     * @return Returns cancel notification result.
     */
    virtual ErrCode Cancel(int32_t notificationId, const std::string &label, int32_t instanceKey) override;

    /**
     * @brief Cancels all the published notifications.
     *
     * @param instanceKey Indicates the application instance key.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelAll(int32_t instanceKey) override;

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
        int32_t notificationId, const std::string &representativeBundle, int32_t userId) override;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle of application your application is representing.
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @return Returns cancel notification result.
     */
    virtual ErrCode CancelAsBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId) override;

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
        const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId) override;

    /**
     * @brief Adds a notification slot by type.
     *
     * @param slotType Indicates the notification slot type to be added.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddSlotByType(NotificationConstant::SlotType slotType) override;

    /**
     * @brief Creates multiple notification slots.
     *
     * @param slots Indicates the notification slots to create.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddSlots(const std::vector<sptr<NotificationSlot>> &slots) override;

    /**
     * @brief Deletes a created notification slot based on the slot ID.
     *
     * @param slotType Indicates the type of the slot, which is created by AddNotificationSlot
     *                 This parameter must be specified.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveSlotByType(const NotificationConstant::SlotType &slotType) override;

    /**
     * @brief Deletes all notification slots.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveAllSlots() override;

    /**
     * @brief Queries a created notification slot.
     *
     * @param slotType Indicates the ID of the slot, which is created by AddNotificationSlot(NotificationSlot). This
     *        parameter must be specified.
     * @param slot Indicates the created NotificationSlot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotByType(
        const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot) override;

    /**
     * @brief Obtains all notification slots of this application.
     *
     * @param slots Indicates the created NotificationSlot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlots(std::vector<sptr<NotificationSlot>> &slots) override;

    /**
     * @brief Obtains the number of slot.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param num Indicates the number of slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotNumAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num) override;

    /**
     * @brief Obtains active notifications of the current application in the system.
     *
     * @param notifications Indicates active NotificationRequest objects of the current application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetActiveNotifications(
        std::vector<sptr<NotificationRequest>> &notifications, int32_t instanceKey) override;

    /**
     * @brief Obtains the number of active notifications of the current application in the system.
     *
     * @param num Indicates the number of active notifications of the current application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetActiveNotificationNums(uint64_t &num) override;

    /**
     * @brief Obtains all active notifications in the current system. The caller must have system permissions to
     * call this method.
     *
     * @param notifications Indicates all active notifications of this application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications) override;

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
        const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications) override;

    virtual ErrCode GetActiveNotificationByFilter(
        const sptr<NotificationBundleOption> &bundleOption, const int32_t notificationId, const std::string &label,
        std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &request) override;

    /**
     * @brief Allows another application to act as an agent to publish notifications in the name of your application
     * bundle.
     *
     * @param agent Indicates the name of the application bundle that can publish notifications for your application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationAgent(const std::string &agent) override;

    /**
     * @brief Obtains the name of the application bundle that can publish notifications in the name of your application.
     *
     * @param agent Indicates the name of the application bundle that can publish notifications for your application if
     * any; returns null otherwise.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetNotificationAgent(std::string &agent) override;

    /**
     * @brief Checks whether your application has permission to publish notifications by calling
     * PublishNotificationAsBundle(string, NotificationRequest) in the name of another application indicated by the
     * given representativeBundle.
     *
     * @param representativeBundle Indicates the name of application bundle your application is representing.
     * @param canPublish Indicates whether your application has permission to publish notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish) override;

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
        const sptr<NotificationRequest> notification, const std::string &representativeBundle) override;

    /**
     * @brief Sets the number of active notifications of the current application as the number to be displayed on the
     * notification badge.
     *
     * @param num Indicates the badge number.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationBadgeNum(int32_t num) override;

    /**
     * @brief Obtains the importance level of this application.
     *
     * @param importance Indicates the importance level of this application, which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetBundleImportance(int32_t &importance) override;

    /**
     * @brief Checks whether this application has permission to modify the Do Not Disturb (DND) notification policy.
     *
     * @param granted True if the application has permission; false for otherwise.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode HasNotificationPolicyAccessPermission(bool &granted) override;

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
        const int32_t notificationId, const sptr<NotificationButtonOption> &buttonOption) override;

    /**
     * @brief Delete notification.
     *
     * @param bundleOption Indicates the NotificationBundleOption of the notification.
     * @param notificationId Indicates the id of the notification.
     * @param label Indicates the label of the notification.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveNotification(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId,
        const std::string &label, int32_t removeReason) override;

    /**
     * @brief Delete all notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption of notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption) override;

    ErrCode RemoveNotifications(const std::vector<std::string> &keys, int32_t removeReason) override;

    /**
     * @brief Delete notification based on key.
     *
     * @param key Indicates the key to delete notification.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Delete(const std::string &key, int32_t removeReason) override;

    /**
     * @brief Remove notifications based on bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption of notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption) override;

    /**
     * @brief Remove all notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DeleteAll() override;

    /**
     * @brief Get all the slots corresponding to the bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slots Indicates the notification slots.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotsByBundle(
        const sptr<NotificationBundleOption> &bundleOption, std::vector<sptr<NotificationSlot>> &slots) override;

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
        sptr<NotificationSlot> &slot) override;

    /**
     * @brief Update slots according to bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slots Indicates the notification slots to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UpdateSlots(
        const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots) override;

    /**
     * @brief Allow notifications to be sent based on the deviceId.
     *
     * @param deviceId Indicates the device Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestEnableNotification(const std::string &deviceId,
        const sptr<AnsDialogCallback> &callback,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Set whether to allow the specified deviceId to send notifications for current bundle.
     *
     * @param deviceId Indicates the device Id.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled) override;

    /**
     * @brief Set whether to allow the specified deviceId to send notifications for all bundles.
     *
     * @param deviceId Indicates the device Id.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled) override;

    /**
     * @brief Set whether to allow the specified bundle to send notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetNotificationsEnabledForSpecialBundle(
        const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled) override;

    /**
     * @brief Sets whether the bundle allows the banner to display notification.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetShowBadgeEnabledForBundle(
        const sptr<NotificationBundleOption> &bundleOption, bool enabled) override;

    /**
     * @brief Gets whether the bundle allows the badge to display the status of notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetShowBadgeEnabledForBundle(
        const sptr<NotificationBundleOption> &bundleOption, bool &enabled) override;

    /**
     * @brief Gets whether allows the badge to display the status of notifications.
     *
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetShowBadgeEnabled(bool &enabled) override;

    /**
     * @brief Subscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Subscribe(
        const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info) override;

    /**
     * @brief Subscribes notifications self.
     *
     * @param subscriber Indicates the subscriber.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SubscribeSelf(const sptr<AnsSubscriberInterface> &subscriber) override;

    virtual ErrCode SubscribeLocalLiveView(
        const sptr<AnsSubscriberLocalLiveViewInterface> &subscriber,
        const sptr<NotificationSubscribeInfo> &info, const bool isNative) override;

    /**
     * @brief Unsubscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode Unsubscribe(
        const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info) override;

    /**
     * @brief Checks whether this device is allowed to publish notifications.
     *
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsAllowedNotify(bool &allowed) override;

    /**
     * @brief Checks whether this application is allowed to publish notifications.
     *
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsAllowedNotifySelf(bool &allowed) override;

    /**
     * @brief Checks whether this application can pop enable notification dialog.
     *
     * @param  canPop True if can pop enable notification dialog
     * @return Returns is canPop result.
     */
    ErrCode CanPopEnableNotificationDialog(const sptr<AnsDialogCallback> &callback,
        bool &canPop, std::string &bundleName) override;

    /**
     * @brief remove enable notification dialog.
     *
     * @return Returns remove dialog result.
     */
    ErrCode RemoveEnableNotificationDialog() override;

    /**
     * @brief Checks whether notifications are allowed for a specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsSpecialBundleAllowedNotify(
        const sptr<NotificationBundleOption> &bundleOption, bool &allowed) override;

    /**
     * @brief Set do not disturb date.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Get do not disturb date.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Add do not disturb profiles.
     *
     * @param profiles Indicates the NotificationDoNotDisturbProfile objects.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) override;

    /**
     * @brief Remove do not disturb profiles.
     *
     * @param profiles Indicates the NotificationDoNotDisturbProfile objects.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) override;

    /**
     * @brief Get whether Do Not Disturb mode is supported.
     *
     * @param doesSupport Indicates the flag that supports DND mode.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DoesSupportDoNotDisturbMode(bool &doesSupport) override;

    /**
     * @brief Is coming call need silent in do not disturb mode.
     *
     * @param phoneNumber the calling format number.
     * @return Returns silent in do not disturb mode.
     */
    virtual ErrCode IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType) override;

    /**
     * @brief Cancel notifications according to group.
     *
     * @param groupName Indicates the group name.
     * @param instanceKey Indicates the application instance key.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelGroup(const std::string &groupName, int32_t instanceKey) override;

    /**
     * @brief Delete notifications according to bundle and group.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param groupName Indicates the group name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RemoveGroupByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName) override;

    /**
     * @brief Gets whether distributed notification is enabled.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsDistributedEnabled(bool &enabled) override;

    /**
     * @brief Sets distributed notification enabled or disabled.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode EnableDistributed(bool enabled) override;

    /**
     * @brief Sets distributed notification enabled or disabled for specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode EnableDistributedByBundle(
        const sptr<NotificationBundleOption> &bundleOption, bool enabled) override;

    /**
     * @brief Sets distributed notification enabled or disabled for current bundle.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode EnableDistributedSelf(bool enabled) override;

    /**
     * @brief Gets whether distributed notification is enabled for specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsDistributedEnableByBundle(
        const sptr<NotificationBundleOption> &bundleOption, bool &enabled) override;

    /**
     * @brief Get the reminder type of the current device.
     *
     * @param remindType Reminder type for the device.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDeviceRemindType(NotificationConstant::RemindType &remindType) override;

    /**
     * @brief Publishes a continuous notification.
     *
     * @param request Notification requests that need to be posted.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode PublishContinuousTaskNotification(const sptr<NotificationRequest> &request) override;

    /**
     * @brief Cancels a continuous notification.
     *
     * @param label Identifies the label of the specified notification.
     * @param notificationId Identifies the id of the specified notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelContinuousTaskNotification(const std::string &label, int32_t notificationId) override;

    /**
     * @brief Publishes a reminder notification.
     *
     * @param reminder Identifies the reminder notification request that needs to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode PublishReminder(sptr<ReminderRequest> &reminder) override;

    /**
     * @brief Cancel a reminder notifications.
     *
     * @param reminderId Identifies the reminders id that needs to be canceled.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelReminder(const int32_t reminderId) override;

    /**
     * @brief Get all valid reminder notifications.
     *
     * @param reminders Identifies the list of all valid notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetValidReminders(std::vector<sptr<ReminderRequest>> &reminders) override;

    /**
     * @brief Cancel all reminder notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode CancelAllReminders() override;

    /**
     * @brief Add exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param date exclude date
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode AddExcludeDate(const int32_t reminderId, const uint64_t date) override;

    /**
     * @brief Clear exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DelExcludeDates(const int32_t reminderId) override;

    /**
     * @brief Get exclude date for reminder
     *
     * @param reminderId Identifies the reminders id.
     * @param dates exclude dates
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetExcludeDates(const int32_t reminderId, std::vector<uint64_t>& dates) override;

    /**
     * @brief Checks whether this device is support template.
     *
     * @param templateName Identifies the template name for searching as a condition.
     * @param support Identifies the support flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsSupportTemplate(const std::string &templateName, bool &support) override;

    /**
     * @brief Checks Whether the specified users is allowed to publish notifications.
     *
     * @param userId Identifies the user's id.
     * @param allowed Identifies the allowed flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode IsSpecialUserAllowedNotify(const int32_t &userId, bool &allowed) override;

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
    virtual ErrCode SetNotificationsEnabledByUser(const int32_t &deviceId, bool enabled) override;

    /**
     * @brief Delete all notifications by user.
     *
     * @param userId Indicates the user id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode DeleteAllByUser(const int32_t &userId) override;

    /**
     * @brief Set do not disturb date by user.
     *
     * @param userId Indicates the user id.
     * @param date Indicates NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetDoNotDisturbDate(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Get the do not disturb date by user.
     *
     * @param userId Indicates the user id.
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDoNotDisturbDate(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date) override;
    virtual ErrCode SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl) override;
    virtual ErrCode GetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, bool &enabled) override;
    virtual ErrCode GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled) override;

    /**
     * @brief Obtains specific datas via specified dump option.
     *
     * @param cmd Indicates the specified dump command.
     * @param bundle Indicates the specified bundle name.
     * @param userId Indicates the specified userId.
     * @param dumpInfo Indicates the container containing datas.
     * @return Returns check result.
     */
    virtual ErrCode ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo) override;

    /**
     * @brief Set whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns set enabled result.
     */
    virtual ErrCode SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled) override;

    /**
     * @brief Obtains whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns get enabled result.
     */
    virtual ErrCode GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled) override;

    /**
     * @brief Set badge number.
     *
     * @param badgeNumber The badge number.
     * @return Returns set badge number result.
     */
    virtual ErrCode SetBadgeNumber(int32_t badgeNumber, int32_t instanceKey) override;

    /**
     * @brief Set badge number by bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param badgeNumber The badge number.
     * @return Returns set badge number by bundle result.
     */
    virtual ErrCode SetBadgeNumberByBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber) override;

   /**
     * @brief Get slotFlags.
     *
     * @param badgeNumber The slotFlags.
     * @return Returns get slotFlags result.
     */
    virtual ErrCode GetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,
        uint32_t &slotFlags) override;

   /**
     * @brief Set slotFlags.
     *
     * @param badgeNumber The slotFlags.
     * @return Returns set slotFlags result.
     */
    virtual ErrCode SetSlotFlagsAsBundle(const sptr<NotificationBundleOption> &bundleOption,
        uint32_t slotFlags) override;

    /**
     * @brief Obtains allow notification application list.
     *
     * @param bundleOption Indicates the bundleOption vector.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption) override;

    /**
     * @brief Register Push Callback.
     *
     * @param pushCallback PushCallBack.
     * @param notificationCheckRequest Filter conditions for push check
     * @return Returns register PushCallback result.
     */
    ErrCode RegisterPushCallback(const sptr<IRemoteObject>& pushCallback,
        const sptr<NotificationCheckRequest>& notificationCheckRequest) override;

    /**
     * @brief Unregister Push Callback.
     *
     * @return Returns unregister push Callback result.
     */
    ErrCode UnregisterPushCallback() override;

    /**
     * @brief Set agent relationship.
     *
     * @param key Indicates storing agent relationship if the value is "PROXY_PKG".
     * @param value Indicates key-value pair of agent relationship.
     * @return Returns set result.
     */
    virtual ErrCode SetAdditionConfig(const std::string &key, const std::string &value) override;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param id Indicates the unique notification ID in the application.
     * @return Returns cancel result.
     */
    virtual ErrCode CancelAsBundleWithAgent(
        const sptr<NotificationBundleOption> &bundleOption, const int32_t id) override;

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetDistributedEnabledByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &deviceType, const bool enabled) override;

    /**
     * @brief get whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsDistributedEnabledByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &deviceType, bool &enabled) override;

    /**
     * @brief Get Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsSmartReminderEnabled(const std::string &deviceType, bool &enabled) override;

    /**
     * @brief Set Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetSmartReminderEnabled(const std::string &deviceType, const bool enabled) override;

    /**
     * @brief Set the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    virtual ErrCode SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status) override;

    /**
     * @brief Get do not disturb profile by id.
     *
     * @param id Profile id.
     * @param status Indicates the NotificationDoNotDisturbProfile object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetDoNotDisturbProfile(int32_t id, sptr<NotificationDoNotDisturbProfile> &profile) override;

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    /**
     * @brief Register Swing Callback.
     *
     * @param swingCallback SwingCallBack.
     * @return Returns register SwingCallback result.
     */
    ErrCode RegisterSwingCallback(const sptr<IRemoteObject>& swingCallback) override;
#endif

    /**
     * @brief Update Notification Timer by uid.
     *
     * @param uid uid.
     * @return Returns Update result.
     */
    virtual ErrCode UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused) override;

    /**
     * @brief set rule of generate hashCode.
     *
     * @param type generate hashCode.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetHashCodeRule(const uint32_t type) override;
    
private:

    ErrCode HandlePublish(MessageParcel &data, MessageParcel &reply);
    ErrCode HandlePublishNotificationForIndirectProxy(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancel(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelAll(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelAsBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelAsBundleOption(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelAsBundleAndUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleAddSlotByType(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleAddSlots(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveSlotByType(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveAllSlots(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSlots(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSlotByType(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSlotNumAsBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetActiveNotifications(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetActiveNotificationNums(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetAllActiveNotifications(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSpecialActiveNotifications(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetActiveNotificationByFilter(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetNotificationAgent(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetNotificationAgent(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCanPublishAsBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandlePublishAsBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetNotificationBadgeNum(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetBundleImportance(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsNotificationPolicyAccessGranted(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveNotification(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveAllNotifications(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveNotifications(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDelete(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDeleteByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDeleteAll(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSlotsByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSlotByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleUpdateSlots(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRequestEnableNotification(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetNotificationsEnabledForBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetNotificationsEnabledForAllBundles(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetNotificationsEnabledForSpecialBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetShowBadgeEnabledForBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetShowBadgeEnabledForBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetShowBadgeEnabled(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSubscribe(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleUnsubscribe(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsAllowedNotify(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsAllowedNotifySelf(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCanPopEnableNotificationDialog(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveEnableNotificationDialog(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsSpecialBundleAllowedNotify(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsDistributedEnabled(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleEnableDistributed(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleEnableDistributedByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleEnableDistributedSelf(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsDistributedEnableByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleShellDump(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelGroup(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveGroupByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDoNotDisturbDate(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDoesSupportDoNotDisturbMode(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsNeedSilentInDoNotDisturbMode(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDeviceRemindType(MessageParcel &data, MessageParcel &reply);
    ErrCode HandlePublishContinuousTaskNotification(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelContinuousTaskNotification(MessageParcel &data, MessageParcel &reply);
    ErrCode HandlePublishReminder(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelReminder(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetValidReminders(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelAllReminders(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleAddExcludeDate(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDelExcludeDates(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetExcludeDates(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsSupportTemplate(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsSpecialUserAllowedNotifyByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetNotificationsEnabledByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDeleteAllByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDoNotDisturbDateByUser(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetEnabledForBundleSlot(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetEnabledForBundleSlot(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetEnabledForBundleSlotSelf(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDistributedSetEnabledWithoutApp(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDistributedGetEnabledWithoutApp(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetBadgeNumber(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetBadgeNumberByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRegisterPushCallback(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleUnregisterPushCallback(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSubscribeLocalLiveView(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleTriggerLocalLiveView(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSubscribeSelf(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetAllNotificationEnableStatus(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetSlotFlagsAsBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetSlotFlagsAsBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetAdditionConfig(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetDistributedEnabledByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsDistributedEnabledByBundle(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetSmartReminderEnabled(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleIsSmartReminderEnabled(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCancelAsBundleWithAgent(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleAddDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleRemoveDoNotDisturbProfiles(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetTargetDeviceStatus(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleGetDoNotDisturbProfile(MessageParcel &data, MessageParcel &reply);
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    ErrCode HandleRegisterSwingCallback(MessageParcel &data, MessageParcel &reply);
#endif
    ErrCode HandleUpdateNotificationTimerByUid(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleSetHashCodeRule(MessageParcel &data, MessageParcel &reply);
    template<typename T>
    bool WriteParcelableVector(const std::vector<sptr<T>> &parcelableVector, MessageParcel &reply, ErrCode &result)
    {
        if (!reply.WriteInt32(result)) {
            ANS_LOGE("write result failed, ErrCode=%{public}d", result);
            return false;
        }

        if (!reply.WriteInt32(parcelableVector.size())) {
            ANS_LOGE("write ParcelableVector size failed");
            return false;
        }

        for (auto &parcelable : parcelableVector) {
            if (!reply.WriteStrongParcelable(parcelable)) {
                ANS_LOGE("write ParcelableVector failed");
                return false;
            }
        }
        return true;
    }

    template<typename T>
    bool ReadParcelableVector(std::vector<sptr<T>> &parcelableInfos, MessageParcel &data)
    {
        int32_t infoSize = 0;
        if (!data.ReadInt32(infoSize)) {
            ANS_LOGE("Failed to read Parcelable size.");
            return false;
        }

        parcelableInfos.clear();
        infoSize = (infoSize < MAX_PARCELABLE_VECTOR_NUM) ? infoSize : MAX_PARCELABLE_VECTOR_NUM;
        for (int32_t index = 0; index < infoSize; index++) {
            sptr<T> info = data.ReadStrongParcelable<T>();
            if (info == nullptr) {
                ANS_LOGE("Failed to read Parcelable infos.");
                return false;
            }
            parcelableInfos.emplace_back(info);
        }

        return true;
    }
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_FRAMEWORKS_ANS_CORE_INCLUDE_ANS_MANAGER_STUB_H
