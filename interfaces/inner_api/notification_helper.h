/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_HELPER_H

#include "ans_dialog_host_client.h"
#include "notification_bundle_option.h"
#include "distributed_bundle_option.h"
#include "notification_button_option.h"
#include "notification_do_not_disturb_date.h"
#include "notification_do_not_disturb_profile.h"
#include "enabled_notification_callback_data.h"
#include "notification_extension_subscription_info.h"
#include "notification_request.h"
#include "notification_slot.h"
#include "notification_sorting_map.h"
#include "notification_subscriber.h"
#include "notification_local_live_view_subscriber.h"
#include "want_params.h"
#include <memory>
#include "ians_operation_callback.h"
#include "notification_ringtone_info.h"

namespace OHOS {
namespace Notification {
class NotificationHelper {
public:
    /**
     * @brief Creates a notification slot.
     * @note You can call the NotificationRequest::SetSlotType(NotificationConstant::SlotType) method to bind the slot
     * for publishing. A NotificationSlot instance cannot be used directly after being initialized. Instead, you have to
     * call this method to create a notification slot and bind the slot ID to a NotificationRequest object so that the
     * notification published can have all the characteristics set in the NotificationSlot. After a notification slot is
     * created by using this method, only the name and description of the notification slot can be changed. Changes to
     * the other attributes, such as the vibration status and notification tone, will no longer take effect.
     *
     * @param slot Indicates the notification slot to be created, which is set by NotificationSlot.
     *             This parameter must be specified.
     * @return Returns add notification slot result.
     */
    static ErrCode AddNotificationSlot(const NotificationSlot &slot);

    /**
     * @brief Adds a notification slot by type.
     *
     * @param slotType Indicates the notification slot type to be added.
     * @return Returns add notification slot result.
     */
    static ErrCode AddSlotByType(const NotificationConstant::SlotType &slotType);

    /**
     * @brief Creates multiple notification slots.
     *
     * @param slots Indicates the notification slots to create.
     * @return Returns add notification slots result.
     */
    static ErrCode AddNotificationSlots(const std::vector<NotificationSlot> &slots);

    /**
     * @brief Deletes a created notification slot based on the slot ID.
     *
     * @param slotType Indicates the type of the slot, which is created by AddNotificationSlot
     *                 This parameter must be specified.
     * @return Returns remove notification slot result.
     */
    static ErrCode RemoveNotificationSlot(const NotificationConstant::SlotType &slotType);

    /**
     * @brief Deletes all notification slots.
     *
     * @return Returns remove all slots result.
     */
    static ErrCode RemoveAllSlots();

    /**
     * @brief Update all notification slots for the specified bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slots Indicates a list of new notification slots.
     * @return Returns update notification slots for bundle result.
     */
    static ErrCode UpdateNotificationSlots(
        const NotificationBundleOption &bundleOption, const std::vector<sptr<NotificationSlot>> &slots);

    /**
     * @brief Queries a created notification slot.
     *
     * @param slotType Indicates the ID of the slot, which is created by AddNotificationSlot(NotificationSlot). This
     *        parameter must be specified.
     * @param slot Indicates the created NotificationSlot.
     * @return Returns the get notification slot result.
     */
    static ErrCode GetNotificationSlot(const NotificationConstant::SlotType &slotType, sptr<NotificationSlot> &slot);

    /**
     * @brief Obtains all notification slots of this application.
     * @param slots Indicates the created NotificationSlot.
     * @return Returns all notification slots of this application.
     */
    static ErrCode GetNotificationSlots(std::vector<sptr<NotificationSlot>> &slots);

    /**
     * @brief Obtains number of slot.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param num Indicates number of slot.
     * @return Returns get slot number by bundle result.
     */
    static ErrCode GetNotificationSlotNumAsBundle(const NotificationBundleOption &bundleOption, uint64_t &num);

    /**
     * @brief Obtains all notification slots belonging to the specified bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slots Indicates a list of notification slots.
     * @return Returns get notification slots for bundle result.
     */
    static ErrCode GetNotificationSlotsForBundle(

        const NotificationBundleOption &bundleOption, std::vector<sptr<NotificationSlot>> &slots);

    /**
     * @brief Obtains all notification slots belonging to the specified bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slotType Indicates the type of the slot, which is created by AddNotificationSlot.
     * @param slot Indicates a notification slot.
     * @return Returns get notification slots for bundle result.
     */
    static ErrCode GetNotificationSlotForBundle(
        const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType,
        sptr<NotificationSlot> &slot);

    /**
     * Set whether the application slot is enabled.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slotType Indicates type of slot.
     * @param enabled the type of slot enabled.
     * @param isForceControl Indicates whether the slot is affected by the notification switch.
     * @return Returns get slot number by bundle result.
     */
    static ErrCode SetEnabledForBundleSlot(const NotificationBundleOption &bundleOption,
        const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl);

    /**
     * Obtains whether the application slot is enabled.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slotType Indicates type of slot.
     * @param enabled the type of slot enabled to get.
     * @return Returns get slot number by bundle result.
     */
    static ErrCode GetEnabledForBundleSlot(
        const NotificationBundleOption &bundleOption, const NotificationConstant::SlotType &slotType, bool &enabled);

    /**
     * Obtains whether the current application slot is enabled.
     *
     * @param slotType Indicates type of slot.
     * @param enabled the type of slot enabled to get.
     * @return Returns get enabled result.
     */
    static ErrCode GetEnabledForBundleSlotSelf(const NotificationConstant::SlotType &slotType, bool &enabled);

    /**
     * @brief Obtains slotflags of bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slotFlags Indicates slotFlags of bundle.
     * @return Returns get slotFlags by bundle result.
     */
    static ErrCode GetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption, uint32_t &slotFlags);

    /**
     * @brief Obtains slotFlags of bundle.
     *
     * @param slotFlags Indicates slotFlags of bundle.
     * @return Returns get slotflags by bundle result.
     */
    static ErrCode GetNotificationSettings(uint32_t &slotFlags);

    /**
     * @brief set slotflags of bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slotFlags Indicates slotFlags of bundle.
     * @return Returns get slotFlags by bundle result.
     */
    static ErrCode SetNotificationSlotFlagsAsBundle(const NotificationBundleOption &bundleOption, uint32_t slotFlags);

    /**
     * @brief Publishes a notification.
     * @note If a notification with the same ID has been published by the current application and has not been deleted,
     * this method will update the notification.
     *
     * @param request Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns publish notification result.
     */
    static ErrCode PublishNotification(const NotificationRequest &request,
        const std::string &instanceKey = "");

    /**
     * @brief Publishes a notification.
     * @note If a notification with the same ID has been published by the current application and has not been deleted,
     * this method will update the notification.
     *
     * @param request Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns publish notification result.
     */
    static ErrCode PublishNotificationForIndirectProxy(const NotificationRequest &request);

    /**
     * @brief Publishes a notification with a specified label.
     * @note If a notification with the same ID has been published by the current application and has not been deleted,
     *       this method will update the notification.
     *
     * @param label Indicates the label of the notification to publish.
     * @param request Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns publish notification result.
     */
    static ErrCode PublishNotification(const std::string &label, const NotificationRequest &request,
        const std::string &instanceKey = "");

    /**
     * @brief Cancels a published notification.
     *
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @return Returns cancel notification result.
     */
    static ErrCode CancelNotification(int32_t notificationId, const std::string &instanceKey = "");

    /**
     * @brief Cancels a published notification matching the specified label and notificationId.
     *
     * @param label Indicates the label of the notification to cancel.
     * @param notificationId Indicates the ID of the notification to cancel.
     * @return Returns cancel notification result.
     */
    static ErrCode CancelNotification(const std::string &label, int32_t notificationId,
        const std::string &instanceKey = "");

    /**
     * @brief Cancels all the published notifications.
     *
     * @note To cancel a specified notification, see CancelNotification(int32_t).
     * @return Returns cancel all notifications result.
     */
    static ErrCode CancelAllNotifications(const std::string &instanceKey = "");

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
    static ErrCode CancelAsBundle(int32_t notificationId, const std::string &representativeBundle, int32_t userId);

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle of application bundle your application is representing.
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @return Returns cancel notification result.
     */
    static ErrCode CancelAsBundle(const NotificationBundleOption &bundleOption, int32_t notificationId);

    /**
     * @brief Obtains the number of active notifications of the current application in the system.
     *
     * @param nums Indicates the number of active notifications of the current application.
     * @return Returns get active notification nums result.
     */
    static ErrCode GetActiveNotificationNums(uint64_t &num);

    /**
     * @brief Obtains active notifications of the current application in the system.
     *
     * @param  request Indicates active NotificationRequest objects of the current application.
     * @return Returns get active notifications result.
     */
    static ErrCode GetActiveNotifications(std::vector<sptr<NotificationRequest>> &request,
        const std::string &instanceKey = "");

    /**
     * @brief Checks whether your application has permission to publish notifications by calling
     * PublishNotificationAsBundle(string, NotificationRequest) in the name of another application indicated by the
     * given representativeBundle.
     *
     * @param representativeBundle Indicates the name of application bundle your application is representing.
     * @param canPublish Indicates whether your application has permission to publish notifications.
     * @return Returns can publish notification as bundle result.
     */
    static ErrCode CanPublishNotificationAsBundle(const std::string &representativeBundle, bool &canPublish);

    /**
     * @brief Publishes a notification in the name of a specified application bundle.
     * @note If the notification to be published has the same ID as a published notification that has not been canceled,
     * the existing notification will be replaced by the new one.
     *
     * @param request Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @param representativeBundle Indicates the name of the application bundle that allows your application to publish
     *                             notifications for it by calling setNotificationAgent.
     * @return Returns publish notification as bundle result.
     */
    static ErrCode PublishNotificationAsBundle(
        const std::string &representativeBundle, const NotificationRequest &request);

    /**
     * @brief Sets the number of active notifications of the current application as the number to be displayed on the
     * notification badge.
     *
     * @return Returns set notification badge num result.
     */
    static ErrCode SetNotificationBadgeNum();

    /**
     * @brief Sets the number to be displayed on the notification badge of the application.
     *
     * @param num Indicates the number to display. A negative number indicates that the badge setting remains unchanged.
     *            The value 0 indicates that no badge is displayed on the application icon.
     *            If the value is greater than 99, 99+ will be displayed.
     * @return Returns set notification badge num result.
     */
    static ErrCode SetNotificationBadgeNum(int32_t num);

    /**
     * @brief Checks whether this application has permission to publish notifications. The caller must have
     * system permissions to call this method.
     *
     * @param  allowed True if this application has the permission; returns false otherwise
     * @return Returns is allowed notify result.
     */
    static ErrCode IsAllowedNotify(bool &allowed);

    /**
     * @brief Checks whether this application has permission to publish notifications.
     *
     * @param  allowed True if this application has the permission; returns false otherwise
     * @return Returns is allowed notify result.
     */
    static ErrCode IsAllowedNotifySelf(bool &allowed);

    /**
     * @brief Checks whether this application can pop enable notification dialog.
     *
     * @param  canPop True if can pop enable notification dialog
     * @return Returns is canPop result.
     */
    static ErrCode CanPopEnableNotificationDialog(sptr<AnsDialogHostClient> &hostClient,
        bool &canPop, std::string &bundleName);

    /**
     * @brief remove enable notification dialog.
     *
     * @return Returns remove dialog result.
     */
    static ErrCode RemoveEnableNotificationDialog();

    /**
     * @brief Allow the current application to publish notifications on a specified device.
     *
     * @param deviceId Indicates the ID of the device running the application. At present, this parameter can
     *                 only be null or an empty string, indicating the current device.
     * @return Returns set notifications enabled for default bundle result.
     */
    static ErrCode RequestEnableNotification(std::string &deviceId,
        sptr<AnsDialogHostClient> &hostClient,
        sptr<IRemoteObject> &callerToken);

    /**
     * @brief Allow application to publish notifications.
     *
     * @param bundleName bundle name.
     * @param uid uid.
     * @return Returns set notifications enabled for the bundle result.
     */
    static ErrCode RequestEnableNotification(const std::string bundleName, const int32_t uid);

    /**
     * @brief Checks whether this application has permission to modify the Do Not Disturb (DND) notification policy.
     *
     * @param hasPermission True if this application is suspended; false otherwise.
     * @return Returns has notification policy access permission.
     */
    static ErrCode HasNotificationPolicyAccessPermission(bool &hasPermission);

    /**
     * @brief Obtains the importance level of this application.
     *
     * @param  importance Indicates the importance level of this application, which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
     * @return Returns get bundle importance result
     */
    static ErrCode GetBundleImportance(NotificationSlot::NotificationLevel &importance);

    /**
     * @brief Subscribes to notifications from all applications. This method can be called only by applications
     * with required system permissions.
     * @note  To subscribe to a notification, inherit the {NotificationSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the notification is published, subscribers that meet the filter criteria can receive the
     *        notification. To subscribe to notifications published only by specified sources, for example,
     *        notifications from certain applications,
     *        call the {SubscribeNotification(NotificationSubscriber, NotificationSubscribeInfo)} method.
     * @deprecated This function is deprecated,
     *             use 'SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)'.
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode SubscribeNotification(const NotificationSubscriber &subscriber);

    /**
     * @brief Subscribes to notifications from all applications. This method can be called only by applications
     * with required system permissions.
     * @note  To subscribe to a notification, inherit the {NotificationSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the notification is published, subscribers that meet the filter criteria can receive the
     *        notification. To subscribe to notifications published only by specified sources, for example,
     *        notifications from certain applications,
     *        call the {SubscribeNotification(NotificationSubscriber, NotificationSubscribeInfo)} method.
     *
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber);

    /**
     * @brief Subscribes to notifications from the appliaction self.
     * @note  To subscribe to a notification, inherit the {NotificationSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the notification is published, subscribers that meet the filter criteria can receive the
     *        notification.
     * @deprecated This function is deprecated,
     *             use 'SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber)'.
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode SubscribeNotificationSelf(const NotificationSubscriber &subscriber);

    /**
     * @brief Subscribes to notifications from the appliaction self.
     * @note  To subscribe to a notification, inherit the {NotificationSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the notification is published, subscribers that meet the filter criteria can receive the
     *        notification.
     *
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode SubscribeNotificationSelf(const std::shared_ptr<NotificationSubscriber> &subscriber);

    /**
     * @brief Subscribes to all notifications based on the filtering criteria. This method can be called only
     * by applications with required system permissions.
     * @note  After {subscribeInfo} is specified, a subscriber receives only the notifications that
     *        meet the filter criteria specified by {subscribeInfo}.
     *        To subscribe to a notification, inherit the {NotificationSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the notification is published, subscribers that meet the filter criteria can receive the
     *        notification. To subscribe to and receive all notifications, call the
     *        {SubscribeNotification(NotificationSubscriber)} method.
     * @deprecated This function is deprecated,
     *             use 'SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
     *             const sptr<NotificationSubscribeInfo> &subscribeInfo)'.
     * @param subscriber Indicates the subscribers to receive notifications. This parameter must be specified.
     *                   For details, see {NotificationSubscriber}.
     * @param subscribeInfo Indicates the filters for specified notification sources, including application name,
     *                      user ID, or device name. This parameter is optional.
     * @return Returns subscribe notification result.
     */
    static ErrCode SubscribeNotification(
        const NotificationSubscriber &subscriber, const NotificationSubscribeInfo &subscribeInfo);

    /**
     * @brief Subscribes to all notifications based on the filtering criteria. This method can be called only
     * by applications with required system permissions.
     * @note  After {subscribeInfo} is specified, a subscriber receives only the notifications that
     *        meet the filter criteria specified by {subscribeInfo}.
     *        To subscribe to a notification, inherit the {NotificationSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the notification is published, subscribers that meet the filter criteria can receive the
     *        notification. To subscribe to and receive all notifications, call the
     *        {SubscribeNotification(NotificationSubscriber)} method.
     *
     * @param subscriber Indicates the subscribers to receive notifications. This parameter must be specified.
     *                   For details, see {NotificationSubscriber}.
     * @param subscribeInfo Indicates the filters for specified notification sources, including application name,
     *                      user ID, or device name. This parameter is optional.
     * @return Returns subscribe notification result.
     */
    static ErrCode SubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
        const sptr<NotificationSubscribeInfo> &subscribeInfo);

    /**
     * @brief Subscribes the localLiveView button click. This method can be called only
     * by applications with required system permissions.
     * @note  To subscribe to a button click, inherit the {NotificationLocalLiveViewSubscriber} class, override its
     *        callback methods and create a subscriber. The subscriber will be used as a parameter of this method.
     *        After the button is clicked, subscribers that meet the filter criteria can receive the response
     *
     * @param subscriber Indicates the subscribers to receive notifications. This parameter must be specified.
     *                   For details, see {NotificationSubscriber}.
     * @return Returns subscribe notification result.
     */
    static ErrCode SubscribeLocalLiveViewNotification(const NotificationLocalLiveViewSubscriber &subscriber,
        const bool isNative = true);

    /**
     * @brief Unsubscribes from all notifications. This method can be called only by applications with required
     * system permissions.
     * @note Generally, you subscribe to a notification by calling the
     *       {SubscribeNotification(NotificationSubscriber)} method. If you do not want your application
     *       to receive a notification any longer, unsubscribe from that notification using this method.
     *       You can unsubscribe from only those notifications that your application has subscribed to.
     *        To unsubscribe from notifications published only by specified sources, for example,
     *       notifications from certain applications, call the
     *       {UnSubscribeNotification(NotificationSubscriber, NotificationSubscribeInfo)} method.
     * @deprecated This function is deprecated,
     *             use 'UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber)'.
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode UnSubscribeNotification(NotificationSubscriber &subscriber);

    /**
     * @brief Unsubscribes from all notifications. This method can be called only by applications with required
     * system permissions.
     * @note Generally, you subscribe to a notification by calling the
     *       {SubscribeNotification(NotificationSubscriber)} method. If you do not want your application
     *       to receive a notification any longer, unsubscribe from that notification using this method.
     *       You can unsubscribe from only those notifications that your application has subscribed to.
     *        To unsubscribe from notifications published only by specified sources, for example,
     *       notifications from certain applications, call the
     *       {UnSubscribeNotification(NotificationSubscriber, NotificationSubscribeInfo)} method.
     *
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber);

    /**
     * @brief Unsubscribes from all notifications based on the filtering criteria. This method can be called
     * only by applications with required system permissions.
     * @note A subscriber will no longer receive the notifications from specified notification sources.
     * @deprecated This function is deprecated,
     *             use 'UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
     *             const sptr<NotificationSubscribeInfo> &subscribeInfo)'.
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @param subscribeInfo Indicates the filters for , including application name,
     *                      user ID, or device name. This parameter is optional.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode UnSubscribeNotification(NotificationSubscriber &subscriber, NotificationSubscribeInfo subscribeInfo);

    /**
     * @brief Unsubscribes from all notifications based on the filtering criteria. This method can be called
     * only by applications with required system permissions.
     * @note A subscriber will no longer receive the notifications from specified notification sources.
     *
     * @param subscriber Indicates the {NotificationSubscriber} to receive notifications.
     *                   This parameter must be specified.
     * @param subscribeInfo Indicates the filters for , including application name,
     *                      user ID, or device name. This parameter is optional.
     * @return Returns unsubscribe notification result.
     */
    static ErrCode UnSubscribeNotification(const std::shared_ptr<NotificationSubscriber> &subscriber,
        const sptr<NotificationSubscribeInfo> &subscribeInfo);

    /**
     * @brief Trigger the local live view after the button has been clicked.
     * @note Your application must have platform signature to use this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application whose notifications has been clicked.
     * @param notificationId Indicates the id of the notification.
     * @param buttonOption Indicates which button has been clicked.
     * @return Returns trigger localLiveView result.
     */
    static ErrCode TriggerLocalLiveView(const NotificationBundleOption &bundleOption,
        const int32_t notificationId, const NotificationButtonOption &buttonOption);

    /**
     * @brief Removes a specified removable notification of other applications.
     * @note Your application must have platform signature to use this method.
     *
     * @param key Indicates the key of the notification to remove.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns remove notification result.
     */
    static ErrCode RemoveNotification(const std::string &key, int32_t removeReason);

    /**
     * @brief Removes a specified removable notification of other applications.
     * @note Your application must have platform signature to use this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application whose notifications are to be removed.
     * @param notificationId Indicates the id of the notification to remove.
     * @param label Indicates the label of the notification to remove.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns remove notification result.
     */
    static ErrCode RemoveNotification(const NotificationBundleOption &bundleOption,
        const int32_t notificationId, const std::string &label, int32_t removeReason);

    /**
     * @brief Removes a specified removable notification of other applications.
     * @note Your application must have platform signature to use this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application whose notifications are to be removed.
     * @return Returns remove notification result.
     */
    static ErrCode RemoveAllNotifications(const NotificationBundleOption &bundleOption);

    static ErrCode RemoveNotifications(const std::vector<std::string> hashcodes, int32_t removeReason);

    /**
     * @brief Removes all removable notifications of a specified bundle.
     * @note Your application must have platform signature to use this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application whose notifications are to be removed.
     * @return Returns remove notifications result.
     */
    static ErrCode RemoveNotificationsByBundle(const NotificationBundleOption &bundleOption);

    /**
     * @brief Removes all removable notifications in the system.
     * @note Your application must have platform signature to use this method.
     * @return Returns remove notifications result.
     */
    static ErrCode RemoveNotifications();

    /**
     * @brief Removes Distributed notifications in the system.
     * @note Your application must have platform signature to use this method.
     * @return Returns remove notifications result.
     */
    static ErrCode RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
        const NotificationConstant::SlotType& slotType,
        const NotificationConstant::DistributedDeleteType& deleteType,
        const int32_t removeReason, const std::string& deviceId = "");

    /**
     * @brief Obtains all active notifications in the current system. The caller must have system permissions to
     * call this method.
     *
     * @param notification Indicates all active notifications of this application.
     * @return Returns get all active notifications
     */
    static ErrCode GetAllActiveNotifications(std::vector<sptr<Notification>> &notification);

    /**
     * @brief Obtains all active notifications by slot type in the current system. The caller must have system
     * permissions to call this method.
     *
     * @param notification Indicates all active notifications of this application.
     * @return Returns get all active notifications
     */
    static ErrCode GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
        const NotificationConstant::SlotType slotType);

    /**
     * @brief Obtains the active notifications corresponding to the specified key in the system. To call this method
     * to obtain particular active notifications, you must have received the notifications and obtained the key
     * via {Notification::GetKey()}.
     *
     * @param key Indicates the key array for querying corresponding active notifications.
     *            If this parameter is null, this method returns all active notifications in the system.
     * @param notification Indicates the set of active notifications corresponding to the specified key.
     * @return Returns get all active notifications.
     */
    static ErrCode GetAllActiveNotifications(
        const std::vector<std::string> key, std::vector<sptr<Notification>> &notification);

    /**
     * @brief Obtains the active notifications by filter.
     * @param filter
     * @param extraInfo
     * @return
     */
    static ErrCode GetActiveNotificationByFilter(
        const LiveViewFilter &filter, sptr<NotificationRequest> &request);

    /**
     * @brief Checks whether a specified application has the permission to publish notifications. If bundle specifies
     * the current application, no permission is required for calling this method. If bundle specifies another
     * application, the caller must have system permissions.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param allowed True if the application has permissions; false otherwise.
     * @return Returns is allowed notify result.
     */
    static ErrCode IsAllowedNotify(const NotificationBundleOption &bundleOption, bool &allowed);

    /**
     * @brief Sets whether to allow all applications to publish notifications on a specified device. The caller must
     * have system permissions to call this method.
     *
     * @param deviceId Indicates the ID of the device running the application. At present, this parameter can only
     *                 be null or an empty string, indicating the current device.
     * @param enabled Specifies whether to allow all applications to publish notifications. The value true
     *                indicates that notifications are allowed, and the value false indicates that notifications
     *                are not allowed.
     * @return Returns set notifications enabled for all bundles result.
     */
    static ErrCode SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled);

    /**
     * @brief Sets whether to allow the current application to publish notifications on a specified device. The caller
     * must have system permissions to call this method.
     *
     * @param deviceId Indicates the ID of the device running the application. At present, this parameter can
     *                 only be null or an empty string, indicating the current device.
     * @param enabled Specifies whether to allow the current application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for default bundle result.
     */
    static ErrCode SetNotificationsEnabledForDefaultBundle(const std::string &deviceId, bool enabled);

    /**
     * @brief Sets whether to allow a specified application to publish notifications on a specified device. The caller
     * must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceId Indicates the ID of the device running the application. At present, this parameter can only
     *                 be null or an empty string, indicating the current device.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that notifications
     *                are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    static ErrCode SetNotificationsEnabledForSpecifiedBundle(
        const NotificationBundleOption &bundleOption, std::string &deviceId, bool enabled);

    /**
     * @brief Sets whether to allow a specified application to show badge.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to show badge.
     * @return Returns set result.
     */
    static ErrCode SetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool enabled);

    /**
     * @brief Obtains the flag that whether to allow a specified application to show badge.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to show badge.
     * @return Returns get result.
     */
    static ErrCode GetShowBadgeEnabledForBundle(const NotificationBundleOption &bundleOption, bool &enabled);

    /**
     * @brief Obtains the flag that whether to allow the current application to show badge.
     *
     * @param enabled Specifies whether to allow the given application to show badge.
     * @return Returns get result.
     */
    static ErrCode GetShowBadgeEnabled(bool &enabled);

    /**
     * @brief Cancel the notification of the specified group of this application.
     *
     * @param groupName Indicates the specified group name.
     * @return Returns cancel group result.
     */
    static ErrCode CancelGroup(const std::string &groupName, const std::string &instanceKey = "");

    /**
     * @brief Remove the notification of the specified group of the specified application.
     *
     * @param bundleOption Indicates the bundle name and uid of the specified application.
     * @param groupName Indicates the specified group name.
     * @return Returns remove group by bundle result.
     */
    static ErrCode RemoveGroupByBundle(const NotificationBundleOption &bundleOption, const std::string &groupName);

    /**
     * @brief Sets the do not disturb time.
     * @note Your application must have system signature to call this method.
     *
     * @param doNotDisturbDate Indicates the do not disturb time to set.
     * @return Returns set do not disturb time result.
     */
    static ErrCode SetDoNotDisturbDate(const NotificationDoNotDisturbDate &doNotDisturbDate);

    /**
     * @brief Obtains the do not disturb time.
     * @note Your application must have system signature to call this method.
     *
     * @param doNotDisturbDate Indicates the do not disturb time to get.
     * @return Returns set do not disturb time result.
     */
    static ErrCode GetDoNotDisturbDate(NotificationDoNotDisturbDate &doNotDisturbDate);

    /**
     * @brief Obtains the flag that whether to support do not disturb mode.
     *
     * @param doesSupport Specifies whether to support do not disturb mode.
     * @return Returns check result.
     */
    static ErrCode DoesSupportDoNotDisturbMode(bool &doesSupport);

    /**
     * @brief Is coming call need silent in do not disturb mode.
     *
     * @param phoneNumber the calling format number.
     * @return Returns silent in do not disturb mode.
     */
    static ErrCode IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType);

    /**
     * @brief Check if the device supports distributed notification.
     *
     * @param enabled True if the device supports distributed notification; false otherwise.
     * @return Returns is distributed enabled result.
     */
    static ErrCode IsDistributedEnabled(bool &enabled);

    /**
     * @brief Set whether the device supports distributed notifications.
     *
     * @param enable Specifies whether to enable the device to support distributed notification.
     *               The value true indicates that the device is enabled to support distributed notifications, and
     *               the value false indicates that the device is forbidden to support distributed notifications.
     * @return Returns enable distributed result.
     */
    static ErrCode EnableDistributed(const bool enabled);

    /**
     * @brief Set whether an application supports distributed notifications.
     *
     * @param bundleOption Indicates the bundle name and uid of an application.
     * @param enabled Specifies whether to enable an application to support distributed notification.
     *                The value true indicates that the application is enabled to support distributed notifications,
     *                and the value false indicates that the application is forbidden to support distributed
     *                notifications.
     * @return Returns enable distributed by bundle result.
     */
    static ErrCode EnableDistributedByBundle(const NotificationBundleOption &bundleOption, const bool enabled);

    /**
     * @brief Set whether this application supports distributed notifications.
     *
     * @param enabled Specifies whether to enable this application to support distributed notification.
     *                The value true indicates that this application is enabled to support distributed notifications,
     *                and the value false indicates that this application is forbidden to support distributed
     *                notifications.
     * @return Returns enable distributed self result.
     */
    static ErrCode EnableDistributedSelf(const bool enabled);

    /**
     * @brief Check whether an application supports distributed notifications.
     *
     * @param bundleOption Indicates the bundle name and uid of an application.
     * @param enabled True if the application supports distributed notification; false otherwise.
     * @return Returns is distributed enabled by bundle result.
     */
    static ErrCode IsDistributedEnableByBundle(const NotificationBundleOption &bundleOption, bool &enabled);

    /**
     * @brief Obtains the device remind type.
     * @note Your application must have system signature to call this method.
     *
     * @param remindType Indicates the device remind type to get.
     * @return Returns get device reminder type result.
     */
    static ErrCode GetDeviceRemindType(NotificationConstant::RemindType &remindType);

    /**
     * @brief Publishes a continuous task notification.
     * @param request Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns publish continuous task notification result.
     */
    static ErrCode PublishContinuousTaskNotification(const NotificationRequest &request);

    /**
     * @brief Cancels a published continuous task notification matching the specified label and notificationId.
     *
     * @param label Indicates the label of the continuous task notification to cancel.
     * @param notificationId Indicates the ID of the continuous task notification to cancel.
     * @return Returns cancel continuous task notification result.
     */
    static ErrCode CancelContinuousTaskNotification(const std::string &label, int32_t notificationId);

    /**
     * @brief Obtains whether the template is supported by the system.
     *
     * @param support Indicates whether is it a system supported template.
     * @return Returns check result.
     */
    static ErrCode IsSupportTemplate(const std::string &templateName, bool &support);

    /**
     * @brief Checks whether this application has permission to publish notifications under the user.
     *
     * @param userId Indicates the userId of the application.
     * @param allowed True if the application has permissions; false otherwise.
     * @return Returns get allowed result.
     */
    static ErrCode IsAllowedNotify(const int32_t &userId, bool &allowed);

    /**
     * @brief Sets whether to allow all applications to publish notifications on a specified user.
     * The caller must have system permissions to call this method.
     *
     * @param userId Indicates the ID of the user running the application.
     * @param enabled Specifies whether to allow all applications to publish notifications. The value true
     *                indicates that notifications are allowed, and the value false indicates that notifications
     *                are not allowed.
     * @return Returns set notifications enabled for all bundles result.
     */
    static ErrCode SetNotificationsEnabledForAllBundles(const int32_t &userId, bool enabled);

    /**
     * @brief Removes notifications under specified user.
     * @note Your application must have platform signature to use this method.
     *
     * @param userId Indicates the ID of user whose notifications are to be removed.
     * @return Returns remove notification result.
     */
    static ErrCode RemoveNotifications(const int32_t &userId);

    /**
     * @brief Sets the do not disturb time on a specified user.
     * @note Your application must have system signature to call this method.
     *
     * @param userId Indicates the specific user.
     * @param doNotDisturbDate Indicates the do not disturb time to set.
     * @return Returns set do not disturb time result.
     */
    static ErrCode SetDoNotDisturbDate(const int32_t &userId, const NotificationDoNotDisturbDate &doNotDisturbDate);

    /**
     * @brief Obtains the do not disturb time on a specified user.
     * @note Your application must have system signature to call this method.
     *
     * @param userId Indicates the specific user.
     * @param doNotDisturbDate Indicates the do not disturb time to get.
     * @return Returns set do not disturb time result.
     */
    static ErrCode GetDoNotDisturbDate(const int32_t &userId, NotificationDoNotDisturbDate &doNotDisturbDate);

    /**
     * @brief Obtains the do not disturb  on a specified user.
     * @note Your application must have system signature to call this method.
     *
     * @param profiles Indicates the do not disturb time to add.
     * @return Returns set do not disturb time result.
     */
    static ErrCode AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);

    /**
     * @brief Obtains the do not disturb on a specified user.
     * @note Your application must have system signature to call this method.
     *
     * @param profiles Indicates the do not disturb time to remove.
     * @return Returns set do not disturb time result.
     */
    static ErrCode RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles);

    /**
     * @brief Set whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns set enabled result.
     */
    static ErrCode SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled);

    /**
     * @brief Obtains whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns get enabled result.
     */
    static ErrCode GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled);

    /**
     * @brief Set badge number.
     *
     * @param badgeNumber The badge number.
     * @return Returns set badge number result.
     */
    static ErrCode SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey = "");

    /**
     * @brief Set badge number by bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param badgeNumber The badge number.
     * @return Returns set badge number by bundle result.
     */
    static ErrCode SetBadgeNumberByBundle(const NotificationBundleOption &bundleOption, int32_t badgeNumber);

    /**
     * @brief Set badge number for dh by bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param badgeNumber The badge number.
     * @return Returns set badge number by bundle result.
     */
    static ErrCode SetBadgeNumberForDhByBundle(const NotificationBundleOption &bundleOption, int32_t badgeNumber);

    /**
     * @brief Obtains allow notification application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption);

    /**
     * @brief Obtains allow liveview application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption);

    /**
     * @brief Obtains allow distribued application list.
     *
     * @param deviceType Indicates device type.
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetAllDistribuedEnabledBundles(const std::string &deviceType,
        std::vector<NotificationBundleOption> &bundleOption);

    /**
     * @brief Register Push Callback.
     *
     * @param pushCallback push appliction's Callback.
     * @param notificationCheckRequest Filter conditions for push check.
     * @return Returns register push callback result.
     */
    static ErrCode RegisterPushCallback(
        const sptr<IRemoteObject>& pushCallback, const sptr<NotificationCheckRequest> &notificationCheckRequest);

    /**
     * @brief Unregister Push Callback.
     *
     * @return Returns unregister push Callback result.
     */
    static ErrCode UnregisterPushCallback();

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
    static ErrCode SetDistributedEnabledByBundle(
        const NotificationBundleOption &bundleOption, const std::string &deviceType, const bool enabled);

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundles Indicates the bundles.
     * @param deviceType Indicates the type of the device running the application.
     * @return Returns set distributed enabled for specified bundle result.
     */
    static ErrCode SetDistributedBundleOption(
        const std::vector<DistributedBundleOption> &bundles, const std::string &deviceType);

    /**
     * @brief Get whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    static ErrCode IsDistributedEnabledByBundle(
        const NotificationBundleOption &bundleOption, const std::string &deviceType, bool &enabled);

    /**
     * @brief Configuring Whether to Synchronize Common Notifications to Target Devices.
     *
     * @param deviceType Target device type.
     * @param enabled Whether to Synchronize Common Notifications to Target Devices.
     * @return Returns configuring Whether to Synchronize Common Notifications to Target Devices result.
     */
    static ErrCode SetDistributedEnabled(const std::string &deviceType, const bool &enabled);

    /**
     * @brief Querying Whether to Synchronize Common Devices to Target Devices.
     *
     * @param deviceType Target device type.
     * @param enabled Whether to Synchronize Common Notifications to Target Devices.
     * @return Returns Whether to Synchronize Common Notifications to Target Devices result.
     */
    static ErrCode IsDistributedEnabled(const std::string &deviceType, bool &enabled);

    /**
     * @brief Obtains the set of supported distributed abilities.
     *
     * @param abilityId The set of supported distributed abilities.
     * @return Returns result in Obtains the set of supported distributed abilities.
     */
    static ErrCode GetDistributedAbility(int32_t &abilityId);

    /**
     * @brief Get the target device's authorization status.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param deviceId The id of the target device.
     * @param userId The userid of the target device.
     * @param isAuth Return The authorization status.
     * @return Returns get result.
     */
    static ErrCode GetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth);

    /**
     * @brief Set the target device's authorization status.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param deviceId The id of the target device.
     * @param userId The userid of the target device.
     * @param isAuth The authorization status.
     * @return Returns set result.
     */
    static ErrCode SetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth);

    /**
     * @brief Get Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    static ErrCode IsSmartReminderEnabled(const std::string &deviceType, bool &enabled);

    /**
     * @brief Set Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    static ErrCode SetSmartReminderEnabled(const std::string &deviceType, const bool enabled);

    /**
     * @brief Get Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    static ErrCode IsSilentReminderEnabled(const NotificationBundleOption &bundleOption, int32_t &enableStatus);

    /**
     * @brief Set Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    static ErrCode SetSilentReminderEnabled(const NotificationBundleOption &bundleOption, const bool enabled);

    /**
     * @brief Set the channel switch for collaborative reminders.
       The caller must have system permissions to call this method.
     *
     * @param slotType Indicates the slot type of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Indicates slot switch status.
     * @return Returns set channel switch result.
     */
    static ErrCode SetDistributedEnabledBySlot(
        const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled);

    /**
     * @brief Query the channel switch for collaborative reminders.
       The caller must have system permissions to call this method.
     *
     * @param slotType Indicates the slot type of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Indicates slot switch status.
     * @return Returns channel switch result.
     */
    static ErrCode IsDistributedEnabledBySlot(
        const NotificationConstant::SlotType &slotType, const std::string &deviceType, bool &enabled);

    /**
     * @brief Set agent relationship.
     *
     * @param key Indicates storing agent relationship if the value is "PROXY_PKG".
     * @param value Indicates key-value pair of agent relationship.
     * @return Returns set result.
     */
    static ErrCode SetAdditionConfig(const std::string &key, const std::string &value);

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param id Indicates the unique notification ID in the application.
     * @return Returns cancel result.
     */
    static ErrCode CancelAsBundleWithAgent(const NotificationBundleOption &bundleOption, const int32_t id);

    /**
     * @brief Set the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    static ErrCode SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
        const std::string deviceId = std::string());

    /**
     * @brief Set the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @param controlFlag The control flag.
     * @return Returns set result.
     */
    static ErrCode SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
        const uint32_t controlFlag, const std::string deviceId = std::string(), int32_t userId = 0);

    /**
     * @brief set target device of bundle list.
     *
     * @param deviceType device type.
     * @param operatorType operation type.
     * @param bundleList device of bundle list.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        int operatorType, const std::vector<std::string>& bundleList, const std::vector<std::string>& labelList);

    /**
     * @brief Get the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    static ErrCode GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
        std::string& deviceId, int32_t& userId);

    /**
     * @brief get target device of bundle list.
     *
     * @param deviceType device type.
     * @param deviceId device udid.
     * @param bundleList device of bundle list.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        std::vector<std::string>& bundleList, std::vector<std::string>& labelList);

    /**
     * @brief set target device of bundle list.
     *
     * @param deviceType device type.
     * @param operatorType operation type.
     * @param notificaitonEnable notification switch.
     * @param liveViewEnable live view switch.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
        bool notificaitonEnable, bool liveViewEnable);

    /**
     * @brief Register Swing Callback Function.
     *
     * @param swingCallback swing Callback Function.
     * @return Returns register swing callback result.
     */
    static ErrCode RegisterSwingCallback(const std::function<void(bool, int)> swingCbFunc);

    /**
     * @brief Get do not disturb profile by id.
     *
     * @param id Profile id.
     * @param status Indicates the NotificationDoNotDisturbProfile objects.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile);

    /**
     * @brief Update Notification Timer by uid
     *
     * @param uid uid.
     * @return Returns Update result.
     */
    static ErrCode UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused);

    /**
     * @brief Whether reminders are allowed.
     *
     * @param bundleName app bundleName
     * @param isAllowUseReminder is allow use reminder
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder);

    /**
     * @brief Set switch and bundle list of disable notification feature.
     *
     * @param notificationDisable Switch and bundle list of disable notification feature.
     * @return Returns set result.
     */
    static ErrCode DisableNotificationFeature(const NotificationDisable &notificationDisable);

    /**
     * @brief Distribution operation based on hashCode.
     *
     * @param hashCode Unique ID of the notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode DistributeOperation(sptr<NotificationOperationInfo>& operationInfo,
        const sptr<IAnsOperationCallback> &callback);

    /**
     * @brief Reply distribute operation.
     *
     * @param hashCode Unique ID of the notification.
     * @param result The result of the distribute operation.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode ReplyDistributeOperation(const std::string& hashCode, const int32_t result);

    /**
     * @brief Get notificationRequest by hashCode.
     *
     * @param hashCode Unique ID of the notification.
     * @param notificationRequest The request of of the notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetNotificationRequestByHashCode(
        const std::string& hashCode, sptr<NotificationRequest>& notificationRequest);

    /**
     * @brief set rule of generate hashCode.
     *
     * @param type generate hashCode.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode SetHashCodeRule(const uint32_t type);

    /**
     * @brief get distributed device list.
     *
     * @param deviceTypes Indicates device types.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetDistributedDevicelist(std::vector<std::string> &deviceTypes);

    /**
     * Set the application default slot is enabled.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slotType Indicates type of slot.
     * @param enabled the type of slot enabled.
     * @param isForceControl Indicates whether the slot is affected by the notification switch.
     * @return Returns get slot number by bundle result.
     */
    static ErrCode SetDefaultSlotForBundle(const NotificationBundleOption& bundleOption,
        const NotificationConstant::SlotType &slotType, bool enabled, bool isForceControl);

    /**
     * @brief Set check config.
     *
     * @param response Indicates the result of check.
     * @param requestId Indicates the request.
     * @param key Indicates live view config if the value is "APP_LIVEVIEW_CONFIG".
     * @param value Indicates key-value pair of live view.
     * @return Returns set result.
     */
    static ErrCode SetCheckConfig(int32_t response, const std::string& requestId, const std::string& key,
        const std::string& value);

    /**
     * @brief Set the notification extension subscription state.
     * @param bundle Indicates the bundle name and uid of the application.
     * @param ringtoneInfo Custom ringtone information.
     * @return Returns set result.
     */
    static ErrCode SetRingtoneInfoByBundle(const NotificationBundleOption &bundle,
        const NotificationRingtoneInfo &ringtoneInfo);

    /**
     * @brief Get the notification extension subscription state.
     * @param bundle Indicates the bundle name and uid of the application.
     * @param ringtoneInfo Custom ringtone information.
     * @return Returns get result.
     */
    static ErrCode GetRingtoneInfoByBundle(const NotificationBundleOption &bundle,
        NotificationRingtoneInfo &ringtoneInfo);

    /**
     * @brief get live view config.
     *
     * @param bundleList Indicates bundle name.
     * @return Returns set result.
     */
    static ErrCode GetLiveViewConfig(const std::vector<std::string>& bundleList);

    /**
     * @brief Subscribe the notification when the bluetooth addr is connected.
     *
     * @param infos The info to be subscribe.
     * @return Returns subscribe result.
     */
    static ErrCode NotificationExtensionSubscribe(
        const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos);

    /**
     * @brief Unsubscribe the notification.
     * @return Returns unsubscribe result.
     */
    static ErrCode NotificationExtensionUnsubscribe();

    /**
     * @brief Obtains the subscribe info for app.
     * @param infos The returned subscribe info.
     * @return Returns get result.
     */
    static ErrCode GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos);

    /**
     * @brief Obtains whether the notification extension subscription is enabled.
     * @param enabled True if the subscription is enabled.
     * @return Returns get result.
     */
    static ErrCode IsUserGranted(bool& enabled);

    /**
     * @brief Obtains whether the notification extension subscription is enabled.
     * @param targetBundle The bundle option to be queried.
     * @param enabled True if the subscription is enabled.
     * @return Returns get result.
     */
    static ErrCode GetUserGrantedState(const NotificationBundleOption& targetBundle, bool& enabled);

    /**
     * @brief Set the notification extension subscription state.
     * @param targetBundle The bundle option to be set.
     * @param enabled True if the subscription is enabled.
     * @return Returns set result.
     */
    static ErrCode SetUserGrantedState(const NotificationBundleOption& targetBundle, bool enabled);
    
    /**
     * @brief Obtains reminder info of application list.
     *
     * @param bundles Indicates the bundles bundleOption.
     * @param reminderInfo Indicates the bundles reminderInfo.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode GetReminderInfoByBundles(
        const std::vector<NotificationBundleOption> &bundles, std::vector<NotificationReminderInfo> &reminderInfo);

    /**
     * @brief Set reminder info for application list.
     *
     * @param reminderInfo Indicates the bundles reminderInfo.
     * @return Returns ERR_OK on success, others on failure.
     */
    static ErrCode SetReminderInfoByBundles(const std::vector<NotificationReminderInfo> &reminderInfo);

    /**
     * @brief Obtains the list of bundleOption which subscribed by targetBundle
     * @param targetBundle The bundle option to be queried.
     * @param enabledBundles the list of subscribed bundle options.
     * @return Returns get result.
     */
    static ErrCode GetUserGrantedEnabledBundles(const NotificationBundleOption& targetBundle,
        std::vector<sptr<NotificationBundleOption>>& enabledBundles);

     /**
     * @brief Obtains the list of bundleOption which granted by self.
     * @param bundles The returned list.
     * @return Returns get result.
     */
    static ErrCode GetUserGrantedEnabledBundlesForSelf(std::vector<sptr<NotificationBundleOption>>& bundles);

    /**
     * @brief Set the bundleOptions of the extensionAbility to be subscribed or unsubscribed.
     * @param targetBundle The bundle option to be set.
     * @param enabledBundles The bundle option list to be configured.
     * @param enabled Set enabled or not.
     * @return Returns set result.
     */
    static ErrCode SetUserGrantedBundleState(const NotificationBundleOption& targetBundle,
        const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled);

    /**
     * @brief Obtains the list of bundleOption which granted by user.
     * @param bundles The returned list.
     * @return Returns get result.
     */
    static ErrCode GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles);
    /**
     * @brief Checks whether the current app is allowed to open the subscribe settings UI.
     *
     * @return Returns ERR_OK if allowed; otherwise returns the specific error code.
     */
    static ErrCode CanOpenSubscribeSettings();
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_HELPER_H
