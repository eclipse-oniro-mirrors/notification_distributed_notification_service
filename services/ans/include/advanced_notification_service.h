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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_ADVANCED_NOTIFICATION_SERVICE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_ADVANCED_NOTIFICATION_SERVICE_H

#include <ctime>
#include <set>
#include <list>
#include <memory>
#include <mutex>

#include "event_handler.h"
#include "event_runner.h"
#include "ffrt.h"
#include "refbase.h"

#include "ans_const_define.h"
#include "ans_manager_stub.h"
#include "bluetooth_hfp_ag.h"
#include "common_notification_publish_process.h"
#include "distributed_kv_data_manager.h"
#include "distributed_kvstore_death_recipient.h"
#include "live_publish_process.h"
#include "notification.h"
#include "notification_bundle_option.h"
#include "distributed_bundle_option.h"
#include "notification_dialog_manager.h"
#include "notification_do_not_disturb_profile.h"
#include "notifictaion_load_utils.h"
#include "notification_record.h"
#include "notification_slot_filter.h"
#include "notification_sorting_map.h"
#include "permission_filter.h"
#include "push_callback_interface.h"
#include "system_event_observer.h"
#include "notification_subscriber_manager.h"
#include "distributed_device_status.h"
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "reminder_swing_decision_center.h"
#endif
#include "notification_clone_bundle_info.h"

namespace OHOS {
namespace Notification {

static const uint32_t DEFAULT_SLOT_FLAGS = 59; // 0b111011
static const uint32_t SILENT_REMINDER__SLOT_FLAGS = 32; // 0b100000
constexpr char REMINDER_CAPABILITY[] = "reminder_capability";
constexpr char SOUND_CAPABILITY[] = "sound_capability";

class HfpStateObserver : public OHOS::Bluetooth::HandsFreeAudioGatewayObserver {
public:
    void OnConnectionStateChanged(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state, int cause) override;
};
    
class AdvancedNotificationService final : public AnsManagerStub,
    public std::enable_shared_from_this<AdvancedNotificationService> {
public:
    struct NotificationRequestDb {
        sptr<NotificationRequest> request {nullptr};
        sptr<NotificationBundleOption> bundleOption {nullptr};
    };

    struct RecentNotification {
        sptr<Notification> notification = nullptr;
        bool isActive = false;
        int32_t deleteReason = 0;
        int64_t deleteTime = 0;
    };

    ~AdvancedNotificationService() override;

    DISALLOW_COPY_AND_MOVE(AdvancedNotificationService);

    /**
     * @brief Get the instance of service.
     *
     * @return Returns the instance.
     */
    static sptr<AdvancedNotificationService> GetInstance();

    static std::map<std::string, uint32_t>& GetDefaultSlotConfig();

    void SelfClean();

    /**
     * @brief Get notification_svr_queue of service.
     *
     * @return Returns the queue.
     */
    std::shared_ptr<ffrt::queue> GetNotificationSvrQueue();

    /**
     * @brief Submit an async task into notification_svr_queue.
     *
     * @param func Indicates the function.
     */
    void SubmitAsyncTask(const std::function<void()>& func);
    /**
     * @brief Submit a sync task into notification_svr_queue.
     *
     * @param func Indicates the function.
     */
    void SubmitSyncTask(const std::function<void()>& func);

    // AnsManagerStub

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
    ErrCode Publish(const std::string &label, const sptr<NotificationRequest> &request) override;

    ErrCode PublishWithMaxCapacity(const std::string& label, const sptr<NotificationRequest>& request) override;

    /**
     * @brief Publishes a notification.
     * @note If a notification with the same ID has been published by the current application and has not been deleted,
     *       this method will update the notification.
     *
     * @param notification Indicates the NotificationRequest object for setting the notification content.
     *                This parameter must be specified.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode PublishNotificationForIndirectProxy(const sptr<NotificationRequest> &request) override;

    ErrCode PublishNotificationForIndirectProxyWithMaxCapacity(const sptr<NotificationRequest> &request) override;

    /**
     * @brief Cancels a published notification matching the specified label and notificationId.
     *
     * @param notificationId Indicates the ID of the notification to cancel.
     * @param label Indicates the label of the notification to cancel.
     * @param instanceKey Indicates the application instance key.
     * @return Returns cancel notification result.
     */
    ErrCode Cancel(int32_t notificationId, const std::string &label, const std::string &instanceKey) override;

    /**
     * @brief Cancels all the published notifications.
     *
     * @param instanceKey Indicates the application instance key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CancelAll(const std::string &instanceKey) override;

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
    ErrCode CancelAsBundle(
        int32_t notificationId, const std::string &representativeBundle, int32_t userId) override;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle of application bundle your application is representing.
     * @param notificationId Indicates the unique notification ID in the application.
     *                       The value must be the ID of a published notification.
     *                       Otherwise, this method does not take effect.
     * @return Returns cancel notification result.
     */
    ErrCode CancelAsBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId) override;

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
    ErrCode CancelAsBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, int32_t userId) override;

    /**
     * @brief Adds a notification slot by type.
     *
     * @param slotType Indicates the notification slot type to be added.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddSlotByType(int32_t slotTypeInt) override;

    /**
     * @brief Creates multiple notification slots.
     *
     * @param slots Indicates the notification slots to create.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddSlots(const std::vector<sptr<NotificationSlot>> &slots) override;

    /**
     * @brief Deletes a created notification slot based on the slot ID.
     *
     * @param slotType Indicates the type of the slot, which is created by AddNotificationSlot
     *                 This parameter must be specified.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveSlotByType(int32_t slotTypeInt) override;

    /**
     * @brief Deletes all notification slots.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveAllSlots() override;

    /**
     * @brief Queries a created notification slot.
     *
     * @param slotType Indicates the ID of the slot, which is created by AddNotificationSlot(NotificationSlot). This
     *        parameter must be specified.
     * @param slot Indicates the created NotificationSlot.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetSlotByType(int32_t slotTypeInt, sptr<NotificationSlot> &slot) override;

    /**
     * @brief Obtains all notification slots of this application.
     *
     * @param slots Indicates the created NotificationSlot.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetSlots(std::vector<sptr<NotificationSlot>> &slots) override;

    /**
     * @brief Obtains the number of slot.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param num Indicates the number of slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetSlotNumAsBundle(const sptr<NotificationBundleOption> &bundleOption, uint64_t &num) override;

    /**
     * @brief Obtains active notifications of the current application in the system.
     *
     * @param notifications Indicates active NotificationRequest objects of the current application.
     * @param instanceKey Indicates the application instance key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetActiveNotifications(std::vector<sptr<NotificationRequest>> &notifications,
        const std::string &instanceKey) override;

    /**
     * @brief Obtains the number of active notifications of the current application in the system.
     *
     * @param num Indicates the number of active notifications of the current application.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetActiveNotificationNums(uint64_t &num) override;

    /**
     * @brief Obtains all active notifications by slot type in the current system. The caller must have system
     * permissions to call this method.
     *
     * @param notification Indicates all active notifications of this application.
     * @return Returns get all active notifications
     */
    ErrCode GetAllNotificationsBySlotType(std::vector<sptr<Notification>> &notifications,
        int32_t slotTypeInt) override;

    /**
     * @brief Obtains all active notifications in the current system. The caller must have system permissions to
     * call this method.
     *
     * @param notifications Indicates all active notifications of this application.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllActiveNotifications(std::vector<sptr<Notification>> &notifications) override;

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
    ErrCode GetSpecialActiveNotifications(
        const std::vector<std::string> &key, std::vector<sptr<Notification>> &notifications) override;

    ErrCode GetActiveNotificationByFilter(
        const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId, const std::string &label,
        int32_t userId, const std::vector<std::string> &extraInfoKeys, sptr<NotificationRequest> &request) override;

    /**
     * @brief Checks whether your application has permission to publish notifications by calling
     * PublishNotificationAsBundle(string, NotificationRequest) in the name of another application indicated by the
     * given representativeBundle.
     *
     * @param representativeBundle Indicates the name of application bundle your application is representing.
     * @param canPublish Indicates whether your application has permission to publish notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CanPublishAsBundle(const std::string &representativeBundle, bool &canPublish) override;

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
    ErrCode PublishAsBundle(
        const sptr<NotificationRequest>& notification, const std::string &representativeBundle) override;

    ErrCode PublishAsBundleWithMaxCapacity(
        const sptr<NotificationRequest>& notification, const std::string &representativeBundle) override;

    /**
     * @brief Sets the number of active notifications of the current application as the number to be displayed on the
     * notification badge.
     *
     * @param num Indicates the badge number.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationBadgeNum(int32_t num) override;

    /**
     * @brief Obtains the importance level of this application.
     *
     * @param importance Indicates the importance level of this application, which can be LEVEL_NONE,
               LEVEL_MIN, LEVEL_LOW, LEVEL_DEFAULT, LEVEL_HIGH, or LEVEL_UNDEFINED.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetBundleImportance(int32_t &importance) override;

    /**
     * @brief Checks whether this application has permission to modify the Do Not Disturb (DND) notification policy.
     *
     * @param granted True if the application has permission; false for otherwise.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HasNotificationPolicyAccessPermission(bool &granted) override;

    /**
     * @brief Trigger the local live view after the button has been clicked.
     * @note Your application must have platform signature to use this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application whose notifications has been clicked.
     * @param notificationId Indicates the id of the notification.
     * @param buttonOption Indicates which button has been clicked.
     * @return Returns trigger localLiveView result.
     */
    ErrCode TriggerLocalLiveView(const sptr<NotificationBundleOption> &bundleOption,
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
    ErrCode RemoveNotification(const sptr<NotificationBundleOption> &bundleOption, int32_t notificationId,
        const std::string &label, int32_t removeReason) override;

    /**
     * @brief Delete all notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption of notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveAllNotifications(const sptr<NotificationBundleOption> &bundleOption) override;

    ErrCode RemoveAllNotificationsForDisable(const sptr<NotificationBundleOption> &bundleOption);

    ErrCode RemoveNotifications(const std::vector<std::string> &keys, int32_t removeReason) override;

    /**
     * @brief Removes Distributed notifications in the system.
     * @note Your application must have platform signature to use this method.
     * @return Returns remove notifications result.
     */
    ErrCode RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
        const int32_t slotTypeInt, const int32_t deleteTypeInt,
        const int32_t removeReason, const std::string& deviceId = "") override;

    ErrCode GetUnifiedGroupInfoFromDb(std::string &enable);

    /**
     * @brief Delete notification based on key.
     *
     * @param key Indicates the key to delete notification.
     * @param removeReason Indicates the reason of remove notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode Delete(const std::string &key, int32_t removeReason) override;

    /**
     * @brief Remove notifications based on bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption of notifications.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteByBundle(const sptr<NotificationBundleOption> &bundleOption) override;

    /**
     * @brief Remove all notifications.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteAll() override;

    /**
     * @brief Get all the slots corresponding to the bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slots Indicates the notification slots.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetSlotsByBundle(
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
    ErrCode GetSlotByBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t slotTypeInt,
        sptr<NotificationSlot> &slot) override;

    /**
     * @brief Update slots according to bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param slots Indicates the notification slots to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateSlots(
        const sptr<NotificationBundleOption> &bundleOption, const std::vector<sptr<NotificationSlot>> &slots) override;

    /**
     * @brief Allow notifications to be sent based on the deviceId.
     *
     * @param deviceId Indicates the device Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestEnableNotification(const std::string &deviceId,
        const sptr<IAnsDialogCallback> &callback,
        const sptr<IRemoteObject> &callerToken) override;

    ErrCode RequestEnableNotification(const std::string &deviceId,
        const sptr<IAnsDialogCallback> &callback) override;

    /**
     * @brief Allow application to publish notifications.
     *
     * @param bundleName bundle name.
     * @param uid uid.
     * @return Returns set notifications enabled for the bundle result.
     */
    ErrCode RequestEnableNotification(const std::string& bundleName, int32_t uid) override;

    /**
     * @brief Set whether to allow the specified deviceId to send notifications for current bundle.
     *
     * @param deviceId Indicates the device Id.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabledForBundle(const std::string &deviceId, bool enabled) override;

    /**
     * @brief Set whether to allow the specified deviceId to send notifications for all bundles.
     *
     * @param deviceId Indicates the device Id.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabledForAllBundles(const std::string &deviceId, bool enabled) override;

    /**
     * @brief Set whether to allow the specified bundle to send notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @param updateUnEnableTime Indicates whether update the unenable time.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabledForSpecialBundle(
        const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption,
        bool enabled, bool updateUnEnableTime = true) override;

    /**
     * @brief Set whether to allow the specified bundle to send notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @param updateUnEnableTime Indicates whether update the unenable time.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsSystemEnabledForSpecialBundle(
        const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled,
        bool updateUnEnableTime = true);

    /**
     * @brief Sets whether the bundle allows the banner to display notification.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled) override;

    /**
     * @brief Sets whether to allow a specified application to to show badge.
     *
     * @param bundleOptions Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to show badge.
     * @return Returns set result.
     */
    ErrCode SetShowBadgeEnabledForBundles(
        const std::map<sptr<NotificationBundleOption>, bool> &bundleOptions) override;

    /**
     * @brief Gets whether the bundle allows the badge to display the status of notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetShowBadgeEnabledForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled) override;

    /**
     * @brief Obtains the flag that whether to allow applications to show badge.
     *
     * @param bundleOptions Indicates the bundle name and uid of the application.
     * @param bundleEnable Allow applications to show badge.
     * @return Returns get result.
     */
    ErrCode GetShowBadgeEnabledForBundles(const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
        std::map<sptr<NotificationBundleOption>, bool> &bundleEnable) override;

    /**
     * @brief Gets whether allows the badge to display the status of notifications.
     *
     * @param enabled Indicates the flag that allows badge to be shown.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetShowBadgeEnabled(bool &enabled) override;

    /**
     * @brief Subscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode Subscribe(const sptr<IAnsSubscriber> &subscriber,
        const sptr<NotificationSubscribeInfo> &info) override;

    ErrCode Subscribe(const sptr<IAnsSubscriber> &subscriber) override;

    /**
     * @brief Subscribes notifications self.
     *
     * @param subscriber Indicates the subscriber.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SubscribeSelf(const sptr<IAnsSubscriber> &subscriber) override;

    /**
     * @brief Subscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SubscribeLocalLiveView(const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        const sptr<NotificationSubscribeInfo> &info, const bool isNative) override;

    ErrCode SubscribeLocalLiveView(const sptr<IAnsSubscriberLocalLiveView> &subscriber, const bool isNative) override;

    /**
     * @brief Unsubscribes notifications.
     *
     * @param subscriber Indicates the subscriber.
     * @param info Indicates the NotificationSubscribeInfo object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode Unsubscribe(const sptr<IAnsSubscriber> &subscriber,
        const sptr<NotificationSubscribeInfo> &info) override;

    ErrCode Unsubscribe(const sptr<IAnsSubscriber> &subscriber) override;

    /**
     * @brief Checks whether this device is allowed to publish notifications.
     *
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsAllowedNotify(bool &allowed) override;

    /**
     * @brief Checks whether this application is allowed to publish notifications.
     *
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsAllowedNotifySelf(bool &allowed) override;

    /**
     * @brief Checks whether this application can pop enable notification dialog.
     *
     * @param  canPop True if can pop enable notification dialog
     * @return Returns is canPop result.
     */
    ErrCode CanPopEnableNotificationDialog(const sptr<IAnsDialogCallback> &callback,
        bool &canPop, std::string &bundleName) override;

    /**
     * @brief remove enable notification dialog.
     *
     * @return Returns remove dialog result.
     */
    ErrCode RemoveEnableNotificationDialog() override;

    ErrCode RemoveEnableNotificationDialog(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Checks whether notifications are allowed for a specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param allowed Indicates the flag that allows notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsSpecialBundleAllowedNotify(const sptr<NotificationBundleOption> &bundleOption, bool &allowed) override;

    /**
     * @brief Set do not disturb date.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetDoNotDisturbDate(const sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Get do not disturb date.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDoNotDisturbDate(sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Add Do Not Disturb profiles.
     *
     * @param profiles Indicates the list of NotificationDoNotDisturbProfile objects to add.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) override;

    /**
     * @brief Remove Do Not Disturb profiles.
     *
     * @param profiles Indicates the list of NotificationDoNotDisturbProfile objects to remove.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveDoNotDisturbProfiles(const std::vector<sptr<NotificationDoNotDisturbProfile>> &profiles) override;

    /**
     * @brief Get whether Do Not Disturb mode is supported.
     *
     * @param doesSupport Indicates the flag that supports DND mode.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DoesSupportDoNotDisturbMode(bool &doesSupport) override;

    /**
     * @brief Is coming call need silent in do not disturb mode.
     *
     * @param phoneNumber the calling format number.
     * @return Returns silent in do not disturb mode.
     */
    ErrCode IsNeedSilentInDoNotDisturbMode(const std::string &phoneNumber, int32_t callerType) override;

    /**
     * @brief Cancel notifications according to group.
     *
     * @param groupName Indicates the group name.
     * @param instanceKey Indicates the application instance key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CancelGroup(const std::string &groupName, const std::string &instanceKey) override;

    /**
     * @brief Delete notifications according to bundle and group.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param groupName Indicates the group name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveGroupByBundle(
        const sptr<NotificationBundleOption> &bundleOption, const std::string &groupName) override;

    /**
     * @brief Gets whether distributed notification is enabled.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsDistributedEnabled(bool &enabled) override;

    /**
     * @brief Sets distributed notification enabled or disabled.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode EnableDistributed(bool enabled) override;

    /**
     * @brief Sets distributed notification enabled or disabled for specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode EnableDistributedByBundle(const sptr<NotificationBundleOption> &bundleOption, bool enabled) override;

    /**
     * @brief Sets distributed notification enabled or disabled for current bundle.
     *
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode EnableDistributedSelf(bool enabled) override;

    /**
     * @brief Gets whether distributed notification is enabled for specific bundle.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the enabled flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsDistributedEnableByBundle(const sptr<NotificationBundleOption> &bundleOption, bool &enabled) override;

    /**
     * @brief Get the reminder type of the current device.
     *
     * @param remindType Reminder type for the device.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDeviceRemindType(int32_t& remindTypeInt) override;

    /**
     * @brief Publishes a continuous notification.
     *
     * @param request Notification requests that need to be posted.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode PublishContinuousTaskNotification(const sptr<NotificationRequest> &request) override;

    /**
     * @brief Cancels a continuous notification.
     *
     * @param label Identifies the label of the specified notification.
     * @param notificationId Identifies the id of the specified notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CancelContinuousTaskNotification(const std::string &label, int32_t notificationId) override;

    /**
     * @brief Check reminder permission
     */
    bool CheckReminderPermission();

    /**
     * @brief Checks whether this device is support template.
     *
     * @param templateName Identifies the template name for searching as a condition.
     * @param support Identifies the support flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsSupportTemplate(const std::string &templateName, bool &support) override;

    /**
     * @brief Checks Whether the specified users is allowed to publish notifications.
     *
     * @param userId Identifies the user's id.
     * @param allowed Identifies the allowed flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode IsSpecialUserAllowedNotify(int32_t userId, bool &allowed) override;

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
    ErrCode SetNotificationsEnabledByUser(int32_t userId, bool enabled) override;

    /**
     * @brief Delete all notifications by user.
     *
     * @param userId Indicates the user id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteAllByUser(int32_t userId) override;

    /**
     * @brief Set do not disturb date by user.
     *
     * @param userId Indicates the user id.
     * @param date Indicates NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetDoNotDisturbDate(int32_t userId, const sptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Get the do not disturb date by user.
     *
     * @param userId Indicates the user id.
     * @param date Indicates the NotificationDoNotDisturbDate object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDoNotDisturbDate(int32_t userId, sptr<NotificationDoNotDisturbDate> &date) override;

    ErrCode SetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        int32_t slotTypeInt, bool enabled, bool isForceControl) override;

    ErrCode GetEnabledForBundleSlot(const sptr<NotificationBundleOption> &bundleOption,
        int32_t slotTypeInt, bool &enabled) override;

    ErrCode GetEnabledForBundleSlotSelf(int32_t slotTypeInt, bool &enabled) override;

    // SystemEvent

    /**
     * @brief Obtains the event of bundle removed.
     *
     * @param bundleOption Indicates the bundle info.
     */
    void OnBundleRemoved(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Obtains the event of bundle batch removed.
     *
     * @param notifications Notification vector.
     */
    void ExecBatchCancel(std::vector<sptr<Notification>> &notifications, int32_t &reason);

    /**
     * @brief Obtains the event of user removed.
     *
     * @param userId Indicates the user.
     */
    void OnUserRemoved(const int32_t &userId);

    /**
     * @brief Set whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns set enabled result.
     */
    ErrCode SetSyncNotificationEnabledWithoutApp(const int32_t userId, const bool enabled) override;

    /**
     * @brief Obtains whether to sync notifications to devices that do not have the app installed.
     *
     * @param userId Indicates the specific user.
     * @param enabled Allow or disallow sync notifications.
     * @return Returns get enabled result.
     */
    ErrCode GetSyncNotificationEnabledWithoutApp(const int32_t userId, bool &enabled) override;

    /**
     * @brief Obtains the number of slotFlags.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slot      Indicates the specified slot object
     * @param slotFlags Indicates the slogFlags of slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption,
        uint32_t &slotFlags) override;

    /**
     * @brief Obtains the number of slotFlags.
     *
     * @param slotFlags Indicates the slogFlags of slot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetNotificationSettings(uint32_t &slotFlags) override;

    /**
     * @brief Set the slotFlags of slot.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param slot      Indicates the specified slot object
     * @param slotFlags Indicates the slogFlags of slot to set.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetSlotFlagsAsBundle(const sptr<NotificationBundleOption>& bundleOption,
        uint32_t slotFlags) override;

#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    /**
     * @brief Obtains the event of turn on screen.
     */
    void OnScreenOn();

    /**
     * @brief Obtains the event of turn off screen.
     */
    void OnScreenOff();
#endif
    void OnResourceRemove(int32_t userId);
    void OnUserStopped(int32_t userId);
    void OnBundleDataCleared(const sptr<NotificationBundleOption> &bundleOption);
    void DeleteAllByUserStopped(int32_t userId);

    /**
     * @brief Obtains the event of bundle install.
     *
     * @param bundleOption Indicates the bundle info.
     */
    void OnBundleDataAdd(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Obtains the event of bundle update.
     *
     * @param bundleOption Indicates the bundle info.
     */
    void OnBundleDataUpdate(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Boot system completed event callback.
     */
    void OnBootSystemCompleted();

    // Distributed KvStore

    /**
     * @brief Obtains the death event of the Distributed KvStore service.
     */
    void OnDistributedKvStoreDeathRecipient();

    ErrCode CancelPreparedNotification(int32_t notificationId, const std::string &label,
        const sptr<NotificationBundleOption> &bundleOption, const int32_t reason);

    ErrCode PrepareNotificationInfo(
        const sptr<NotificationRequest> &request, sptr<NotificationBundleOption> &bundleOption);
    ErrCode PublishPreparedNotification(const sptr<NotificationRequest> &request,
        const sptr<NotificationBundleOption> &bundleOption, bool isUpdateByOwner = false);

    /**
     * @brief Dump current running status for debuging.
     *
     * @param cmd Indicates the specified dump command.
     * @param bundle Indicates the specified bundle name.
     * @param userId Indicates the specified userId.
     * @param dumpInfo Indicates the container containing datas.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo) override;

    /**
     * @brief Set badge number.
     *
     * @param badgeNumber The badge number.
     * @param instanceKey The application instance key.
     * @return Returns set badge number result.
     */
    ErrCode SetBadgeNumber(int32_t badgeNumber, const std::string &instanceKey) override;

    /**
     * @brief Set badge number by bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param badgeNumber The badge number.
     * @return Returns set badge number by bundle result.
     */
    ErrCode SetBadgeNumberByBundle(const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber) override;

    /**
     * @brief Set badge number for dh by bundle.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param badgeNumber The badge number.
     * @return Returns set badge number by bundle result.
     */
    ErrCode SetBadgeNumberForDhByBundle(
        const sptr<NotificationBundleOption> &bundleOption, int32_t badgeNumber) override;

    /**
     * @brief Obtains allow notification application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllNotificationEnabledBundles(std::vector<NotificationBundleOption> &bundleOption) override;

    /**
     * @brief Obtains allow liveview application list.
     *
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllLiveViewEnabledBundles(std::vector<NotificationBundleOption> &bundleOption) override;

    /**
     * @brief Obtains allow distribued application list.
     *
     * @param deviceType Indicates device type.
     * @param bundleOption Indicates the bundle bundleOption.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllDistribuedEnabledBundles(const std::string &deviceType,
        std::vector<NotificationBundleOption> &bundleOption) override;

    /**
     * @brief Register Push Callback.
     *
     * @param pushCallback PushCallBack.
     * @param notificationCheckRequest Filter conditions for push check
     * @return Returns register push Callback result.
     */
    ErrCode RegisterPushCallback(const sptr<IRemoteObject>& pushCallback,
        const sptr<NotificationCheckRequest> &notificationCheckRequest) override;

    /**
     * @brief Unregister Push Callback.
     *
     * @return Returns unregister push Callback result.
     */
    ErrCode UnregisterPushCallback() override;

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
    ErrCode SetDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
        const std::string &deviceType, const bool enabled) override;

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundles Indicates the bundles.
     * @param deviceType Indicates the type of the device running the application.
     * @return Returns set distributed enabled for specified bundle result.
     */
    ErrCode SetDistributedBundleOption(const std::vector<sptr<DistributedBundleOption>> &bundles,
        const std::string &deviceType) override;

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
    ErrCode IsDistributedEnabledByBundle(const sptr<NotificationBundleOption> &bundleOption,
        const std::string &deviceType, bool &enabled) override;

    /**
     * @brief Sets whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption, const bool enabled) override;

    /*
     * @brief Get whether to allow a specified application to publish notifications cross
     * device collaboration. The caller must have system permissions to call this method.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param enabled Specifies whether to allow the given application to publish notifications. The value
     *                true indicates that notifications are allowed, and the value false indicates that
     *                notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsSilentReminderEnabled(const sptr<NotificationBundleOption> &bundleOption, int32_t &enableStatus) override;

    /**
     * @brief Obtains reminder info of application list.
     *
     * @param bundles Indicates the bundles bundleOption.
     * @param reminderInfo Indicates the bundles reminderInfo.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetReminderInfoByBundles(const std::vector<sptr<NotificationBundleOption>> &bundles,
        std::vector<NotificationReminderInfo> &reminderInfo) override;

    /**
     * @brief Set reminder info for application list.
     *
     * @param reminderInfo Indicates the bundles reminderInfo.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetReminderInfoByBundles(const std::vector<sptr<NotificationReminderInfo>> &reminderInfo) override;

    /**
     * @brief configuring Whether to Synchronize Common Notifications to Target Devices.
     *
     * @param deviceType Target device type.
     * @param enabled Whether to Synchronize Common Notifications to Target Devices.
     * @return Returns configuring Whether to Synchronize Common Notifications to Target Devices result.
     */
    ErrCode SetDistributedEnabled(const std::string &deviceType, const bool enabled) override;

    /**
     * @brief querying Whether to Synchronize Common Devices to Target Devices.
     *
     * @param deviceType Target device type.
     * @param enabled Whether to Synchronize Common Notifications to Target Devices.
     * @return Returns Whether to Synchronize Common Notifications to Target Devices result.
     */
    ErrCode IsDistributedEnabled(const std::string &deviceType, bool &enabled) override;

    /**
     * @brief Obtains the set of supported distributed abilities.
     *
     * @param abilityId The set of supported distributed abilities.
     * @return Returns result in Obtains the set of supported distributed abilities.
     */
    ErrCode GetDistributedAbility(int32_t &abilityId) override;

    /**
     * @brief Get the target device's authorization status.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param deviceId The id of the target device.
     * @param userId The userid of the target device.
     * @param isAuth Return The authorization status.
     * @return Returns get result.
     */
    ErrCode GetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t userId, bool &isAuth) override;

    /**
     * @brief Set the target device's authorization status.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param deviceId The id of the target device.
     * @param userId The userid of the target device.
     * @param isAuth The authorization status.
     * @return Returns set result.
     */
    ErrCode SetDistributedAuthStatus(
        const std::string &deviceType, const std::string &deviceId, int32_t userId, bool isAuth) override;

    /**
     * @brief Set distributed target device list.
     *
     * @param deviceType Type of the target device whose status you want to set.
     * @param userId The userid of the target device.
     * @return Returns set result.
     */
    ErrCode UpdateDistributedDeviceList(const std::string &deviceType) override;

    /**
     * @brief get distributed device list.
     *
     * @param deviceTypes Indicates device types.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDistributedDevicelist(std::vector<std::string> &deviceTypes) override;

    /**
     * @brief Get Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given device to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode IsSmartReminderEnabled(const std::string &deviceType, bool &enabled) override;

    /**
     * @brief Set Enable smartphone to collaborate with other devices for intelligent reminders
     *
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Specifies whether to allow the given device to publish notifications.
     *                The value true indicates that notifications are allowed, and the value
     *                false indicates that notifications are not allowed.
     * @return Returns set notifications enabled for specified bundle result.
     */
    ErrCode SetSmartReminderEnabled(const std::string &deviceType, const bool enabled) override;

    /**
     * @brief Set the channel switch for collaborative reminders.
       The caller must have system permissions to call this method.
     *
     * @param slotType Indicates the slot type of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Indicates slot switch status.
     * @return Returns set channel switch result.
     */
    ErrCode SetDistributedEnabledBySlot(
        int32_t slotTypeInt, const std::string &deviceType, bool enabled) override;

    /**
     * @brief Query the channel switch for collaborative reminders.
       The caller must have system permissions to call this method.
     *
     * @param slotType Indicates the slot type of the application.
     * @param deviceType Indicates the type of the device running the application.
     * @param enabled Indicates slot switch status.
     * @return Returns channel switch result.
     */
    ErrCode IsDistributedEnabledBySlot(
        int32_t slotTypeInt, const std::string &deviceType, bool &enabled) override;

    /**
     * @brief Set the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    ErrCode SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
        const std::string &deviceId) override;

    /**
     * @brief Set the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    ErrCode SetTargetDeviceStatus(const std::string &deviceType, uint32_t status,
        uint32_t controlFlag, const std::string &deviceId, int32_t userId) override;

    ErrCode SetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        int operatorType, const std::vector<std::string>& bundleList,
        const std::vector<std::string>& labelList) override;

    ErrCode SetTargetDeviceSwitch(const std::string& deviceType, const std::string& deviceId,
        bool notificaitonEnable, bool liveViewEnable) override;

    ErrCode GetTargetDeviceBundleList(const std::string& deviceType, const std::string& deviceId,
        std::vector<std::string>& bundleList, std::vector<std::string>& labelList) override;

    ErrCode GetMutilDeviceStatus(const std::string &deviceType, const uint32_t status,
        std::string& deviceId, int32_t& userId) override;

    /**
     * @brief clear notification when aggregate local switch close.
     */
    void ClearAllNotificationGroupInfo(std::string localSwitch);

    /**
     * @brief Reset pushcallback proxy
     */
    void ResetPushCallbackProxy(NotificationConstant::SlotType slotType);

    /**
     * @brief Set the notification SlotFlags whitelist.
     */
    void SetSlotFlagsTrustlistsAsBundle(const sptr<NotificationBundleOption> &bundleOption);

    /**
     * @brief Init The Default Installation Package Notification Enabled.
     */
    void InitNotificationEnableList();
    /**
     * @brief Remove Local Live Notifications
     */
    ErrCode RemoveSystemLiveViewNotifications(const std::string& bundleName, const int32_t uid);

    /**
     * @brief Remove Local Live Notifications created by sa.
     */
    ErrCode RemoveSystemLiveViewNotificationsOfSa(int32_t uid);

    /**
     * @brief Set the notification flags by soltType.
     */
    void SetRequestBySlotType(const sptr<NotificationRequest> &request,
        const sptr<NotificationBundleOption> &bundleOption);

    void HandleFlagsWithRequest(const sptr<NotificationRequest> &request,
        const sptr<NotificationBundleOption> &bundleOption);

    // Might fail if ces subscribe failed, if failed, dialogManager_ will be set nullptr
    bool CreateDialogManager();

    /**
     * @brief Set agent relationship.
     *
     * @param key Indicates storing agent relationship if the value is "PROXY_PKG".
     * @param value Indicates key-value pair of agent relationship.
     * @return Returns set result.
     */
    ErrCode SetAdditionConfig(const std::string &key, const std::string &value) override;

    /**
     * @brief Cancels a published agent notification.
     *
     * @param bundleOption Indicates the bundle name and uid of the application.
     * @param id Indicates the unique notification ID in the application.
     * @return Returns cancel result.
     */
    ErrCode CancelAsBundleWithAgent(const sptr<NotificationBundleOption> &bundleOption, const int32_t id) override;

    /**
     * @brief Get the status of the target device.
     *
     * @param deviceType Type of the device whose status you want to set.
     * @param status The status.
     * @return Returns set result.
     */
    ErrCode GetTargetDeviceStatus(const std::string &deviceType, int32_t &status) override;

    /**
     * @brief Init publish process.
     */
    bool InitPublishProcess();

    /**
    * @brief Recover LiveView from DB.
    */
    void RecoverLiveViewFromDb(int32_t userId = -1);

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    /**
     * @brief Register Swing Callback.
     *
     * @param swingCallback SwingCallBack.
     * @return Returns register swing Callback result.
     */
    ErrCode RegisterSwingCallback(const sptr<IRemoteObject>& swingCallback) override;
#endif

    /**
     * @brief update unified group info.
     */
    void UpdateUnifiedGroupInfo(const std::string &key, std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo);

    /**
     * @brief Whether reminders are allowed.
     */
    bool AllowUseReminder(const std::string& bundleName);

    /**
     * @brief Whether reminders are allowed.
     *
     * @param bundleName app bundleName
     * @param isAllowUseReminder is allow use reminder
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder) override;

    /**
     * @brief Get do not disturb profile by id.
     *
     * @param id Profile id.
     * @param status Indicates the NotificationDoNotDisturbProfile object.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDoNotDisturbProfile(int64_t id, sptr<NotificationDoNotDisturbProfile> &profile) override;

    /**
     * @brief Distribution operation based on hashCode.
     *
     * @param hashCode Unique ID of the notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DistributeOperation(const sptr<NotificationOperationInfo>& operationInfo,
        const sptr<IAnsOperationCallback> &callback) override;

    /**
     * @brief Reply distribute operation.
     *
     * @param hashCode Unique ID of the notification.
     * @param result The result of the distribute operation.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ReplyDistributeOperation(const std::string& hashCode, const int32_t result) override;

    /**
     * @brief Get notificationRequest by hashCode.
     *
     * @param hashCode Unique ID of the notification.
     * @param notificationRequest The request of of the notification.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetNotificationRequestByHashCode(
        const std::string& hashCode, sptr<NotificationRequest>& notificationRequest) override;

    int32_t OnBackup(MessageParcel& data, MessageParcel& reply);

    int32_t OnRestore(MessageParcel& data, MessageParcel& reply);

    void ResetDistributedEnabled();

    ErrCode UpdateNotificationTimerByUid(const int32_t uid, const bool isPaused) override;

    void UpdateCloneBundleInfo(const NotificationCloneBundleInfo cloneBundleInfo, int32_t userId);

    void UpdateCloneBundleInfoForEnable(
        const NotificationCloneBundleInfo cloneBundleInfo, const sptr<NotificationBundleOption> bundle);

    void UpdateCloneBundleInfoFoSlot(
        const NotificationCloneBundleInfo cloneBundleInfo, const sptr<NotificationBundleOption> bundle);

    void UpdateCloneBundleInfoFoSilentReminder(
        const NotificationCloneBundleInfo cloneBundleInfo, const sptr<NotificationBundleOption> bundle);

    void TryStartReminderAgentService();

    static sptr<NotificationBundleOption> GenerateBundleOption();
    static sptr<NotificationBundleOption> GenerateValidBundleOption(const sptr<NotificationBundleOption> &bundleOption);

    ErrCode DisableNotificationFeature(const sptr<NotificationDisable> &notificationDisable) override;

    bool IsDisableNotification(const std::string &bundleName);

    bool IsDisableNotificationByKiosk(const std::string &bundleName);

    bool IsDisableNotificationForSaByKiosk(const std::string &bundleName, bool directAgency);

    bool IsNeedToControllerByDisableNotification(const sptr<NotificationRequest> &request);

    void SetAndPublishSubscriberExistFlag(const std::string& deviceType, bool existFlag);
    ErrCode RemoveAllNotificationsByBundleName(const std::string &bundleName, int32_t reason);

    void UpdateCloneBundleInfoForRingtone(NotificationRingtoneInfo ringtoneInfo, int32_t userId,
        const sptr<NotificationBundleOption> bundle, const NotificationCloneBundleInfo cloneBundleInfo);

    /**
     * @brief set rule of generate hashCode.
     *
     * @param type generate hashCode.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetHashCodeRule(const uint32_t type) override;

    ErrCode AtomicServicePublish(const sptr<NotificationRequest> &request);

    ErrCode SetDefaultSlotForBundle(const sptr<NotificationBundleOption> &bundleOption,
        int32_t slotTypeInt, bool enabled, bool isForceControl) override;

    ErrCode SetCheckConfig(int32_t response, const std::string& requestId, const std::string& key,
        const std::string& value) override;

    ErrCode GetLiveViewConfig(const std::vector<std::string>& bundleList) override;

    ErrCode SetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundle,
        const sptr<NotificationRingtoneInfo> &ringtoneInfo) override;

    ErrCode GetRingtoneInfoByBundle(const sptr<NotificationBundleOption> &bundle,
        sptr<NotificationRingtoneInfo> &ringtoneInfo) override;

    ErrCode NotificationExtensionSubscribe(
        const std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos) override;

    ErrCode NotificationExtensionUnsubscribe() override;

    ErrCode GetSubscribeInfo(std::vector<sptr<NotificationExtensionSubscriptionInfo>>& infos) override;

    ErrCode GetAllSubscriptionBundles(std::vector<sptr<NotificationBundleOption>>& bundles) override;

    ErrCode IsUserGranted(bool& isEnabled) override;

    ErrCode GetUserGrantedState(const sptr<NotificationBundleOption>& targetBundle, bool& enabled) override;

    ErrCode SetUserGrantedState(const sptr<NotificationBundleOption>& targetBundle, bool enabled) override;

    ErrCode GetUserGrantedEnabledBundles(const sptr<NotificationBundleOption>& targetBundle,
        std::vector<sptr<NotificationBundleOption>>& enabledBundles) override;

    ErrCode GetUserGrantedEnabledBundlesForSelf(std::vector<sptr<NotificationBundleOption>>& bundles) override;

    ErrCode SetUserGrantedBundleState(const sptr<NotificationBundleOption>& targetBundle,
        const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled) override;
		
    ErrCode ProxyForUnaware(const std::vector<int32_t>& uidList, bool isProxy) override;

    ErrCode CanOpenSubscribeSettings() override;

protected:
    /**
     * @brief Query whether there is a agent relationship between the two apps.
     *
     * @param agentBundleName The bundleName of the agent app.
     * @param sourceBundleName The bundleName of the source app.
     * @return Returns true if There is an agent relationship; returns false otherwise.
     */
    bool IsAgentRelationship(const std::string &agentBundleName, const std::string &sourceBundleName);

public:
    void ClearCloneRingToneInfo(NotificationRingtoneInfo ringtoneInfo,
        std::vector<NotificationRingtoneInfo> cloneRingtoneInfos);
    void TriggerLiveViewSwitchCheck(int32_t userId);
    bool CheckApiCompatibility(const sptr<NotificationBundleOption> &bundleOption);
    ErrCode SetDefaultNotificationEnabled(
        const sptr<NotificationBundleOption> &bundleOption, bool enabled);
    ErrCode RemoveNotificationBySlot(const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationSlot> &slot, const int reason);
    bool PublishSlotChangeCommonEvent(const sptr<NotificationBundleOption> &bundleOption);
    ErrCode PublishExtensionServiceStateChange(NotificationConstant::EventCodeType eventCode,
        const sptr<NotificationBundleOption> &bundleOption, bool state,
        const std::vector<sptr<NotificationBundleOption>> &enabledBundles = {});
    void HandleBundleInstall(const sptr<NotificationBundleOption> &bundleOption);
    void HandleBundleUpdate(const sptr<NotificationBundleOption> &bundleOption);
    void HandleBundleUninstall(const sptr<NotificationBundleOption> &bundleOption);
    bool TryStartExtensionSubscribeService();
    void OnHfpDeviceConnectChanged(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state);
    void ProcessSetUserGrantedState(const sptr<NotificationBundleOption>& bundle,
        bool enabled, ErrCode& result);
    void ProcessSetUserGrantedBundleState(const sptr<NotificationBundleOption>& bundle,
        const std::vector<sptr<NotificationBundleOption>>& enabledBundles, bool enabled, ErrCode& result);

private:
    struct RecentInfo {
        std::list<std::shared_ptr<RecentNotification>> list;
        size_t recentCount = 16;
    };

    struct SoundPermissionInfo {
        std::set<std::string> bundleName_;
        std::atomic<bool> needUpdateCache_ = true;
        bool allPackage_ = false;
        ffrt::mutex dbMutex_;
    };

    enum UploadStatus {
        CREATE,
        FIRST_UPDATE_TIME_OUT,
        CONTINUOUS_UPDATE_TIME_OUT,
        END,
        FINISH
    };

    enum ContactPolicy {
        FORBID_EVERYONE = 1,
        ALLOW_EVERYONE = 2,
        ALLOW_EXISTING_CONTACTS = 3,
        ALLOW_FAVORITE_CONTACTS = 4,
        ALLOW_SPECIFIED_CONTACTS = 5,
        FORBID_SPECIFIED_CONTACTS = 6,
    };
    
    /**
     * @brief Set whether to allow the specified bundle to send notifications.
     *
     * @param bundleOption Indicates the NotificationBundleOption object.
     * @param enabled Indicates the flag that allows notification to be pulished.
     * @param updateUnEnableTime Indicates whether update the unenable time.
     * @param isSystemCall Indicates whether set by system.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetNotificationsEnabledForSpecialBundleImpl(
        const std::string &deviceId, const sptr<NotificationBundleOption> &bundleOption, bool enabled,
        bool updateUnEnableTime = true, bool isSystemCall = false);

    AdvancedNotificationService();

    void StartFilters();
    void StopFilters();
    ErrCode Filter(const std::shared_ptr<NotificationRecord> &record, bool isRecover = false);
    void ChangeNotificationByControlFlags(const std::shared_ptr<NotificationRecord> &record,
        const bool isAgentController);
    ErrCode CheckPublishPreparedNotification(const std::shared_ptr<NotificationRecord> &record, bool isSystemApp);
    void AddToNotificationList(const std::shared_ptr<NotificationRecord> &record);
    void AddToDelayNotificationList(const std::shared_ptr<NotificationRecord> &record);
    ErrCode UpdateInNotificationList(const std::shared_ptr<NotificationRecord> &record);
    void UpdateInDelayNotificationList(const std::shared_ptr<NotificationRecord> &record);
    ErrCode AssignToNotificationList(const std::shared_ptr<NotificationRecord> &record);
    ErrCode RemoveFromNotificationList(const sptr<NotificationBundleOption> &bundleOption,
        NotificationKey notificationKey, sptr<Notification> &notification, int32_t removeReason,
        bool isCancel = false);
    ErrCode RemoveFromNotificationList(const std::string &key, sptr<Notification> &notification,
        bool isCancel, int32_t removeReason);
    ErrCode RemoveFromNotificationListForDeleteAll(const std::string &key,
        const int32_t &userId, sptr<Notification> &notification, bool removeAll = false);
    bool RemoveFromDelayedNotificationList(const std::string &key);
    std::shared_ptr<NotificationRecord> GetFromNotificationList(const std::string &key);
    std::shared_ptr<NotificationRecord> GetFromNotificationList(const int32_t ownerUid, const int32_t notificationId);
    std::shared_ptr<NotificationRecord> GetFromDelayedNotificationList(
        const int32_t ownerUid, const int32_t notificationId);
    std::vector<std::string> GetNotificationKeys(const sptr<NotificationBundleOption> &bundleOption);
    std::vector<std::string> GetNotificationKeysByBundle(const sptr<NotificationBundleOption> &bundleOption);
    bool IsNotificationExists(const std::string &key);
    void SortNotificationList();
    static bool NotificationCompare(
        const std::shared_ptr<NotificationRecord> &first, const std::shared_ptr<NotificationRecord> &second);
    ErrCode PublishInNotificationList(const std::shared_ptr<NotificationRecord> &record);

    sptr<NotificationSortingMap> GenerateSortingMap();

    std::string TimeToString(int64_t time);
    void ExtendDumpForFlags(std::shared_ptr<NotificationFlags>, std::stringstream &stream);
    ErrCode ActiveNotificationDump(const std::string& bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo);
    ErrCode RecentNotificationDump(const std::string& bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    ErrCode DistributedNotificationDump(const std::string& bundle, int32_t userId, int32_t recvUserId,
        std::vector<std::string> &dumpInfo);
#endif
    ErrCode SetRecentNotificationCount(const std::string arg);
    void UpdateRecentNotification(sptr<Notification> &notification, bool isDelete, int32_t reason);

    void AdjustDateForDndTypeOnce(int64_t &beginDate, int64_t &endDate);
    ErrCode PrepareNotificationRequest(const sptr<NotificationRequest> &request);
    ErrCode PrepareContinuousTaskNotificationRequest(const sptr<NotificationRequest> &request, const int32_t &uid);

    void TriggerRemoveWantAgent(const sptr<NotificationRequest> &request, int32_t removeReason, bool isThirdParty);

    ErrCode IsAllowedNotifySelf(const sptr<NotificationBundleOption> &bundleOption, bool &allowed);

    ErrCode SetNotificationRemindType(sptr<Notification> notification, bool isLocal);
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    std::vector<std::string> GetLocalNotificationKeys(const sptr<NotificationBundleOption> &bundleOption);
    NotificationConstant::RemindType GetRemindType();
    ErrCode DoDistributedPublish(
        const sptr<NotificationBundleOption> bundleOption, const std::shared_ptr<NotificationRecord> record);
    ErrCode DoDistributedDelete(
        const std::string deviceId, const std::string bundleName, const sptr<Notification> notification);
    void GetDistributedInfo(const std::string &key, std::string &deviceId, std::string &bundleName);
    bool CheckDistributedNotificationType(const sptr<NotificationRequest> &request);
    void OnDistributedPublish(
        const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request);
    void OnDistributedUpdate(
        const std::string &deviceId, const std::string &bundleName, sptr<NotificationRequest> &request);
    void OnDistributedDelete(
        const std::string &deviceId, const std::string &bundleName, const std::string &label, int32_t id);
    static ErrCode GetDistributedEnableInApplicationInfo(
        const sptr<NotificationBundleOption> bundleOption, bool &enable);
    bool CheckPublishWithoutApp(const int32_t userId, const sptr<NotificationRequest> &request);
    void InitDistributeCallBack();
#endif

    void ClearOverTimeRingToneInfo();
    ErrCode SetDoNotDisturbDateByUser(const int32_t &userId, const sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetDoNotDisturbDateByUser(const int32_t &userId, sptr<NotificationDoNotDisturbDate> &date);
    ErrCode GetHasPoppedDialog(const sptr<NotificationBundleOption> bundleOption, bool &hasPopped);
    static ErrCode GetAppTargetBundle(const sptr<NotificationBundleOption> &bundleOption,
        sptr<NotificationBundleOption> &targetBundle);
    void ReportInfoToResourceSchedule(const int32_t userId, const std::string &bundleName);
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    void GetDumpInfo(const std::vector<std::u16string> &args, std::string &result);

    static void SendSubscribeHiSysEvent(int32_t pid, int32_t uid, const sptr<NotificationSubscribeInfo> &info,
        ErrCode errCode);
    static void SendUnSubscribeHiSysEvent(int32_t pid, int32_t uid, const sptr<NotificationSubscribeInfo> &info);
    void SendPublishHiSysEvent(const sptr<NotificationRequest> &request, ErrCode errCode);
    void SendCancelHiSysEvent(int32_t notificationId, const std::string &label,
        const sptr<NotificationBundleOption> &bundleOption, ErrCode errCode);
    void SendRemoveHiSysEvent(int32_t notificationId, const std::string &label,
        const sptr<NotificationBundleOption> &bundleOption, ErrCode errCode);
    void SendEnableNotificationHiSysEvent(const sptr<NotificationBundleOption> &bundleOption, bool enabled,
        ErrCode errCode);
    void SendEnableNotificationSlotHiSysEvent(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType, bool enabled, ErrCode errCode);
    void SendFlowControlOccurHiSysEvent(const std::shared_ptr<NotificationRecord> &record);
    void SendLiveViewUploadHiSysEvent(const std::shared_ptr<NotificationRecord> &record, int32_t uploadStatus);

    ErrCode SetRequestBundleInfo(const sptr<NotificationRequest> &request, int32_t uid, std::string &bundle);
    ErrCode PrePublishNotificationBySa(const sptr<NotificationRequest> &request, int32_t uid, std::string &bundle);
    ErrCode PrePublishRequest(const sptr<NotificationRequest> &request);
    ErrCode PublishNotificationBySa(const sptr<NotificationRequest> &request);
    bool IsNeedPushCheck(const sptr<NotificationRequest> &request);
    void FillExtraInfoToJson(const sptr<NotificationRequest> &request,
        sptr<NotificationCheckRequest> &checkRequest, nlohmann::json &jsonObject);
    void CreatePushCheckJson(const sptr<NotificationRequest> &request,
        sptr<NotificationCheckRequest> &checkRequest, nlohmann::json &jsonObject);
    ErrCode PushCheck(const sptr<NotificationRequest> &request);
    uint64_t StartAutoDelete(const std::shared_ptr<NotificationRecord> &record,
        int64_t deleteTimePoint, int32_t reason);
    void TriggerAutoDelete(const std::string &hashCode, int32_t reason);
    void SendNotificationsOnCanceled(std::vector<sptr<Notification>> &notifications,
        const sptr<NotificationSortingMap> &notificationMap, int32_t deleteReason);
    void SetAgentNotification(sptr<NotificationRequest>& notificationRequest, std::string& bundleName);
    static bool GetBundleInfoByNotificationBundleOption(
        const sptr<NotificationBundleOption> &bundleOption, AppExecFwk::BundleInfo &bundleInfo);

    ErrCode GetTargetRecordList(const int32_t uid, NotificationConstant::SlotType slotType,
        NotificationContent::Type contentType, std::vector<std::shared_ptr<NotificationRecord>>& recordList);
    ErrCode GetCommonTargetRecordList(const int32_t uid, NotificationConstant::SlotType slotType,
        NotificationContent::Type contentType, std::vector<std::shared_ptr<NotificationRecord>>& recordList);
    ErrCode RemoveNotificationFromRecordList(const std::vector<std::shared_ptr<NotificationRecord>>& recordList);
    ErrCode OnSubscriberAdd(const std::shared_ptr<NotificationSubscriberManager::SubscriberRecord> &record,
        const int32_t userId);
    bool IsLiveViewCanRecover(const sptr<NotificationRequest> request);
    ErrCode FillNotificationRecord(const NotificationRequestDb &requestdbObj,
        std::shared_ptr<NotificationRecord> record);
    static int32_t SetNotificationRequestToDb(const NotificationRequestDb &requestDb);
    static int32_t GetBatchNotificationRequestsFromDb(std::vector<NotificationRequestDb> &requests,
        int32_t userId = -1);
    static int32_t DoubleDeleteNotificationFromDb(const std::string &key,
        const std::string &secureKey, const int32_t userId);
    static int32_t DeleteNotificationRequestFromDb(const std::string &key, const int32_t userId);
    void CancelTimer(uint64_t timerId);
    void BatchCancelTimer(std::vector<uint64_t> timerIds);
    ErrCode UpdateNotificationTimerInfo(const std::shared_ptr<NotificationRecord> &record);
    ErrCode SetFinishTimer(const std::shared_ptr<NotificationRecord> &record);
    ErrCode StartFinishTimer(const std::shared_ptr<NotificationRecord> &record,
        int64_t expireTimePoint, const int32_t reason);
    void CancelFinishTimer(const std::shared_ptr<NotificationRecord> &record);
    ErrCode SetUpdateTimer(const std::shared_ptr<NotificationRecord> &record);
    ErrCode StartUpdateTimer(const std::shared_ptr<NotificationRecord> &record,
        int64_t expireTimePoint, const int32_t reason);
    void CancelUpdateTimer(const std::shared_ptr<NotificationRecord> &record);
    void StartArchiveTimer(const std::shared_ptr<NotificationRecord> &record);
    void CancelArchiveTimer(const std::shared_ptr<NotificationRecord> &record);
    ErrCode StartAutoDeletedTimer(const std::shared_ptr<NotificationRecord> &record);
    void ProcForDeleteLiveView(const std::shared_ptr<NotificationRecord> &record);
    void QueryDoNotDisturbProfile(const int32_t &userId, std::string &enable, std::string &profileId);
    void QueryIntelligentExperienceEnable(const int32_t &userId, std::string &enable);
    void CheckDoNotDisturbProfile(const std::shared_ptr<NotificationRecord> &record);
    void ReportDoNotDisturbModeChanged(const int32_t &userId, std::string &enable);
    void DoNotDisturbUpdataReminderFlags(const std::shared_ptr<NotificationRecord> &record);
    ErrCode CheckCommonParams();
    std::shared_ptr<NotificationRecord> GetRecordFromNotificationList(
        int32_t notificationId, int32_t uid, const std::string &label, const std::string &bundleName, int32_t userId);
    std::shared_ptr<NotificationRecord> MakeNotificationRecord(
        const sptr<NotificationRequest> &request, const sptr<NotificationBundleOption> &bundleOption);
    ErrCode IsAllowedNotifyForBundle(const sptr<NotificationBundleOption> &bundleOption, bool &allowed);
    void FillActionButtons(const sptr<NotificationRequest> &request);
    ErrCode IsAllowedGetNotificationByFilter(const std::shared_ptr<NotificationRecord> &record,
        const sptr<NotificationBundleOption> &bundleOption);
    ErrCode FillRequestByKeys(const sptr<NotificationRequest> &oldRequest,
        const std::vector<std::string> extraInfoKeys, sptr<NotificationRequest> &newRequest);
    ErrCode IsAllowedRemoveSlot(const sptr<NotificationBundleOption> &bundleOption,
        const NotificationConstant::SlotType &slotType);
    void HandleBadgeEnabledChanged(const sptr<NotificationBundleOption> &bundleOption, bool enabled);
    ErrCode CheckBundleOptionValid(sptr<NotificationBundleOption> &bundleOption);
    sptr<NotificationBundleOption> GenerateValidBundleOptionV2(const sptr<NotificationBundleOption> &bundleOption);
    bool IsNeedNotifyConsumed(const sptr<NotificationRequest> &request);
    ErrCode AddRecordToMemory(const std::shared_ptr<NotificationRecord> &record,
        bool isSystemApp, bool isUpdateByOwner, const bool isAgentController);
    ErrCode DuplicateMsgControl(const sptr<NotificationRequest> &request);
    void RemoveExpiredUniqueKey();
    void RemoveExpiredDistributedUniqueKey();
    void RemoveExpiredLocalUniqueKey();
    bool IsDuplicateMsg(const std::list<std::pair<std::chrono::system_clock::time_point, std::string>> &msglist,
        const std::string &key);
    void DeleteDuplicateMsgs(const sptr<NotificationBundleOption> &bundleOption);
    ErrCode PublishRemoveDuplicateEvent(const std::shared_ptr<NotificationRecord> &record);
    ErrCode UpdateSlotAuthInfo(const std::shared_ptr<NotificationRecord> &record);
    std::vector<AppExecFwk::BundleInfo> GetBundlesOfActiveUser();
    void RemoveNotificationList(const std::shared_ptr<NotificationRecord> &record);
    void FillLockScreenPicture(const sptr<NotificationRequest> &newRequest,
        const sptr<NotificationRequest> &oldRequest);
    static ErrCode SetLockScreenPictureToDb(const sptr<NotificationRequest> &request);
    static ErrCode GetLockScreenPictureFromDb(NotificationRequest *request);
    void RemoveDoNotDisturbProfileTrustList(const sptr<NotificationBundleOption> &bundleOption);
    ErrCode DeleteAllByUserInner(const int32_t &userId, int32_t reason, bool isAsync = false, bool removeAll = false);
    ErrCode RemoveAllNotificationsInner(const sptr<NotificationBundleOption> &bundleOption, int32_t reason);
    void ExcuteRemoveAllNotificationsInner(const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationBundleOption> &bundle, int32_t &reason);
    void GetRemoveListForRemoveAll(const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationBundleOption> &bundle, std::vector<std::shared_ptr<NotificationRecord>> &removeList);
    ErrCode ValidRightsForCancelAsBundle(int32_t notificationId, int32_t &reason);
    ErrCode ExcuteRemoveNotification(const sptr<NotificationBundleOption> &bundle,
        int32_t notificationId, const std::string &label, int32_t &removeReason);
    void ExcuteRemoveNotifications(const std::vector<std::string> &keys, int32_t removeReason);
    void GetRemoveListForRemoveNtfBySlot(const sptr<NotificationBundleOption> &bundle,
        const sptr<NotificationSlot> &slot, std::vector<std::shared_ptr<NotificationRecord>> &removeList);
    void ExcuteDeleteAll(ErrCode &result, const int32_t reason);
    ErrCode GetNotificationById(const sptr<NotificationBundleOption> &bundle,
        const int32_t notificationId, sptr<Notification> &notification);
    ErrCode AssignValidNotificationSlot(const std::shared_ptr<NotificationRecord> &record,
        const sptr<NotificationBundleOption> &bundleOption);
    ErrCode UpdateSlotReminderModeBySlotFlags(const sptr<NotificationBundleOption> &bundle, uint32_t slotFlags);
        bool VerifyCloudCapability(const int32_t &uid, const std::string &capability);
    ErrCode CheckSoundPermission(const sptr<NotificationRequest> &request,
        sptr<NotificationBundleOption> &bundleOption);
    void GenerateSlotReminderMode(const sptr<NotificationSlot> &slot, const sptr<NotificationBundleOption> &bundle,
        bool isSpecifiedSlot = false, uint32_t defaultSlotFlags = DEFAULT_SLOT_FLAGS);
    static void CloseAlert(const std::shared_ptr<NotificationRecord> &record);
    bool IsUpdateSystemLiveviewByOwner(const sptr<NotificationRequest> &request);
    bool IsSaCreateSystemLiveViewAsBundle(const std::shared_ptr<NotificationRecord> &record, int32_t ipcUid);
    ErrCode SaPublishSystemLiveViewAsBundle(const std::shared_ptr<NotificationRecord> &record);
    bool IsNotificationExistsInDelayList(const std::string &key);
    uint64_t StartDelayPublishTimer(const int32_t ownerUid, const int32_t notificationId, const uint32_t delayTime);
    ErrCode StartPublishDelayedNotification(const std::shared_ptr<NotificationRecord> &record);
    void StartPublishDelayedNotificationTimeOut(const int32_t ownerUid, const int32_t notificationId);
    void UpdateRecordByOwner(const std::shared_ptr<NotificationRecord> &record, bool isSystemApp);
    void StartFinishTimerForUpdate(const std::shared_ptr<NotificationRecord> &record, uint64_t process);
    ErrCode CheckLongTermLiveView(const sptr<NotificationRequest> &request, const std::string &key);
    void ExcuteCancelGroupCancel(const sptr<NotificationBundleOption>& bundleOption,
        const std::string &groupName, const int32_t reason);
    ErrCode ExcuteCancelAll(const sptr<NotificationBundleOption>& bundleOption, const int32_t reason);
    ErrCode ExcuteDelete(const std::string &key, const int32_t removeReason);
    ErrCode CheckNeedSilent(const std::string &phoneNumber, int32_t callerType, int32_t userId);
    ErrCode QueryContactByProfileId(const std::string &phoneNumber, const std::string &policy, int32_t userId);
    uint32_t GetDefaultSlotFlags(const sptr<NotificationRequest> &request);
    bool IsSystemUser(int32_t userId);
    ErrCode CollaboratePublish(const sptr<NotificationRequest> &request);
    ErrCode SetCollaborateRequest(const sptr<NotificationRequest> &request);
    void SetCollaborateReminderFlag(const sptr<NotificationRequest> &request);
    ErrCode SetEnabledForBundleSlotInner(const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationBundleOption> &bundle,
        const NotificationConstant::SlotType &slotType, NotificationSlot slotInfo);
    ErrCode AddSlotThenPublishEvent(
        const sptr<NotificationSlot> &slot,
        const sptr<NotificationBundleOption> &bundle,
        bool enabled, bool isForceControl, int32_t authStatus = NotificationSlot::AuthorizedStatus::AUTHORIZED);
    ErrCode OnRecoverLiveView(const std::vector<std::string> &keys);
    ErrCode CollaborateFilter(const sptr<NotificationRequest> &request);
    void HandleUpdateLiveViewNotificationTimer(const int32_t uid, const bool isPaused);
    void CancelWantAgent(const sptr<Notification> &notification);
    void CancelOnceWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent);
    void PublishSubscriberExistFlagEvent(bool headsetExistFlag, bool wearableExistFlag);
    void SetClassificationWithVoip(const sptr<NotificationRequest> &request);
    void UpdateCollaborateTimerInfo(const std::shared_ptr<NotificationRecord> &record);
#ifdef ENABLE_ANS_PRIVILEGED_MESSAGE_EXT_WRAPPER
    void SetDialogPoppedUnEnableTime(const sptr<NotificationBundleOption> &bundleOption);
#endif
    ErrCode CommonRequestEnableNotification(const std::string &deviceId,
        const sptr<IAnsDialogCallback> &callback,
        const sptr<IRemoteObject> &callerToken,
        const sptr<NotificationBundleOption> bundleOption,
        const bool innerLake,
        const bool easyAbroad);
    void ClearSlotTypeData(const sptr<NotificationRequest> &request, int32_t callingUid, int32_t sourceType);
    ErrCode RegisterPushCallbackTokenCheck();
    ErrCode RemoveDistributedNotifications(const std::vector<std::string>& hashcodes,
        const int32_t removeReason);
    ErrCode RemoveDistributedNotifications(const NotificationConstant::SlotType& slotType,
        const int32_t removeReason,
        const NotificationConstant::DistributedDeleteType& deleteType);
    ErrCode RemoveDistributedNotificationsByDeviceId(const std::string& deviceId,
        const int32_t removeReason);
    ErrCode RemoveAllDistributedNotifications(const int32_t removeReason);
    bool ExecuteDeleteDistributedNotification(std::shared_ptr<NotificationRecord>& record,
        std::vector<sptr<Notification>>& notifications, const int32_t removeReason);
    bool IsDistributedNotification(sptr<NotificationRequest> request);
    bool IsEnableNotificationByKioskAppTrustList(const std::string &bundleName);
    void InvockLiveViewSwitchCheck(const std::vector<sptr<NotificationBundleOption>>& bundles,
        int32_t userId, uint32_t index);
    void InvokeCheckConfig(const std::string& requestId);
    ErrCode HandlePushCheckFailed(const sptr<NotificationRequest> &request, int32_t result);

    template<typename T>
    bool WriteParcelableVector(const std::vector<sptr<T>> &parcelableVector, MessageParcel &data)
    {
        if (!data.WriteInt32(parcelableVector.size())) {
            ANS_LOGE("Failed to write ParcelableVector size.");
            return false;
        }

        for (auto &parcelable : parcelableVector) {
            if (!data.WriteStrongParcelable(parcelable)) {
                ANS_LOGE("Failed to write ParcelableVector");
                return false;
            }
        }
        return true;
    }

    void SetChainIdToExtraInfo(const sptr<NotificationRequest> &request, OHOS::HiviewDFX::HiTraceId traceId);
    void SetIsFromSAToExtendInfo(const sptr<NotificationRequest> &request);

    ErrCode CheckNotificationRequest(const sptr<NotificationRequest> &request);
    ErrCode CheckNotificationRequestLineWantAgents(const std::shared_ptr<NotificationContent> &content,
        bool isAgentController, bool isSystemComp);
    bool IsReasonClickDelete(const int32_t removeReason);
    void CheckRemovalWantAgent(const sptr<NotificationRequest> &request);
    ErrCode SetCreatorInfoWithAtomicService(const sptr<NotificationRequest> &request);
    AnsStatus CheckAndPrepareNotificationInfoWithAtomicService(
        const sptr<NotificationRequest> &request, sptr<NotificationBundleOption> &bundleOption);
    AnsStatus ExecutePublishProcess(
        const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed);

    ErrCode UpdateNotificationSwitchState(
        const sptr<NotificationBundleOption> &bundleOption, const AppExecFwk::BundleInfo &bundleInfo);
    ErrCode DistributeOperationInner(const sptr<NotificationOperationInfo>& operationInfo);
    
    void CheckExtensionServiceCondition(
        std::vector<std::pair<sptr<NotificationBundleOption>,
        std::vector<sptr<NotificationBundleOption>>>> &extensionBundleInfos,
        std::vector<sptr<NotificationBundleOption>> &bundles);
    bool CheckBluetoothConnectionInInfos(
        const sptr<NotificationBundleOption> &bundleOption,
        const std::vector<sptr<NotificationExtensionSubscriptionInfo>> &infos);
    bool CheckAndUpdateHfpDeviceStatus(
        const sptr<NotificationBundleOption> &bundleOption,
        const sptr<NotificationExtensionSubscriptionInfo> &info,
        const std::vector<sptr<NotificationExtensionSubscriptionInfo>> &infos,
        const std::string &bluetoothAddress);
    bool CheckBluetoothConditions(const std::string &addr);
    void FilterPermissionBundles(std::vector<sptr<NotificationBundleOption>> &bundles);
    void FilterGrantedBundles(std::vector<sptr<NotificationBundleOption>> &bundles);
    void FilterBundlesByBluetoothConnection(std::vector<sptr<NotificationBundleOption>> &bundles);
    bool HasExtensionSubscriptionStateChanged(const sptr<NotificationBundleOption> &bundle, bool enabled);
    ErrCode PreReminderInfoCheck();
    bool isProxyForUnaware(const int32_t uid);
	
    ErrCode RefreshExtensionSubscriptionBundlesFromConfig(const sptr<NotificationBundleOption>& bundleOption,
        std::vector<sptr<NotificationBundleOption>>& enabledBundles);
    bool isExtensionServiceExist();
    int32_t LoadExtensionService();
    int32_t SubscribeExtensionService(const sptr<NotificationBundleOption> &bundleOption,
        const std::vector<sptr<NotificationBundleOption>> &bundles);
    int32_t UnSubscribeExtensionService(const sptr<NotificationBundleOption> &bundleOption);
    int32_t ShutdownExtensionService();
    void PrepareShutdownExtensionService();
    bool EnsureExtensionServiceLoadedAndSubscribed(const sptr<NotificationBundleOption> &bundle);
    bool EnsureExtensionServiceLoadedAndSubscribed(const sptr<NotificationBundleOption> &bundle,
        const std::vector<sptr<NotificationBundleOption>> &subscribeBundles);
    bool ShutdownExtensionServiceAndUnSubscribed(const sptr<NotificationBundleOption> &bundle);
    ErrCode GetNotificationExtensionEnabledBundles(std::vector<sptr<NotificationBundleOption>>  &bundles);
    void RegisterHfpObserver();
    void ProcessHfpDeviceStateChange(const OHOS::Bluetooth::BluetoothRemoteDevice &device, int state);
private:
    static sptr<AdvancedNotificationService> instance_;
    static ffrt::mutex instanceMutex_;
    static ffrt::mutex pushMutex_;
    static std::map<NotificationConstant::SlotType, sptr<IPushCallBack>> pushCallBacks_;
    static std::map<NotificationConstant::SlotType, sptr<NotificationCheckRequest>> checkRequests_;
    bool aggregateLocalSwitch_ = false;
    std::set<int32_t> currentUserId;
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner_ = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_ = nullptr;
    std::list<std::shared_ptr<NotificationRecord>> notificationList_;
    std::shared_ptr<RecentInfo> recentInfo_ = nullptr;
    std::shared_ptr<SystemEventObserver> systemEventObserver_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> pushRecipient_ = nullptr;
    std::shared_ptr<ffrt::queue> notificationSvrQueue_ = nullptr;
    std::map<NotificationConstant::SlotType, std::shared_ptr<BasePublishProcess>> publishProcess_;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    std::shared_ptr<DistributedKvStoreDeathRecipient> distributedKvStoreDeathRecipient_ = nullptr;
    DistributedKv::DistributedKvDataManager dataManager_;
    NotificationConstant::DistributedReminderPolicy distributedReminderPolicy_ = DEFAULT_DISTRIBUTED_REMINDER_POLICY;
    bool localScreenOn_ = true;
#endif
    std::shared_ptr<SoundPermissionInfo> soundPermissionInfo_ = nullptr;
    std::shared_ptr<PermissionFilter> permissonFilter_ = nullptr;
    std::shared_ptr<NotificationSlotFilter> notificationSlotFilter_ = nullptr;
    std::shared_ptr<NotificationDialogManager> dialogManager_ = nullptr;
    std::list<std::pair<std::chrono::system_clock::time_point, std::string>> uniqueKeyList_;
    std::list<std::pair<std::chrono::system_clock::time_point, std::string>> distributedUniqueKeyList_;
    std::list<std::pair<std::chrono::system_clock::time_point, std::string>> localUniqueKeyList_;
    std::list<std::pair<std::shared_ptr<NotificationRecord>, uint64_t>> delayNotificationList_;
    ffrt::mutex delayNotificationMutext_;
    static ffrt::mutex doNotDisturbMutex_;
    std::map<int32_t, std::string> doNotDisturbEnableRecord_;
    bool isCachedAppAndDeviceRelationMap_ = false;
    std::map<std::string, std::string> appAndDeviceRelationMap_;
    std::set<int32_t> proxyForUnawareUidSet_;
    mutable std::shared_mutex proxyForUnawareUidSetMutex_;
    std::atomic<bool> notificationExtensionLoaded_ = false;
    std::shared_ptr<NotificationLoadUtils> notificationExtensionHandler_;
    bool supportHfp_ = false;
    std::vector<sptr<NotificationBundleOption>> cacheNotificationExtensionBundles_;
    uint64_t timerIdShutdownExtensionService_ = 0L;
    std::shared_ptr<HfpStateObserver> hfpObserver_;
};

/**
 * @class PushCallbackRecipient
 * PushCallbackRecipient notices IRemoteBroker died.
 */
class PushCallbackRecipient : public IRemoteObject::DeathRecipient {
public:
    PushCallbackRecipient();
    PushCallbackRecipient(const NotificationConstant::SlotType slotType);
    virtual ~PushCallbackRecipient();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);
private:
    NotificationConstant::SlotType slotType_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_ADVANCED_NOTIFICATION_SERVICE_H
