/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_MANAGER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_MANAGER_H

#include <list>
#include <memory>
#include <mutex>
#include <string>

#include "common_event_data.h"
#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#include "refbase.h"

#include "ans_dialog_callback_interface.h"
#include "ans_inner_errors.h"

namespace OHOS::Notification {
class AdvancedNotificationService;
class NotificationBundleOption;
class NotificationDialogManager;

enum class DialogStatus {
    ALLOW_CLICKED,
    DENY_CLICKED,
    DIALOG_CRASHED,
    DIALOG_SERVICE_DESTROYED
};

class NotificationDialogEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    DISALLOW_COPY_AND_MOVE(NotificationDialogEventSubscriber);
    explicit NotificationDialogEventSubscriber(
        NotificationDialogManager& dialogManager,
        const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    ~NotificationDialogEventSubscriber() override;

    static std::shared_ptr<NotificationDialogEventSubscriber> Create(NotificationDialogManager& dialogManager);
    void OnReceiveEvent(const EventFwk::CommonEventData& data) override;

private:
    inline static const std::string EVENT_NAME = "OnNotificationServiceDialogClicked";
    NotificationDialogManager& dialogManager_;
};

class NotificationDialogManager final {
public:
    DISALLOW_COPY_AND_MOVE(NotificationDialogManager);
    NotificationDialogManager(AdvancedNotificationService& ans);
    ~NotificationDialogManager();

    /*
     * Subscribe CommonEvent, return false if failed
     */
    bool Init();

    struct DialogInfo {
        sptr<NotificationBundleOption> bundleOption;
        // When multi devices are going to be supported, a deviceId need to be stored
        sptr<AnsDialogCallback> callback;
    };

    /**
     * @return ERR_OK when dialog serivce is requested successfully
     * @return ERR_ANS_DIALOG_IS_POPPING when dialog is already popped
     * @return ERROR_INTERNAL_ERROR for other errors
     */
    ErrCode RequestEnableNotificationDailog(
        const sptr<NotificationBundleOption>& bundle,
        const sptr<AnsDialogCallback>& callback,
        const sptr<IRemoteObject>& callerToken
    );

    /*
     * Currently, notification dialog do not support multi device
     * Due to that commonEvent is used for now and
     * `NotificationDialogEventSubscriber` only subscribe commonEvent published by
     * "com.ohos.notificationdialog", caller token is not checked
     * when commonEvent callback is triggered.
     */
    ErrCode OnBundleEnabledStatusChanged(DialogStatus status, const std::string& bundleName);

    inline static const std::string NOTIFICATION_DIALOG_SERVICE_BUNDLE = "com.ohos.notificationdialog";
    inline static const std::string NOTIFICATION_DIALOG_SERVICE_ABILITY = "EnableNotificationDialog";

private:
    inline static const std::string DEFAULT_DEVICE_ID = "";
    static bool SetHasPoppedDialog(const sptr<NotificationBundleOption>& bundleOption, bool hasPopped);

    // bundle need to be not null
    bool AddDialogInfoIfNotExist(const sptr<NotificationBundleOption>& bundle, const sptr<AnsDialogCallback>& callback);
    sptr<NotificationBundleOption> GetBundleOptionByBundleName(const std::string& bundleName);
    // bundle need to be not null
    void RemoveDialogInfoByBundleOption(const sptr<NotificationBundleOption>& bundle,
        std::unique_ptr<DialogInfo>& dialogInfoRemoved);
    void RemoveAllDialogInfos(std::list<std::unique_ptr<DialogInfo>>& dialogInfosRemoved);

    bool OnDialogButtonClicked(const std::string& bundleName, bool enabled);
    bool OnDialogCrashed(const std::string& bundleName);
    bool OnDialogServiceDestroyed();

    bool HandleOneDialogClosed(sptr<NotificationBundleOption> bundleOption, EnabledDialogStatus status);
    bool HandleAllDialogsClosed();

    std::shared_ptr<NotificationDialogEventSubscriber> dialogEventSubscriber = nullptr;
    AdvancedNotificationService& ans_;
    std::mutex dialogsMutex_;
    std::list<std::unique_ptr<DialogInfo>> dialogsOpening_;
};
} // namespace OHOS::Notification
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_NOTIFICATION_DIALOG_MANAGER_H
