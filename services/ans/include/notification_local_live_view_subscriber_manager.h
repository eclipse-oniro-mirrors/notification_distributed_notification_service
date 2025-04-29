/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef BND_NOTIFICATION_SERVICE_SERVICES_INCLUDE_NOTIFICATION_LOCAL_LIVE_VIEW_SUBSCRIBER_LOCAL_LIVE_VIEW_MANAGER_H
#define BND_NOTIFICATION_SERVICE_SERVICES_INCLUDE_NOTIFICATION_LOCAL_LIVE_VIEW_SUBSCRIBER_LOCAL_LIVE_VIEW_MANAGER_H

#include <list>
#include <memory>
#include <mutex>

#include "errors.h"
#include "event_handler.h"
#include "event_runner.h"
#include "ffrt.h"
#include "ians_subscriber_local_live_view.h"
#include "nocopyable.h"
#include "refbase.h"
#include "singleton.h"

#include "notification.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include "notification_request.h"
#include "notification_sorting_map.h"
#include "notification_subscribe_info.h"

namespace OHOS {
namespace Notification {
class NotificationLocalLiveViewSubscriberManager : public DelayedSingleton<NotificationLocalLiveViewSubscriberManager> {
public:
    /**
     * @brief Add a subscriber.
     *
     * @param subscriber Indicates the AnsSubscriberInterface object.
     * @param subscribeInfo Indicates the NotificationSubscribeInfo object.
     * @return Indicates the result code.
     */
    ErrCode AddLocalLiveViewSubscriber(const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        const sptr<NotificationSubscribeInfo> &subscribeInfo);

    /**
     * @brief Remove a subscriber.
     *
     * @param subscriber Indicates the AnsSubscriberInterface object.
     * @param subscribeInfo Indicates the NotificationSubscribeInfo object.
     * @return Indicates the result code.
     */
    ErrCode RemoveLocalLiveViewSubscriber(const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        const sptr<NotificationSubscribeInfo> &subscribeInfo);

    /**
     * @brief Notify all subscribers on canceled.
     *
     * @param notification Indicates the Notification object.
     * @param buttonOption Indicates the buttonOption object.
     */
    void NotifyTriggerResponse(const sptr<Notification> &notification,
        const sptr<NotificationButtonOption> &buttonOption);

    /**
     * @brief Obtains the death event.
     *
     * @param object Indicates the death object.
     */
    void OnRemoteDied(const wptr<IRemoteObject> &object);

    /**
     * @brief Reset ffrt queue
     */
    void ResetFfrtQueue();

private:
    struct LocalLiveViewSubscriberRecord;

    std::shared_ptr<LocalLiveViewSubscriberRecord> FindSubscriberRecord(const wptr<IRemoteObject> &object);
    std::shared_ptr<LocalLiveViewSubscriberRecord> FindSubscriberRecord(
        const sptr<IAnsSubscriberLocalLiveView> &subscriber);
    std::shared_ptr<LocalLiveViewSubscriberRecord> CreateSubscriberRecord(
        const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        const sptr<NotificationBundleOption> &bundleOption);
    
    ErrCode AddSubscriberInner(const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        const sptr<NotificationBundleOption> &bundleOption);
    ErrCode RemoveSubscriberInner(const sptr<IAnsSubscriberLocalLiveView> &subscriber,
        const sptr<NotificationSubscribeInfo> &subscribeInfo);

    void NotifyTriggerResponseInner(const sptr<Notification> &notification,
        sptr<NotificationButtonOption> buttonOption);
    bool IsSystemUser(int32_t userId);

private:
    std::list<std::shared_ptr<LocalLiveViewSubscriberRecord>> buttonRecordList_ {};
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner_ {};
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler_ {};
    sptr<IAnsSubscriberLocalLiveView> ansSubscriberProxy_ {};
    sptr<IRemoteObject::DeathRecipient> recipient_ {};
    std::shared_ptr<ffrt::queue> notificationButtonQueue_ = nullptr;

    DECLARE_DELAYED_SINGLETON(NotificationLocalLiveViewSubscriberManager);
    DISALLOW_COPY_AND_MOVE(NotificationLocalLiveViewSubscriberManager);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BND_NOTIFICATION_SERVICE_SERVICES_INCLUDE_NOTIFICATION_LOCAL_LIVE_VIEW_SUBSCRIBER_LOCAL_LIVE_VIEW_MANAGER_H