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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBE_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

class SubscriberInstance : public NotificationSubscriber {
private:
    struct CallbackInfo {
        napi_env env = nullptr;
        napi_ref ref = nullptr;
    };
public:
    SubscriberInstance();
    virtual ~SubscriberInstance();

    /**
     * @brief Called back when a notification is canceled.
     *
     * @param request Indicates the canceled NotificationRequest object.
     * @param sortingMap Indicates the sorting map used by the current subscriber to obtain notification ranking
     * information.
     * @param deleteReason Indicates the reason for the deletion. For details, see NotificationConstant.
     */
    virtual void OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;

    /**
     * @brief Called back when a notification is canceled.
     *
     * @param request Indicates the received NotificationRequest object.
     * @param sortingMap Indicates the sorting map used by the current subscriber to obtain notification ranking
     * information.
     */
    virtual void OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override;

    /**
     * @brief Called back when a notification is canceled.
     *
     * @param sortingMap Indicates the sorting map used to obtain notification ranking information.
     */
    virtual void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override;

    /**
     * @brief Called back when a notification is canceled.
     *
     */
    virtual void OnConnected() override;

    /**
     * @brief Called back when the subscriber is disconnected from the ANS.
     *
     */
    virtual void OnDisconnected() override;

    /**
     * @brief Called back when connection to the ANS has died.
     *
     */
    virtual void OnDied() override;

    /**
     * @brief Called when the Do Not Disturb mode type changes.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     */
    virtual void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override;

    /**
     * @brief Called when the Do Not Disturb mode type changes.
     *
     * @param date Indicates the NotificationDoNotDisturbDate object.
     */
    void onDoNotDisturbChanged(const std::shared_ptr<NotificationDoNotDisturbDate> &date);

    /**
     * @brief Called when the enabled notification changes.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    virtual void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override;

    /**
     * @brief The callback function on the badge enabled state changed.
     *
     * @param callbackData Indicates the EnabledNotificationCallbackData object.
     */
    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    virtual void OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;

    /**
     * @brief The callback function on the badge number changed.
     *
     * @param badgeData Indicates the BadgeNumberCallbackData object.
     */
    virtual bool HasOnBatchCancelCallback() override;

    /**
     * @brief Sets the callback information by type.
     *
     * @param env Indicates the environment that the API is invoked under.
     * @param type Indicates the type of callback.
     * @param ref Indicates the napi_ref of callback.
     */
    void SetCallbackInfo(const napi_env &env, const std::string &type, const napi_ref &ref);

    /**
     * @brief Gets the callback information by type.
     *
     * @param type Indicates the type of callback.
     */
    CallbackInfo GetCallbackInfo(const std::string &type);

    /**
     * @brief Sets threadsafe_function.
     *
     * @param tsfn Indicates the napi_threadsafe_function of callback.
     */
    void SetThreadSafeFunction(const napi_threadsafe_function &tsfn);

private:
    void SetCancelCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetConsumeCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetUpdateCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetSubscribeCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetUnsubscribeCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetDieCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetDisturbModeCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetDisturbDateCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetDisturbChangedCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetEnabledNotificationCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetBadgeCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetBadgeEnabledCallbackInfo(const napi_env &env, const napi_ref &ref);
    void SetBatchCancelCallbackInfo(const napi_env &env, const napi_ref &ref);

    CallbackInfo GetCancelCallbackInfo();
    CallbackInfo GetConsumeCallbackInfo();
    CallbackInfo GetUpdateCallbackInfo();
    CallbackInfo GetSubscribeCallbackInfo();
    CallbackInfo GetUnsubscribeCallbackInfo();
    CallbackInfo GetDieCallbackInfo();
    CallbackInfo GetDisturbModeCallbackInfo();
    CallbackInfo GetDisturbDateCallbackInfo();
    CallbackInfo GetDisturbChangedCallbackInfo();
    CallbackInfo GetEnabledNotificationCallbackInfo();
    CallbackInfo GetBadgeCallbackInfo();
    CallbackInfo GetBadgeEnabledCallbackInfo();
    CallbackInfo GetBatchCancelCallbackInfo();

private:
    napi_threadsafe_function tsfn_ = nullptr;
    CallbackInfo canceCallbackInfo_;
    CallbackInfo consumeCallbackInfo_;
    CallbackInfo updateCallbackInfo_;
    CallbackInfo subscribeCallbackInfo_;
    CallbackInfo unsubscribeCallbackInfo_;
    CallbackInfo dieCallbackInfo_;
    CallbackInfo disturbModeCallbackInfo_;
    CallbackInfo disturbDateCallbackInfo_;
    CallbackInfo disturbChangedCallbackInfo_;
    CallbackInfo enabledNotificationCallbackInfo_;
    CallbackInfo setBadgeCallbackInfo_;
    CallbackInfo setBadgeEnabledCallbackInfo_;
    CallbackInfo batchCancelCallbackInfo_;
};

struct SubscriberInstancesInfo {
    napi_ref ref = nullptr;
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
};

struct AsyncCallbackInfoSubscribe {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::shared_ptr<SubscriberInstance> objectInfo = nullptr;
    NotificationSubscribeInfo subscriberInfo;
    CallbackPromiseInfo info;
};

struct OperationInfo {
    int32_t operationType;
    std::string actionName;
    std::string userInput;
    int32_t btnIndex;
};

struct AsyncOperationCallbackInfo {
    napi_env env;
    napi_value thisVar = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    std::string hashCode;
    OperationInfo operationInfo;
};

static std::mutex mutex_;
static thread_local std::vector<SubscriberInstancesInfo> subscriberInstances_;

static std::mutex delMutex_;
static std::vector<std::shared_ptr<SubscriberInstance>> DeletingSubscriber;

bool HasNotificationSubscriber(const napi_env &env, const napi_value &value, SubscriberInstancesInfo &subscriberInfo);
bool AddSubscriberInstancesInfo(const napi_env &env, const SubscriberInstancesInfo &subscriberInfo);
bool DelSubscriberInstancesInfo(const napi_env &env, const std::shared_ptr<SubscriberInstance> subscriber);

bool AddDeletingSubscriber(std::shared_ptr<SubscriberInstance> subscriber);
void DelDeletingSubscriber(std::shared_ptr<SubscriberInstance> subscriber);

napi_value Subscribe(napi_env env, napi_callback_info info);

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info,
    NotificationSubscribeInfo &subscriberInfo, std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback);
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, std::string &hashCode,
    napi_value& thisVar, OperationInfo& operationInfo);
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBE_H
