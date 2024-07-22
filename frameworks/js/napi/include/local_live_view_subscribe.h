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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBE_H

#include "common.h"
#include "notification_bundle_option.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

class LocalLiveViewSubscriberInstance : public NotificationLocalLiveViewSubscriber {
public:
    LocalLiveViewSubscriberInstance();
    virtual ~LocalLiveViewSubscriberInstance();

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

    virtual void OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption) override;

    /**
     * @brief Called back when connection to the ANS has died.
     *
     */
    virtual void OnDied() override;

    /**
     * @brief Sets the callback information by type.
     *
     * @param env Indicates the environment that the API is invoked under.
     * @param type Indicates the type of callback.
     * @param ref Indicates the napi_ref of callback.
     */
    void SetCallbackInfo(const napi_env &env, const std::string &type, const napi_ref &ref);

private:
    void SetResponseCallbackInfo(const napi_env &env, const napi_ref &ref);

private:
    struct CallbackInfo {
        napi_env env = nullptr;
        napi_ref ref = nullptr;
    };

    CallbackInfo responseCallbackInfo_;
};

struct LocalLiveViewSubscriberInstancesInfo {
    napi_ref ref = nullptr;
    LocalLiveViewSubscriberInstance *subscriber = nullptr;
};

struct AsyncCallbackInfoSubscribeLocalLiveView {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    LocalLiveViewSubscriberInstance *objectInfo = nullptr;
    NotificationBundleOption bundleOption;
    NotificationButtonOption buttonOption;
    int32_t notificationId;
    CallbackPromiseInfo info;
};

static std::mutex mutex_;
static thread_local std::vector<LocalLiveViewSubscriberInstancesInfo> subscriberInstances_;

static std::mutex delMutex_;
static std::vector<LocalLiveViewSubscriberInstance*> DeletingSubscriber;

bool HasNotificationSubscriber(const napi_env &env,
    const napi_value &value, LocalLiveViewSubscriberInstancesInfo &subscriberInfo);
bool AddSubscriberInstancesInfo(const napi_env &env, const LocalLiveViewSubscriberInstancesInfo &subscriberInfo);
bool DelSubscriberInstancesInfo(const napi_env &env, const LocalLiveViewSubscriberInstance *subscriber);

bool AddDeletingSubscriber(LocalLiveViewSubscriberInstance *subscriber);
void DelDeletingSubscriber(LocalLiveViewSubscriberInstance *subscriber);

napi_value Subscribe(napi_env env, napi_callback_info info);

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info,
    LocalLiveViewSubscriberInstance *&subscriber, napi_ref &callback);
}  // namespace NotificationNapi
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBE_H
