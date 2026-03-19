/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_SUBSCRIBER_EXTENSION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_ANI_SUBSCRIBER_EXTENSION_H
#include "ani.h"
#include "concurrency_helpers.h"
#include "sts_callback_promise.h"
#include "notification_bundle_option.h"
#include "notification_extension_subscription_info.h"

namespace OHOS {
namespace NotificationExtensionSubScriptionSts {
enum class NotificationExtensionFunctionType {
    NONE, // should not use
    SUBSCRIBE,
    UNSUBSCRIBE,
    GET_SUBSCRIBE_INFO,
    GET_ALL_SUBSCRIPTION_BUNDLES,
    IS_USER_GRANTED,
    GET_USER_GRANTED_STATE,
    SET_USER_GRANTED_STATE,
    GET_USER_GRANTED_ENABLED_BUNDLES,
    GET_USER_GRANTED_ENABLED_BUNDLES_FOR_SELF,
    SET_USER_GRANTED_BUNDLE_STATE
};
struct AsyncCallbackInfoNotificationExtension {
    ani_vm *vm = nullptr;
    arkts::concurrency_helpers::AsyncWork *asyncWork = nullptr;
    OHOS::NotificationSts::CallbackPromiseInfo info;
    NotificationExtensionFunctionType funcType = NotificationExtensionFunctionType::NONE;

    bool enabled = false;
    Notification::NotificationBundleOption targetBundle;
    std::vector<sptr<Notification::NotificationBundleOption>> bundles;
    std::vector<sptr<Notification::NotificationExtensionSubscriptionInfo>> subscriptionInfo;
};

void HandleAsyncCallbackComplete(ani_env *env, arkts::concurrency_helpers::WorkStatus status, void *data);
void HandleAsyncCallbackCompleteInner(ani_env *envCurr, AsyncCallbackInfoNotificationExtension *asyncCallbackInfo);

ani_object AniSubscribe(ani_env *env, ani_object notificationInfoArrayobj);
ani_object AniUnsubscribe(ani_env *env);
ani_object AniGetSubscribeInfo(ani_env *env);
ani_object AniGetAllSubscriptionBundles(ani_env *env);
ani_object AniIsUserGranted(ani_env *env);
ani_object AniGetUserGrantedState(ani_env *env, ani_object bundleOption);
ani_object AniSetUserGrantedState(ani_env *env, ani_object bundleOption, ani_boolean enable);
ani_object AniGetUserGrantedEnabledBundles(ani_env *env, ani_object bundleOption);
ani_object AniGetUserGrantedEnabledBundlesForSelf(ani_env *env);
ani_object AniSetUserGrantedBundleState(ani_env *env, ani_object bundleOption, ani_object bundles, ani_boolean enabled);
} // namespace NotificationExtensionSubScriptionSts
} // namespace OHOS
#endif

