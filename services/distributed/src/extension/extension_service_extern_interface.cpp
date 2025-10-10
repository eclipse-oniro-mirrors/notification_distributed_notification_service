/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <cstdint>

#include "extension_service.h"

#define SYMBOL_EXPORT __attribute__ ((visibility("default")))
namespace OHOS {
namespace Notification {
#ifdef __cplusplus
extern "C" {
#endif

SYMBOL_EXPORT int32_t Startup()
{
    return NotificationExtensionService::GetInstance().InitService();
}

SYMBOL_EXPORT void Shutdown()
{
    NotificationExtensionService::GetInstance().DestroyService();
}

SYMBOL_EXPORT void Subscribe(
    const sptr<NotificationBundleOption> bundle, const std::vector<sptr<NotificationBundleOption>>& subscribedBundles)
{
    NotificationExtensionService::GetInstance().SubscribeNotification(bundle, subscribedBundles);
}

SYMBOL_EXPORT void Unsubscribe(const sptr<NotificationBundleOption> bundle)
{
    NotificationExtensionService::GetInstance().UnsubscribeNotification(bundle);
}

SYMBOL_EXPORT size_t GetSubscriberCount()
{
    return NotificationExtensionService::GetInstance().GetSubscriberCount();
}

#ifdef __cplusplus
}
#endif
}  // namespace Notification
}  // namespace OHOS
