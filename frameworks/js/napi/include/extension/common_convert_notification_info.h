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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_COMMON_CONVERT_NOTIFICATION_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_COMMON_CONVERT_NOTIFICATION_INFO_H

#include "common.h"
#include "notification_info.h"

namespace OHOS {
namespace NotificationNapi {
/**
 * @brief Sets a js object by specified NotificationInfo object
 *
 * @param env Indicates the environment that the API is invoked under
 * @param notification Indicates a NotificationInfo object to be converted
 * @param result Indicates a js object to be set
 * @return Returns the null object if success, returns the null value otherwise
 */
napi_value SetNotificationInfo(
    const napi_env &env, const std::shared_ptr<NotificationInfo> &notificationInfo, napi_value &result);

/**
 * @brief Sets a js object by specified NotificationExtensionContent object
 *
 * @param env Indicates the environment that the API is invoked under
 * @param notification Indicates a NotificationExtensionContent object to be converted
 * @param result Indicates a js object to be set
 * @return Returns the null object if success, returns the null value otherwise
 */
napi_value SetNotificationExtensionContent(const napi_env &env,
    const std::shared_ptr<NotificationExtensionContent> &notificationExtensionContent, napi_value &result);
} // namespace NotificationNapi
} // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_SUBSCRIBER_EXTENSION_CONTEXT_H
 