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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_PREFERENCES_CONSTANT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_PREFERENCES_CONSTANT_H

namespace OHOS {
namespace Notification {
/**
 * Indicates distributed database app id.
 */
constexpr char APP_ID[] = "notification_service";

/**
 * Indicates distributed database store id.
 */
constexpr char STORE_ID[] = "local_db";

/**
 * Default params that bundle importance is LEVEL_DEFAULT.
 */
const static int BUNDLE_IMPORTANCE = 3;

/**
 * Default params that bundle badge total num is zero.
 */
const static int BUNDLE_BADGE_TOTAL_NUM = 0;

/**
 * Default params that bundle enable notification is true.
 */
const static int BUNDLE_ENABLE_NOTIFICATION = true;
const static int BUNDLE_POPPED_DIALOG = false;

/**
 * Default params that bundle show badge is false.
 */
const static bool BUNDLE_SHOW_BADGE = true;

/**
 * Indicates bundle type which used to DB store.
 */
enum class BundleType {
    BUNDLE_NAME_TYPE = 1,
    BUNDLE_IMPORTANCE_TYPE,
    BUNDLE_SHOW_BADGE_TYPE,
    BUNDLE_BADGE_TOTAL_NUM_TYPE,
    BUNDLE_ENABLE_NOTIFICATION_TYPE,
    BUNDLE_ENABLE_NOTIFICATION_USER_OPTION,
    BUNDLE_POPPED_DIALOG_TYPE,
    BUNDLE_SLOTFLGS_TYPE,
    BUNDLE_EXTENSION_SUBSCRIPTION_ENABLED_TYPE,
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_PREFERENCES_CONSTANT_H
