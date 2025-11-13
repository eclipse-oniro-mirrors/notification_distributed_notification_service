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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_CORE_NOTIFICATION_BADGEQUERY_LISTENER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_CORE_NOTIFICATION_BADGEQUERY_LISTENER_H

#include "ibadge_query_callback.h"
#include "badge_query_callback_stub.h"

namespace OHOS {
namespace Notification {
class BadgeQueryListener final : public BadgeQueryCallbackStub {
public:
    BadgeQueryListener(const std::shared_ptr<IBadgeQueryCallback> &badgeQuery);
    ~BadgeQueryListener();
    ErrCode OnBadgeNumberQuery(const sptr<NotificationBundleOption>& bundleOption, int32_t &badgeNumber) override;

public:
    std::weak_ptr<IBadgeQueryCallback> badgeQueryCallback_;
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_CORE_NOTIFICATION_SUBSCRIBER_LISTENER_H
