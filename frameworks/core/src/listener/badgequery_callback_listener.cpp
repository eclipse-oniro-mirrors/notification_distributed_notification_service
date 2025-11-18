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

#include "ans_badgequery_listener.h"
#include "ans_trace_wrapper.h"

namespace OHOS {
namespace Notification {
BadgeQueryListener::BadgeQueryListener(const std::shared_ptr<IBadgeQueryCallback> &badgeQueryCallback)
    : badgeQueryCallback_(badgeQueryCallback)
{};

BadgeQueryListener::~BadgeQueryListener()
{}

ErrCode BadgeQueryListener::OnBadgeNumberQuery(const sptr<NotificationBundleOption>& bundleOption, int32_t &badgeNumber)
{
    auto badgeQueryCallback = badgeQueryCallback_.lock();
    if (badgeQueryCallback == nullptr) {
        ANS_LOGE("null badgeQueryCallback");
        return ERR_INVALID_DATA;
    }
    badgeQueryCallback->OnBadgeNumberQuery(bundleOption, badgeNumber);
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
