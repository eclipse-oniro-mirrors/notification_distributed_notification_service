/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "mock_notification_helper.h"

#include "notification_helper.h"

namespace OHOS::Notification {
namespace {
bool g_mockIsAllowUseReminder = true;
bool g_mockIsAllowedNotify = true;
int32_t g_mockIsAllowedNotifyRet = 0;
}

void MockNotificationHelper::MockIsAllowUseReminder(const bool isAllowUseReminder)
{
    g_mockIsAllowUseReminder = isAllowUseReminder;
}

void MockNotificationHelper::MockIsAllowedNotify(const bool isAllowedNotify, const int32_t ret)
{
    g_mockIsAllowedNotify = isAllowedNotify;
    g_mockIsAllowedNotifyRet = ret;
}

ErrCode NotificationHelper::AllowUseReminder(const std::string& bundleName, bool& isAllowUseReminder)
{
    isAllowUseReminder = g_mockIsAllowUseReminder;
    return 0;
}

ErrCode NotificationHelper::IsAllowedNotify(const NotificationBundleOption& bundleOption, bool& allowed)
{
    allowed = g_mockIsAllowedNotify;
    return g_mockIsAllowedNotifyRet;
}
} // namespace OHOS::Notification