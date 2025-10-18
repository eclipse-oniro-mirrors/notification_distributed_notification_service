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
#include "common_event_manager.h"

namespace OHOS {
namespace {
bool g_mockIsAllowUseReminder = true;
bool g_mockIsAllowedNotify = true;
bool g_mockSubscribeCommonEventRet = true;
int32_t g_mockIsAllowedNotifyRet = 0;
int32_t g_mockSubscribeNotificationRet = 0;
}

namespace Notification {
void MockNotificationHelper::MockIsAllowUseReminder(const bool isAllowUseReminder)
{
    g_mockIsAllowUseReminder = isAllowUseReminder;
}

void MockNotificationHelper::MockIsAllowedNotify(const bool isAllowedNotify, const int32_t ret)
{
    g_mockIsAllowedNotify = isAllowedNotify;
    g_mockIsAllowedNotifyRet = ret;
}

void MockNotificationHelper::MockSubscribeNotification(const int32_t ret)
{
    g_mockSubscribeNotificationRet = ret;
}

void MockNotificationHelper::MockSubscribeCommonEvent(const bool ret)
{
    g_mockSubscribeCommonEventRet = ret;
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

ErrCode NotificationHelper::SubscribeNotification(const NotificationSubscriber& subscriber)
{
    return g_mockSubscribeNotificationRet;
}
}

namespace EventFwk {
bool CommonEventManager::SubscribeCommonEvent(const std::shared_ptr<CommonEventSubscriber>& subscriber)
{
    return g_mockSubscribeCommonEventRet;
}
}
} // namespace OHOS