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

#include "advanced_notdisturb_white_list_observer.h"
#include "advanced_notification_service.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
AdvancedNotdisturbWhiteListObserver::AdvancedNotdisturbWhiteListObserver()
{}

AdvancedNotdisturbWhiteListObserver::~AdvancedNotdisturbWhiteListObserver() = default;

void AdvancedNotdisturbWhiteListObserver::OnChange()
{
    if (AdvancedNotificationService::GetInstance() != nullptr) {
        AdvancedNotificationService::GetInstance()->RefreshNotDisturbWhiteList();
        ANS_LOGI("RefreshNotDisturbWhiteList success.");
    }
}
} // namespace Notification
} // namespace OHOS