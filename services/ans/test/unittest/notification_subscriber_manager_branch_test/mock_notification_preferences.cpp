/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "notification_preferences.h"

#include "ans_inner_errors.h"

namespace {
    bool g_mockGetNotificationSlotRet = true;
}

void MockGetNotificationSlotRet(bool mockRet)
{
    g_mockGetNotificationSlotRet = mockRet;
}

namespace OHOS {
namespace Notification {
ErrCode NotificationPreferences::GetNotificationSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &type, sptr<NotificationSlot> &slot)
{
    if (g_mockGetNotificationSlotRet == false) {
        return ERR_ANS_INVALID_PARAM;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS