/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "ans_service_errors.h"
#include "notification_bundle_option.h"
#include "notification_constant.h"
#include <map>
#include <vector>

namespace {
    bool g_mockGetNotificationSlotRet = true;
    bool g_mockGetEnabledForBundleSlotsRet = true;
    int32_t g_mockDeleteKvFromDbRet = 0;
}

void MockGetNotificationSlotRet(bool mockRet)
{
    g_mockGetNotificationSlotRet = mockRet;
}

void MockGetEnabledForBundleSlotsRet(bool mockRet)
{
    g_mockGetEnabledForBundleSlotsRet = mockRet;
}

void MockDeleteKvFromDb(int32_t mockRet)
{
    g_mockDeleteKvFromDbRet = mockRet;
}

namespace OHOS {
namespace Notification {
ErrCode NotificationPreferences::GetNotificationSlot(const sptr<NotificationBundleOption> &bundleOption,
    const NotificationConstant::SlotType &type, sptr<NotificationSlot> &slot)
{
    if (g_mockGetNotificationSlotRet == false) {
        return ERR_ANS_INNER_INVALID_PARAM;
    }
    return ERR_OK;
}

bool NotificationPreferences::GetEnabledForBundleSlots(
    const std::vector<sptr<NotificationBundleOption>> &bundleOptions,
    int32_t slotType,
    std::map<sptr<NotificationBundleOption>, bool> &slotEnabled)
{
    return g_mockGetEnabledForBundleSlotsRet;
}

ErrCode NotificationPreferences::SetGeofenceEnabled(bool enabled)
{
    return ERR_OK;
}

int32_t NotificationPreferences::DeleteKvFromDb(const std::string &key, const int32_t &userId)
{
    return g_mockDeleteKvFromDbRet;
}
}  // namespace Notification
}  // namespace OHOS
