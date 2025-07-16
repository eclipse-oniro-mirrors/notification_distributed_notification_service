/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "ans_notification.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {

ErrCode AnsNotification::SetNotificationsEnabledForSpecifiedBundle(
    const NotificationBundleOption &bundleOption, const std::string &deviceId, bool enabled)
{
    if (bundleOption.GetBundleName() == "gg") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}

ErrCode AnsNotification::GetTargetDeviceStatus(const std::string &deviceType, int32_t &status)
{
    if (deviceType == "phone") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}

ErrCode AnsNotification::SetTargetDeviceStatus(const std::string &deviceType, const uint32_t status,
    const std::string deveiceId)
{
    if (deviceType == "phone") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}

ErrCode AnsNotification::SetSmartReminderEnabled(const std::string &deviceType, const bool enabled)
{
    if (deviceType == "phone") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}

ErrCode AnsNotification::SetDistributedEnabledByBundle(const NotificationBundleOption &bundleOption,
    const std::string &deviceType, const bool enabled)
{
    if (deviceType == "phone") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}

ErrCode AnsNotification::SetDistributedBundleOption(
    const std::vector<DistributedBundleOption> &bundles, const std::string &deviceType)
{
    if (deviceType == "phone") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}

ErrCode AnsNotification::SetDistributedEnabledBySlot(
    const NotificationConstant::SlotType &slotType, const std::string &deviceType, const bool enabled)
{
    if (deviceType == "phone") {
        return ERR_OK;
    } else {
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
}
}  // namespace Notification
}  // namespace OHOS