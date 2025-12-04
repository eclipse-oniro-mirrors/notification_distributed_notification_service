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

#include "notification_clone_geofence_switch.h"

#include "ans_log_wrapper.h"
#include "notification_preferences.h"
#include "notification_clone_util.h"
#include "os_account_manager_helper.h"

namespace OHOS {
namespace Notification {
constexpr const char *NOTIFICATION_GEOFENCE_ENABLE = "notificationGeofenceEnable";
std::shared_ptr<NotificationCloneGeofenceSwitch> NotificationCloneGeofenceSwitch::GetInstance()
{
    static std::shared_ptr<NotificationCloneGeofenceSwitch> instance =
        std::make_shared<NotificationCloneGeofenceSwitch>();
    return instance;
}

NotificationCloneGeofenceSwitch::NotificationCloneGeofenceSwitch()
{
}

NotificationCloneGeofenceSwitch::~NotificationCloneGeofenceSwitch()
{
}

void NotificationCloneGeofenceSwitch::OnRestoreStart(const std::string bundleName, int32_t appIndex,
    int32_t userId, int32_t uid)
{
}

void NotificationCloneGeofenceSwitch::OnUserSwitch(int32_t userId)
{
    ANS_LOGD("Handler user switch %{public}d", userId);
}

ErrCode NotificationCloneGeofenceSwitch::OnBackup(nlohmann::json &jsonObject)
{
    ANS_LOGI("NotificationCloneGeofenceSwitch OnBackup");
    bool enable = false;
    NotificationPreferences::GetInstance()->IsGeofenceEnabled(enable);
    jsonObject[NOTIFICATION_GEOFENCE_ENABLE] = enable ? 1 : 0;
    // 将enable转换为json对象
    ANS_LOGD("Notification bundle list %{public}s", jsonObject.dump().c_str());
    return ERR_OK;
}

void NotificationCloneGeofenceSwitch::OnRestore(const nlohmann::json &jsonObject, std::set<std::string> systemApps)
{
    ANS_LOGI("NotificationCloneGeofenceSwitch OnRestore");
    if (jsonObject.is_null()) {
        ANS_LOGI("jsonObject is null");
        return;
    }

    // 将json对象中的数据enable解析出来
    bool enable = false;
    if (jsonObject.contains(NOTIFICATION_GEOFENCE_ENABLE) && jsonObject[NOTIFICATION_GEOFENCE_ENABLE].is_number()) {
        int32_t geofence_enable = jsonObject.at(NOTIFICATION_GEOFENCE_ENABLE).get<int32_t>();
        enable = (geofence_enable == 1);
    }

    NotificationPreferences::GetInstance()->SetGeofenceEnabled(enable);

    ANS_LOGD("end");
}
}
}