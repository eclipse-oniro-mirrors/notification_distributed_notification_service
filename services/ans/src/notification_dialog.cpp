/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "notification_dialog.h"

#include "ability_manager_client.h"
#include "ans_const_define.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "bundle_manager_helper.h"
#include "in_process_call_wrapper.h"
#include "os_account_manager.h"
#include "os_account_manager_helper.h"
#include "system_dialog_connect_stb.h"
#include "extension_manager_client.h"
#include <thread>
#include <chrono>

namespace OHOS {
namespace Notification {
namespace {
constexpr int32_t DEFAULT_VALUE = -1;
const int32_t SLEEP_TIME = 200;
constexpr const char* SCENEBOARD_BUNDLE_NAME = "com.ohos.sceneboard";
constexpr const char* SCENEBOARD_ABILITY_NAME = "com.ohos.sceneboard.systemdialog";
constexpr const char* SYSTEM_UI_BUNDLE_NAME = "com.ohos.systemui";
constexpr const char* SYSTEM_UI_ABILITY_NAME = "com.ohos.systemui.dialog";
constexpr const char* UI_EXTENSION_TYPE = "sysDialog/common";

ErrCode ConnectEnableNotificationDialog(
    int32_t uid, const std::string &appBundleName, bool innerLake, bool easyAbroad)
{
    AAFwk::Want want;
    want.SetElementName(SCENEBOARD_BUNDLE_NAME, SCENEBOARD_ABILITY_NAME);

    nlohmann::json root;
    root["bundleName"] = appBundleName;
    root["bundleUid"] = uid;
    root["ability.want.params.uiExtensionType"] = UI_EXTENSION_TYPE;
    root["innerLake"] = innerLake;
    root["easyAbroad"] = easyAbroad;
    std::string command = root.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

    auto connection = sptr<SystemDialogConnectStb>(new (std::nothrow) SystemDialogConnectStb(command));
    if (connection == nullptr) {
        ANS_LOGE("new connection error.");
        return ERR_NO_MEMORY;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();

    auto result = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
        want, connection, nullptr, DEFAULT_VALUE);
    if (result != ERR_OK) {
        ANS_LOGW("connect fail, result = %{public}d", result);
        want.SetElementName(SYSTEM_UI_BUNDLE_NAME, SYSTEM_UI_ABILITY_NAME);
        result = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
            want, connection, nullptr, DEFAULT_VALUE);
    }

    IPCSkeleton::SetCallingIdentity(identity);

    ANS_LOGD("End, result = %{public}d", result);
    return result;
}
}  // namespace

int32_t NotificationDialog::GetUidByBundleName(const std::string &bundleName)
{
    int32_t userId = AppExecFwk::Constants::ANY_USERID;
    OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId);
    return IN_PROCESS_CALL(BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId));
}

ErrCode NotificationDialog::StartEnableNotificationDialogAbility(
    const std::string &serviceBundleName,
    const std::string &serviceAbilityName,
    int32_t uid,
    std::string appBundleName,
    const sptr<IRemoteObject> &callerToken,
    const bool innerLake,
    const bool easyAbroad)
{
    ANS_LOGD("%{public}s, Enter.", __func__);
    int userId = INVALID_USER_ID;
    if (OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK || userId < 0) {
        ANS_LOGE("Failed to get valid userId from uid, function: %{public}s, uid: %{public}d", __FUNCTION__, uid);
        return ERR_ANS_INNER_GET_ACTIVE_USER_FAILED;
    }
    auto topBundleName =
        IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility(false, userId).GetBundleName());
    if (topBundleName != appBundleName) {
        ANS_LOGW("App isn't in foreground, top %{public}s.", topBundleName.c_str());
        if (!innerLake) {
            return ERR_ANS_INNER_INVALID_BUNDLE;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
            topBundleName = IN_PROCESS_CALL(
                AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility(false, userId).GetBundleName());
            if (topBundleName != appBundleName) {
                return ERR_ANS_INNER_INVALID_BUNDLE;
            }
        }
    }
    ANS_LOGD("called");

    return ConnectEnableNotificationDialog(uid, appBundleName, innerLake, easyAbroad);
}
}  // namespace Notification
}  // namespace OHOS
