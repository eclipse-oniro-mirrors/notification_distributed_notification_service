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
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "bundle_manager_helper.h"
#include "in_process_call_wrapper.h"
#include "os_account_manager.h"

namespace OHOS {
namespace Notification {
int32_t NotificationDialog::GetActiveUserId()
{
    std::vector<int32_t> activeUserId;
    auto errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(activeUserId);
    if (errCode != ERR_OK) {
        ANS_LOGE("Query active accountIds failed with %{public}d.", errCode);
        return AppExecFwk::Constants::ANY_USERID;
    }

    if (activeUserId.empty()) {
        ANS_LOGE("Active accountIds is empty.");
        return AppExecFwk::Constants::ANY_USERID;
    }

    return activeUserId.front();
}

int32_t NotificationDialog::GetUidByBundleName(const std::string &bundleName)
{
    auto userId = NotificationDialog::GetActiveUserId();
    return IN_PROCESS_CALL(BundleManagerHelper::GetInstance()->GetDefaultUidByBundleName(bundleName, userId));
}

ErrCode NotificationDialog::StartEnableNotificationDialogAbility(
    const std::string &serviceBundleName,
    const std::string &serviceAbilityName,
    int32_t uid,
    const sptr<IRemoteObject> &callerToken)
{
    ANS_LOGD("%{public}s, Enter.", __func__);
    auto appBundleName = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility().GetBundleName());
    auto topUid = NotificationDialog::GetUidByBundleName(appBundleName);
    if (topUid != uid) {
        ANS_LOGE("Current application isn't in foreground, top is %{private}s.", appBundleName.c_str());
        return ERR_ANS_INVALID_BUNDLE;
    }

    AAFwk::Want want;
    want.SetElementName(serviceBundleName, serviceAbilityName);
    want.SetParam("from", appBundleName);
    if (callerToken != nullptr) {
        want.SetParam("callerToken", callerToken);
    }
    auto result = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want));
    ANS_LOGD("End, result = %{public}d", result);
    return result;
}
}  // namespace Notification
}  // namespace OHOS
