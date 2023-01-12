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
#include "advanced_notification_service.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Notification {
bool NotificationDialog::JudgeSelfCalled(const std::shared_ptr<AAFwk::AbilityRecord> &abilityRecord)
{
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenID = abilityRecord->GetApplicationInfo().accessTokenId;
    if (callingTokenId != tokenID) {
        ANS_LOGE("Is not self, not enabled");
        return false;
    }
    return true;
}

ErrCode NotificationDialog::StartEnableNotificationDialogAbility()
{
    ANS_LOGD("%{public}s, Enter.", __func__);
    sptr<IRemoteObject> token;
    int result = IN_PROCESS_CALL(AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility(token));
    std::shared_ptr<AAFwk::AbilityRecord> ability = AAFwk::Token::GetAbilityRecordByToken(token);
    if (result != ERR_OK) {
        ANS_LOGD("%{public}s, GetTopAbility failed. result=%{public}d", __func__, result);
        return result;
    }
    if (!JudgeSelfCalled(ability)) {
        ANS_LOGD("%{public}s, if it is not selfcalled.", __func__);
        return result;
    }
    AAFwk::Want want;
    std::string bundleName = IN_PROCESS_CALL(
        AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility().GetBundleName());
    want.SetElementName("com.ohos.notificationdialog", "EnableNotificationDialog");
    want.SetParam("tokenId", token);
    want.SetParam("from", bundleName);
    result = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token, -1);
    ANS_LOGD("%{public}s, End Calling StartNotificationDialog. result=%{public}d", __func__, result);
    return result;
}
}  // namespace Notification
}  // namespace OHOS