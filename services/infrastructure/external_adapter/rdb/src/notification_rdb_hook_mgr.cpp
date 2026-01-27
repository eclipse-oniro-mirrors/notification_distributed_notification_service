/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "notification_rdb_hook_mgr.h"
#include "ans_log_wrapper.h"

namespace OHOS::Notification::Infra {
bool NtfRdbHookMgr::OnRdbUpgradeLiveviewMigrate(const std::string &oldValue, std::string &newValue)
{
    if (hooks_.OnRdbUpgradeLiveviewMigrate == nullptr) {
        ANS_LOGE("OnRdbUpgradeLiveviewMigrate not init");
        return false;
    }
    return hooks_.OnRdbUpgradeLiveviewMigrate(oldValue, newValue);
}

bool NtfRdbHookMgr::OnRdbOperationFailReport(const int32_t sceneId, const int32_t branchId,
    const int32_t errCode, const std::string &errMsg)
{
    if (hooks_.OnRdbOperationFailReport == nullptr) {
        ANS_LOGE("OnRdbOperationFailReport not init");
        return false;
    }
    hooks_.OnRdbOperationFailReport(sceneId, branchId, errCode, errMsg);
    return true;
}

bool NtfRdbHookMgr::OnSendUserDataSizeHisysevent()
{
    if (hooks_.OnSendUserDataSizeHisysevent == nullptr) {
        ANS_LOGE("OnSendUserDataSizeHisysevent not init");
        return false;
    }
    hooks_.OnSendUserDataSizeHisysevent();
    return true;
}
} // namespace OHOS::Notification::Infra