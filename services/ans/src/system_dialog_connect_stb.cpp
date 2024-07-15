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
#include "system_dialog_connect_stb.h"
#include "ability_connect_callback_interface.h"
#include "ability_manager_client.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "common_event_manager.h"

constexpr int32_t SIGNAL_NUM = 3;
constexpr int32_t REMOVE_BUNDLE_CODE = 3;
const static std::string DIALOG_CRASH_EVENT = "OnNotificationServiceDialogClicked";

namespace OHOS {
namespace Notification {

void SystemDialogConnectStb::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    ANS_LOGI("on ability connected");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(SIGNAL_NUM);
    data.WriteString16(u"bundleName");
    data.WriteString16(u"com.ohos.notificationdialog");
    data.WriteString16(u"abilityName");
    data.WriteString16(u"EnableNotificationDialog");
    data.WriteString16(u"parameters");
    data.WriteString16(Str8ToStr16(commandStr_));

    int32_t errCode = remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    ANS_LOGI("AbilityConnectionWrapperProxy::OnAbilityConnectDone result %{public}d", errCode);
    if (errCode != ERR_OK) {
        ANS_LOGD("send Request to SytemDialog fail");
        SendRemoveBundleEvent();
    }
}

void SystemDialogConnectStb::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    ANS_LOGI("on ability disconnected");
}

void SystemDialogConnectStb::SendRemoveBundleEvent()
{
    EventFwk::Want want;
    want.SetAction(DIALOG_CRASH_EVENT);

    EventFwk::CommonEventData commonData;
    commonData.SetWant(want);
    commonData.SetCode(REMOVE_BUNDLE_CODE);

    if (commandStr_.empty() || !nlohmann::json::accept(commandStr_)) {
        ANS_LOGW("Invaild json param");
        return;
    }
    nlohmann::json root = nlohmann::json::parse(commandStr_);
    if (!root.contains("from")) {
        ANS_LOGW("not found jsonKey from");
        return;
    }
    if (!root["from"].is_string()) {
        ANS_LOGW("value type of json key from is not string");
        return;
    }
    std::string from = root["from"];
    commonData.SetData(from);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(commonData)) {
        ANS_LOGE("Publish remove bundle failed");
    }
}

}
}