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
#include "advanced_notification_service.h"
#include "notification_bundle_option.h"
#include "notification_analytics_util.h"

constexpr int32_t SIGNAL_NUM = 3;

namespace OHOS {
namespace Notification {

void SystemDialogConnectStb::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    ANS_LOGD("on ability connected");
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
        ANS_LOGE("send Request to SytemDialog fail");
        RemoveEnableNotificationDialog();
    }
}

void SystemDialogConnectStb::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    ANS_LOGI("on ability disconnected");
    RemoveEnableNotificationDialog();
}

void SystemDialogConnectStb::RemoveEnableNotificationDialog()
{
    ANS_LOGI("RemoveEnableNotificationDialog called.");
    HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_23, EventBranchId::BRANCH_0);
    if (commandStr_.empty() || !nlohmann::json::accept(commandStr_)) {
        ANS_LOGE("Invalid JSON");
        NotificationAnalyticsUtil::ReportModifyEvent(message);
        return;
    }
    nlohmann::json root = nlohmann::json::parse(commandStr_);
    if (root.is_null() or !root.is_object()) {
        ANS_LOGE("Invalid JSON object");
        NotificationAnalyticsUtil::ReportModifyEvent(message.BranchId(BRANCH_1));
        return;
    }
    if (!root.contains("bundleName") || !root.contains("bundleUid")) {
        ANS_LOGE("not found jsonKey from");
        NotificationAnalyticsUtil::ReportModifyEvent(message.BranchId(BRANCH_2));
        return;
    }
    if (!root["bundleName"].is_string() || !root["bundleUid"].is_number_integer()) {
        ANS_LOGE("value type is not right");
        NotificationAnalyticsUtil::ReportModifyEvent(message.BranchId(BRANCH_3));
        return;
    }
    std::string bundleName = root["bundleName"];
    int32_t bundleUid = root["bundleUid"];
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption(
        bundleName, bundleUid);
    if (bundleOption == nullptr) {
        ANS_LOGE("bundleOption inin fail");
        return;
    }
    AdvancedNotificationService::GetInstance()->RemoveEnableNotificationDialog(bundleOption);
}

}
}