/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "notification_manager_impl.h"
#include "cj_modal_extension_callback.h"
#include "notification_utils.h"
#include "inner_errors.h"
#include "notification_enable.h"
#include "notification_manager_log.h"
#include "pixel_map_impl.h"
#include "ans_notification.h"
#include "ans_service_errors.h"
#include "singleton.h"

namespace OHOS {
namespace CJSystemapi {
    using namespace OHOS::Notification;
    using namespace OHOS::CJSystemapi::Notification;
    bool CreateUIExtension(sptr<AbilityRuntime::CJAbilityContext> context, const std::string &bundleName);

    static bool ParseParameters(CNotificationRequestV2 params, NotificationRequest &request)
    {
        if (!GetNotificationRequestByNumberV2(params, request)) {
            return false;
        }

        if (!GetNotificationRequestByStringV2(params, request)) {
            return false;
        }

        if (!GetNotificationRequestByBoolV2(params, request)) {
            return false;
        }

        if (!GetNotificationRequestByCustomV2(params, request)) {
            return false;
        }
        return true;
    }

    static bool ParseBundleOption(CNotificationBundleOptionV2 &option, NotificationBundleOption &bundleOption)
    {
        char bundle[STR_MAX_SIZE] = {0};
        if (strcpy_s(bundle, STR_MAX_SIZE, option.bundle) != EOK) {
            return false;
        }
        bundleOption.SetBundleName(std::string(bundle));
        int32_t uid = option.uid;
        bundleOption.SetUid(uid);
        return true;
    }

    int NotificationManagerImplV2::Publish(CNotificationRequestV2 cjRequest)
    {
        NotificationRequest request;
        if (!ParseParameters(cjRequest, request)) {
            return ERROR_PARAM_INVALID;
        }
        uint32_t result =
            AnsNotification::GetInstance()->PublishNotification(request);
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::Cancel(int32_t id, const char* label)
    {
        uint32_t result =
            AnsNotification::GetInstance()->CancelNotification(label, id);
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::CancelAll()
    {
        uint32_t result =
            AnsNotification::GetInstance()->CancelAllNotifications();
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::AddSlot(int32_t type)
    {
        NotificationConstant::SlotType slot = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToCV2(SlotTypeV2(type), slot)) {
            return ERROR_PARAM_INVALID;
        }
        uint32_t result =
            AnsNotification::GetInstance()->AddSlotByType(slot);
        return InnerErrorToExternal(result);
    }

    CNotificationSlotV2 NotificationManagerImplV2::GetSlot(int32_t type, int32_t &errCode)
    {
        CNotificationSlotV2 notificationSlot = {
            .notificationType = 0,
            .level = 0,
            .desc = NULL,
            .badgeFlag = false,
            .bypassDnd = false,
            .lockscreenVisibility = 0,
            .vibrationEnabled = false,
            .sound = NULL,
            .lightEnabled = false,
            .lightColor = 0,
            .vibrationValues = { .head = NULL, .size = 0 },
            .enabled = false
        };
        NotificationConstant::SlotType slotType = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToCV2(SlotTypeV2(type), slotType)) {
            errCode = ERROR_PARAM_INVALID;
            return notificationSlot;
        }

        sptr<NotificationSlot> slot = nullptr;
        uint32_t result =
            AnsNotification::GetInstance()->GetNotificationSlot(slotType, slot);
        errCode = InnerErrorToExternal(result);
        if (slot != nullptr && !SetNotificationSlotV2(*slot, notificationSlot)) {
            errCode = ERROR_PARAM_INVALID;
        }
        return notificationSlot;
    }

    CArrayNotificationSlotsV2 NotificationManagerImplV2::GetSlots(int32_t &errCode)
    {
        CArrayNotificationSlotsV2 notificationSlots = { .head = nullptr, .size = 0 };
        std::vector<sptr<NotificationSlot>> slots;
        uint32_t result =
            AnsNotification::GetInstance()->GetNotificationSlots(slots);
        errCode = InnerErrorToExternal(result);
        if (errCode != SUCCESS_CODE) {
            return notificationSlots;
        }
        if (slots.size() > INT32_MAX / sizeof(CNotificationSlotV2)) {
            errCode = ERROR_INTERNAL_ERROR;
            return notificationSlots;
        }
        CNotificationSlotV2* head =
            reinterpret_cast<CNotificationSlotV2 *>(malloc(sizeof(CNotificationSlotV2) * slots.size()));
        if (head == nullptr) {
            LOGE("null head");
            errCode = ERROR_NO_MEMORY;
            return notificationSlots;
        }
        int32_t count = 0;
        for (auto vec : slots) {
            if (!vec) {
                LOGE("Invalidated NotificationSlot object ptr.");
                continue;
            }
            if (!SetNotificationSlotV2(*vec, head[count])) {
                LOGE("null SetNotificationSlotV2");
                continue;
            }
            count++;
        }
        notificationSlots.size = static_cast<int64_t>(count);
        notificationSlots.head = head;
        return notificationSlots;
    }

    int NotificationManagerImplV2::RemoveSlot(int32_t type)
    {
        NotificationConstant::SlotType slot = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToCV2(SlotTypeV2(type), slot)) {
            return ERROR_PARAM_INVALID;
        }
        uint32_t result =
            AnsNotification::GetInstance()->RemoveNotificationSlot(slot);
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::RemoveAllSlots()
    {
        uint32_t result =
            AnsNotification::GetInstance()->RemoveAllSlots();
        return InnerErrorToExternal(result);
    }

    RetDataUI32 NotificationManagerImplV2::GetActiveNotificationCount()
    {
        RetDataUI32 ret = { .code = 0, .data = 0 };
        uint64_t num = 0;
        uint32_t result =
            AnsNotification::GetInstance()->GetActiveNotificationNums(num);
        ret.code = static_cast<uint32_t>(InnerErrorToExternal(result));
        ret.data = static_cast<uint32_t>(num);
        return ret;
    }

    CArrayNotificationRequestV2 NotificationManagerImplV2::GetActiveNotifications(int32_t &errCode)
    {
        CArrayNotificationRequestV2 notificationRequests = { .head = nullptr, .size = 0 };
        std::vector<sptr<NotificationRequest>> requests;
        uint32_t result =
            AnsNotification::GetInstance()->GetActiveNotifications(requests);
        errCode = InnerErrorToExternal(result);
        if (result != ERR_ANS_INNER_OK) {
            return notificationRequests;
        }
        CNotificationRequestV2** head =
            reinterpret_cast<CNotificationRequestV2 **>(malloc(sizeof(CNotificationRequestV2*) * requests.size()));
        if (head == nullptr) {
            return notificationRequests;
        }
        notificationRequests.size = static_cast<int64_t>(requests.size());
        int32_t count = 0;
        for (auto vec : requests) {
            if (!vec) {
                LOGI("Invalid NotificationRequest object ptr");
                continue;
            }
            head[count] = reinterpret_cast<CNotificationRequestV2 *>(malloc(sizeof(CNotificationRequestV2)));
            if (head[count] == nullptr) {
                LOGE("null head[count]");
                for (int32_t i = 0 ; i < count; i++) {
                    free(head[i]);
                }
                free(head);
                head = nullptr;
                break;
            }
            if (!SetNotificationRequestV2(vec.GetRefPtr(), *(head[count++]))) {
                LOGI("Set NotificationRequest object failed");
                continue;
            }
        }
        notificationRequests.head = head;
        return notificationRequests;
    }

    int NotificationManagerImplV2::CancelGroup(const char* cGroupName)
    {
        std::string groupName(cGroupName);
        uint32_t result =
            AnsNotification::GetInstance()->CancelGroup(groupName);
        return InnerErrorToExternal(result);
    }

    RetDataBool NotificationManagerImplV2::IsSupportTemplate(const char* cTemplateName)
    {
        RetDataBool ret = { .code = 0, .data = false };
        std::string templateName(cTemplateName);
        bool isSupport = false;
        uint32_t result =
            AnsNotification::GetInstance()->IsSupportTemplate(templateName, isSupport);
        ret.code = InnerErrorToExternal(result);
        ret.data = isSupport;
        return ret;
    }

    int NotificationManagerImplV2::SetNotificationEnable(CNotificationBundleOptionV2 option, bool enable)
    {
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            return ERROR_PARAM_INVALID;
        }
        std::string deviceId {""};
        uint32_t result =
            AnsNotification::GetInstance()->SetNotificationsEnabledForSpecifiedBundle(
                bundleOption, deviceId, enable);
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::DisplayBadge(CNotificationBundleOptionV2 option, bool enable)
    {
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            return ERROR_PARAM_INVALID;
        }
        uint32_t result =
            AnsNotification::GetInstance()->SetShowBadgeEnabledForBundle(bundleOption, enable);
        return InnerErrorToExternal(result);
    }

    RetDataBool NotificationManagerImplV2::IsBadgeDisplayed(CNotificationBundleOptionV2 option)
    {
        NotificationBundleOption bundleOption;
        RetDataBool ret = { .code = 0, .data = false };
        if (!ParseBundleOption(option, bundleOption)) {
            ret.code = ERROR_PARAM_INVALID;
            return ret;
        }
        bool enabled = false;
        uint32_t result =
            AnsNotification::GetInstance()->GetShowBadgeEnabledForBundle(bundleOption, enabled);
        ret.code = InnerErrorToExternal(result);
        ret.data = enabled;
        return ret;
    }

    int NotificationManagerImplV2::SetSlotFlagsByBundle(CNotificationBundleOptionV2 option, int32_t slotFlags)
    {
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            return ERROR_PARAM_INVALID;
        }
        uint32_t result =
            AnsNotification::GetInstance()->SetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
        return InnerErrorToExternal(result);
    }

    RetDataUI32 NotificationManagerImplV2::GetSlotFlagsByBundle(CNotificationBundleOptionV2 option)
    {
        RetDataUI32 ret = { .code = 0, .data = 0 };
        uint32_t slotFlags = 0;
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            ret.code = ERROR_PARAM_INVALID;
            return ret;
        }
        uint32_t result =
            AnsNotification::GetInstance()->GetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
        ret.code = static_cast<uint32_t>(InnerErrorToExternal(result));
        ret.data = slotFlags;
        return ret;
    }

    RetDataUI32 NotificationManagerImplV2::GetSlotNumByBundle(CNotificationBundleOptionV2 option)
    {
        RetDataUI32 ret = { .code = 0, .data = 0 };
        uint64_t num = 0;
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            ret.code = ERROR_PARAM_INVALID;
            return ret;
        }
        uint32_t result =
            AnsNotification::GetInstance()->GetNotificationSlotNumAsBundle(bundleOption, num);
        ret.code = static_cast<uint32_t>(InnerErrorToExternal(result));
        ret.data = static_cast<uint32_t>(num);
        return ret;
    }

    int NotificationManagerImplV2::RemoveGroupByBundle(CNotificationBundleOptionV2 option, const char* cGroupName)
    {
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            return ERROR_PARAM_INVALID;
        }
        std::string groupName(cGroupName);
        uint32_t result =
            AnsNotification::GetInstance()->RemoveGroupByBundle(bundleOption, groupName);
        return InnerErrorToExternal(result);
    }

    RetDataBool NotificationManagerImplV2::IsNotificationEnabled()
    {
        RetDataBool ret = { .code = EINVAL, .data = false };
        IsEnableParams params {};
        bool allowed = false;
        uint32_t result;
        if (params.hasBundleOption) {
            LOGI("option.bundle : %{public}s option.uid : %{public}d",
                params.option.GetBundleName().c_str(),
                params.option.GetUid());
            result = AnsNotification::GetInstance()->IsAllowedNotify(params.option, allowed);
        } else if (params.hasUserId) {
            LOGI("userId : %{public}d", params.userId);
            result = AnsNotification::GetInstance()->IsAllowedNotify(params.userId, allowed);
        } else {
            result = AnsNotification::GetInstance()->IsAllowedNotifySelf(allowed);
        }
        ret.code = InnerErrorToExternal(result);
        ret.data = allowed;
        LOGI("result : %{public}d, allowed : %{public}d",
            ret.code, allowed);
        return ret;
    }

    int NotificationManagerImplV2::SetBadgeNumber(int32_t badgeNumber)
    {
        uint32_t result =
            AnsNotification::GetInstance()->SetBadgeNumber(badgeNumber);
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::RequestEnableNotification()
    {
        IsEnableParams params {};
        std::string deviceId {""};
        sptr<AnsDialogHostClient> client = nullptr;
        if (!AnsDialogHostClient::CreateIfNullptr(client)) {
            LOGI("dialog is popping %{public}u.", ERR_ANS_INNER_DIALOG_IS_POPPING)
            return InnerErrorToExternal(ERR_ANS_INNER_DIALOG_IS_POPPING);
        }
        uint32_t result =
            AnsNotification::GetInstance()->RequestEnableNotification(
                deviceId, client, params.callerToken);
        LOGI("done, result is %{public}d.", InnerErrorToExternal(result))
        return InnerErrorToExternal(result);
    }

    int NotificationManagerImplV2::RequestEnableNotificationWithContext(sptr<AbilityRuntime::CJAbilityContext> context)
    {
        sptr<IRemoteObject> callerToken = context->GetToken();
        sptr<AnsDialogHostClient> client = nullptr;
        std::string deviceId {""};
        AnsDialogHostClient::CreateIfNullptr(client, true);
        if (client == nullptr) {
            LOGE("create client fail");
            return InnerErrorToExternal(ERR_ANS_INNER_TASK_ERR);
        }
        bool canPop = false;
        std::string bundleName {""};
        uint32_t result = AnsNotification::GetInstance()->CanPopEnableNotificationDialog(
            client, canPop, bundleName);
        LOGI("canPopDialog result=%{public}d canPop=%{public}d bundleName=%{public}s.",
            result, canPop, bundleName.c_str());
        if (canPop == false) {
            return InnerErrorToExternal(result);
        }
        bool success = CreateUIExtension(context, bundleName);
        if (!success) {
            AnsNotification::GetInstance()->RemoveEnableNotificationDialog();
            return InnerErrorToExternal(ERR_ANS_INNER_TASK_ERR);
        }
        return ERR_OK;
    }

    RetDataBool NotificationManagerImplV2::IsDistributedEnabled()
    {
        RetDataBool ret = { .code = EINVAL, .data = false };
        bool enable = false;
        uint32_t result =
            AnsNotification::GetInstance()->IsDistributedEnabled(enable);
        LOGI("IsDistributedEnabled enable = %{public}d", enable);
        ret.code = InnerErrorToExternal(result);
        ret.data = enable;
        return ret;
    }

    bool CreateUIExtension(sptr<AbilityRuntime::CJAbilityContext> context, const std::string &bundleName)
    {
        if (context == nullptr) {
            LOGE("null cjContext");
            return false;
        }
        auto abilityContext = context->GetAbilityContext();
        if (abilityContext == nullptr) {
            LOGE("null abilityContext");
            return false;
        }
        auto uiContent = abilityContext->GetUIContent();
        if (uiContent == nullptr) {
            LOGE("null uiContent");
            return false;
        }
        AAFwk::Want want;
        std::string targetBundleName = "com.ohos.notificationdialog";
        std::string targetAbilityName = "EnableNotificationDialog";
        want.SetElementName(targetBundleName, targetAbilityName);
        std::string typeKey = "ability.want.params.uiExtensionType";
        std::string typeValue = "sysDialog/common";
        want.SetParam(typeKey, typeValue);
        auto modalCb = std::make_shared<CjModalExtensionCallback>();
        modalCb->SetAbilityContext(abilityContext);
        modalCb->SetBundleName(bundleName);
        Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
            .onRelease = [modalCb](int32_t code) { modalCb->OnRelease(code); },
            .onResult = [modalCb](int32_t rc, const AAFwk::Want& w) { modalCb->OnResult(rc, w); },
            .onReceive = [modalCb](const AAFwk::WantParams& p) { modalCb->OnReceive(p); },
            .onError = [modalCb](int32_t c, const std::string& n, const std::string& m) {
                modalCb->OnError(c, n, m);
            },
            .onRemoteReady = [modalCb](const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy) {
                modalCb->OnRemoteReady(uiProxy);
            },
            .onDestroy = [modalCb]() { modalCb->OnDestroy(); },
        };
        Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;

        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        LOGI("CreateModalUIExtension sessionId=%{public}d", sessionId);
        if (sessionId == 0) {
            return false;
        }
        modalCb->SetSessionId(sessionId);
        return true;
    }
} // CJSystemapi
} // namespace OHOS
