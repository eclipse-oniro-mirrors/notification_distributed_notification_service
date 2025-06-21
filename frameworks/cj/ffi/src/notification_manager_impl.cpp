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
#include "notification_utils.h"
#include "inner_errors.h"
#include "notification_enable.h"
#include "notification_manager_log.h"
#include "pixel_map_impl.h"

namespace OHOS {
namespace CJSystemapi {

    using namespace OHOS::Notification;
    using namespace OHOS::CJSystemapi::Notification;

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
        int code = NotificationHelper::PublishNotification(request);
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::Cancel(int32_t id, const char* label)
    {
        int code = NotificationHelper::CancelNotification(label, id);
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::CancelAll()
    {
        int code = NotificationHelper::CancelAllNotifications();
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::AddSlot(int32_t type)
    {
        NotificationConstant::SlotType slot = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToCV2(SlotTypeV2(type), slot)) {
            return ERROR_PARAM_INVALID;
        }
        int code = NotificationHelper::AddSlotByType(slot);
        return ErrorToExternal(code);
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
        errCode = ErrorToExternal(NotificationHelper::GetNotificationSlot(slotType, slot));
        if (slot != nullptr && !SetNotificationSlotV2(*slot, notificationSlot)) {
            errCode = ERROR_PARAM_INVALID;
        }
        return notificationSlot;
    }

    CArrayNotificationSlotsV2 NotificationManagerImplV2::GetSlots(int32_t &errCode)
    {
        CArrayNotificationSlotsV2 notificationSlots = { .head = nullptr, .size = 0 };
        std::vector<sptr<NotificationSlot>> slots;
        errCode = ErrorToExternal(NotificationHelper::GetNotificationSlots(slots));
        CNotificationSlotV2* head =
            reinterpret_cast<CNotificationSlotV2 *>(malloc(sizeof(CNotificationSlotV2) * slots.size()));
        if (head == nullptr) {
            LOGE("null head");
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
        notificationSlots.size = static_cast<int64_t>(slots.size());
        notificationSlots.head = head;
        return notificationSlots;
    }

    int NotificationManagerImplV2::RemoveSlot(int32_t type)
    {
        NotificationConstant::SlotType slot = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToCV2(SlotTypeV2(type), slot)) {
            return ERROR_PARAM_INVALID;
        }
        int code = NotificationHelper::RemoveNotificationSlot(slot);
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::RemoveAllSlots()
    {
        int code = NotificationHelper::RemoveAllSlots();
        return ErrorToExternal(code);
    }

    RetDataUI32 NotificationManagerImplV2::GetActiveNotificationCount()
    {
        RetDataUI32 ret = { .code = 0, .data = 0 };
        uint64_t num = 0;
        int code = NotificationHelper::GetActiveNotificationNums(num);
        ret.code = static_cast<uint32_t>(ErrorToExternal(code));
        ret.data = static_cast<uint32_t>(num);
        return ret;
    }

    CArrayNotificationRequestV2 NotificationManagerImplV2::GetActiveNotifications(int32_t &errCode)
    {
        CArrayNotificationRequestV2 notificationRequests = { .head = nullptr, .size = 0 };
        std::vector<sptr<NotificationRequest>> requests;
        int code = NotificationHelper::GetActiveNotifications(requests);
        errCode = ErrorToExternal(code);
        if (code != ERR_OK) {
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
        int code = NotificationHelper::CancelGroup(groupName);
        return ErrorToExternal(code);
    }

    RetDataBool NotificationManagerImplV2::IsSupportTemplate(const char* cTemplateName)
    {
        RetDataBool ret = { .code = 0, .data = false };
        std::string templateName(cTemplateName);
        bool isSupport = false;
        int code = NotificationHelper::IsSupportTemplate(templateName, isSupport);
        ret.code = ErrorToExternal(code);
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
        int code = NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, enable);
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::DisplayBadge(CNotificationBundleOptionV2 option, bool enable)
    {
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            return ERROR_PARAM_INVALID;
        }
        int code = NotificationHelper::SetShowBadgeEnabledForBundle(bundleOption, enable);
        return ErrorToExternal(code);
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
        int code = NotificationHelper::GetShowBadgeEnabledForBundle(bundleOption, enabled);
        ret.code = ErrorToExternal(code);
        ret.data = enabled;
        return ret;
    }

    int NotificationManagerImplV2::SetSlotFlagsByBundle(CNotificationBundleOptionV2 option, int32_t slotFlags)
    {
        NotificationBundleOption bundleOption;
        if (!ParseBundleOption(option, bundleOption)) {
            return ERROR_PARAM_INVALID;
        }
        int code = NotificationHelper::SetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
        return ErrorToExternal(code);
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
        int code = NotificationHelper::GetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
        ret.code = static_cast<uint32_t>(ErrorToExternal(code));
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
        int code = NotificationHelper::GetNotificationSlotNumAsBundle(bundleOption, num);
        ret.code = static_cast<uint32_t>(ErrorToExternal(code));
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
        int code = NotificationHelper::RemoveGroupByBundle(bundleOption, groupName);
        return ErrorToExternal(code);
    }

    RetDataBool NotificationManagerImplV2::IsNotificationEnabled()
    {
        RetDataBool ret = { .code = EINVAL, .data = false };
        IsEnableParams params {};
        bool allowed = false;
        int errorCode;
        if (params.hasBundleOption) {
            LOGI("option.bundle : %{public}s option.uid : %{public}d",
                params.option.GetBundleName().c_str(),
                params.option.GetUid());
            errorCode = NotificationHelper::IsAllowedNotify(params.option, allowed);
        } else if (params.hasUserId) {
            LOGI("userId : %{public}d", params.userId);
            errorCode = NotificationHelper::IsAllowedNotify(params.userId, allowed);
        } else {
            errorCode = NotificationHelper::IsAllowedNotifySelf(allowed);
        }
        ret.code = ErrorToExternal(errorCode);
        ret.data = allowed;
        LOGI("errorCode : %{public}d, allowed : %{public}d",
            errorCode, allowed);
        return ret;
    }

    int NotificationManagerImplV2::SetBadgeNumber(int32_t badgeNumber)
    {
        int code = NotificationHelper::SetBadgeNumber(badgeNumber);
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::RequestEnableNotification()
    {
        IsEnableParams params {};
        std::string deviceId {""};
        sptr<AnsDialogHostClient> client = nullptr;
        if (!AnsDialogHostClient::CreateIfNullptr(client)) {
            LOGI("dialog is popping %{public}d.", ERR_ANS_DIALOG_IS_POPPING)
            return ErrorToExternal(ERR_ANS_DIALOG_IS_POPPING);
        }
        int code = NotificationHelper::RequestEnableNotification(deviceId, client, params.callerToken);
        LOGI("done, code is %{public}d.", code)
        return ErrorToExternal(code);
    }

    int NotificationManagerImplV2::RequestEnableNotificationWithContext(sptr<AbilityRuntime::CJAbilityContext> context)
    {
        IsEnableParams params {};
        sptr<IRemoteObject> callerToken = context->GetToken();
        params.callerToken = callerToken;
        sptr<AnsDialogHostClient> client = nullptr;
        params.hasCallerToken = true;
        std::string deviceId {""};
        if (!AnsDialogHostClient::CreateIfNullptr(client)) {
            LOGI("dialog is popping %{public}d.", ERR_ANS_DIALOG_IS_POPPING)
            return ErrorToExternal(ERR_ANS_DIALOG_IS_POPPING);
        }
        int code = NotificationHelper::RequestEnableNotification(deviceId, client, params.callerToken);
        LOGI("done, code is %{public}d.", code)
        return ErrorToExternal(code);
    }

    RetDataBool NotificationManagerImplV2::IsDistributedEnabled()
    {
        RetDataBool ret = { .code = EINVAL, .data = false };
        bool enable = false;
        int code = NotificationHelper::IsDistributedEnabled(enable);
        LOGI("IsDistributedEnabled enable = %{public}d", enable);
        ret.code = code;
        ret.data = enable;
        return ret;
    }
} // CJSystemapi
} // namespace OHOS