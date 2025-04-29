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

#include "notification_manager_ffi.h"
#include "notification_manager_impl.h"
#include "macro.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace CJSystemapi {
namespace Notification {

extern "C" {
int32_t FfiOHOSNotificationManagerPublishV2(CNotificationRequestV2 request)
{
    auto code = NotificationManagerImplV2::Publish(request);
    return code;
}

int32_t FfiOHOSNotificationManagerCancelV2(int32_t id, const char* label)
{
    auto code = NotificationManagerImplV2::Cancel(id, label);
    return code;
}

int32_t FfiOHOSNotificationManagerCancelAllV2()
{
    auto code = NotificationManagerImplV2::CancelAll();
    return code;
}

int32_t FfiOHOSNotificationManagerAddSlotV2(int32_t type)
{
    auto code = NotificationManagerImplV2::AddSlot(type);
    return code;
}

CNotificationSlotV2 FfiOHOSNotificationManagerGetSlot(int32_t type, int32_t* errCode)
{
    CNotificationSlotV2 ret = NotificationManagerImplV2::GetSlot(type, *errCode);
    return ret;
}

CArrayNotificationSlotsV2 FfiOHOSNotificationManagerGetSlots(int32_t* errCode)
{
    CArrayNotificationSlotsV2 ret = NotificationManagerImplV2::GetSlots(*errCode);
    return ret;
}

int32_t FfiOHOSNotificationManagerRemoveSlot(int32_t type)
{
    auto code = NotificationManagerImplV2::RemoveSlot(type);
    return code;
}

int32_t FfiOHOSNotificationManagerRemoveAllSlots()
{
    auto code = NotificationManagerImplV2::RemoveAllSlots();
    return code;
}

RetDataUI32 FfiOHOSNotificationManagerGetActiveNotificationCount()
{
    RetDataUI32 ret = NotificationManagerImplV2::GetActiveNotificationCount();
    return ret;
}

CArrayNotificationRequestV2 FfiOHOSNotificationManagerGetActiveNotifications(int32_t* errCode)
{
    CArrayNotificationRequestV2 ret = NotificationManagerImplV2::GetActiveNotifications(*errCode);
    return ret;
}

int32_t FfiOHOSNotificationManagerCancelGroup(const char* cGroupName)
{
    auto code = NotificationManagerImplV2::CancelGroup(cGroupName);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsSupportTemplate(const char* cTemplateName)
{
    RetDataBool ret =  NotificationManagerImplV2::IsSupportTemplate(cTemplateName);
    return ret;
}

int32_t FfiOHOSNotificationManagerSetNotificationEnable(CNotificationBundleOptionV2 option, bool enable)
{
    auto code = NotificationManagerImplV2::SetNotificationEnable(option, enable);
    return code;
}

int32_t FfiOHOSNotificationManagerDisplayBadge(CNotificationBundleOptionV2 option, bool enable)
{
    auto code = NotificationManagerImplV2::DisplayBadge(option, enable);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsBadgeDisplayed(CNotificationBundleOptionV2 option)
{
    RetDataBool ret =  NotificationManagerImplV2::IsBadgeDisplayed(option);
    return ret;
}

int32_t FfiOHOSNotificationManagerSetSlotFlagsByBundle(
    CNotificationBundleOptionV2 option,
    int32_t slotFlags)
{
    auto code = NotificationManagerImplV2::SetSlotFlagsByBundle(option, slotFlags);
    return code;
}

RetDataUI32 FfiOHOSNotificationManagerGetSlotFlagsByBundle(CNotificationBundleOptionV2 option)
{
    RetDataUI32 ret = NotificationManagerImplV2::GetSlotFlagsByBundle(option);
    return ret;
}

RetDataUI32 FfiOHOSNotificationManagerGetSlotNumByBundle(CNotificationBundleOptionV2 option)
{
    RetDataUI32 ret = NotificationManagerImplV2::GetSlotNumByBundle(option);
    return ret;
}

int32_t FfiOHOSNotificationManagerRemoveGroupByBundle(
    CNotificationBundleOptionV2 option,
    const char* cGroupName)
{
    auto code = NotificationManagerImplV2::RemoveGroupByBundle(option, cGroupName);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsNotificationEnabledV2()
{
    RetDataBool ret = { .code = ERR_INVALID_INSTANCE_CODE, .data = 0 };
    auto [status, enabledStatus] = NotificationManagerImplV2::IsNotificationEnabled();
    if (status != SUCCESS_CODE) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsNotificationEnabled error");
        ret.code = status;
        ret.data = false;
        return ret;
    }
    ret.code = status;
    ret.data = enabledStatus;
    return ret;
}

int32_t FfiOHOSNotificationManagerSetBadgeNumberV2(int32_t badgeNumber)
{
    auto code = NotificationManagerImplV2::SetBadgeNumber(badgeNumber);
    return code;
}

int32_t FfiOHOSNotificationManagerRequestEnableNotificationV2()
{
    auto code = NotificationManagerImplV2::RequestEnableNotification();
    return code;
}

int32_t FfiOHOSNotificationManagerRequestEnableNotificationWithContextV2(int64_t id)
{
    auto context = FFIData::GetData<AbilityRuntime::CJAbilityContext>(id);
    if (context == nullptr) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotificationWithContext error");
        return ERROR_PARAM_INVALID;
    }
    auto code = NotificationManagerImplV2::RequestEnableNotificationWithContext(context);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsDistributedEnabledV2()
{
    RetDataBool ret = { .code = ERR_INVALID_INSTANCE_CODE, .data = 0 };
    auto [status, enabledStatus] = NotificationManagerImplV2::IsDistributedEnabled();
    if (status != SUCCESS_CODE) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsDistributedEnabled error");
        ret.code = status;
        ret.data = false;
        return ret;
    }
    ret.code = status;
    ret.data = enabledStatus;
    return ret;
}
}

} // namespace Notification
} // namespace CJSystemapi
} // namespace OHOS