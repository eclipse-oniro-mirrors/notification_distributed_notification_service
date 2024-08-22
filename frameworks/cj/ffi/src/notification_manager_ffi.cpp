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
int32_t FfiOHOSNotificationManagerPublish(CNotificationRequest request)
{
    auto code = NotificationManagerImpl::Publish(request);
    return code;
}

int32_t FfiOHOSNotificationManagerCancel(int32_t id, const char* label)
{
    auto code = NotificationManagerImpl::Cancel(id, label);
    return code;
}

int32_t FfiOHOSNotificationManagerCancelAll()
{
    auto code = NotificationManagerImpl::CancelAll();
    return code;
}

int32_t FfiOHOSNotificationManagerAddSlot(int32_t type)
{
    auto code = NotificationManagerImpl::AddSlot(type);
    return code;
}

CNotificationSlot FfiOHOSNotificationManagerGetSlot(int32_t type, int32_t* errCode)
{
    CNotificationSlot ret = NotificationManagerImpl::GetSlot(type, *errCode);
    return ret;
}

CArrayNotificationSlots FfiOHOSNotificationManagerGetSlots(int32_t* errCode)
{
    CArrayNotificationSlots ret = NotificationManagerImpl::GetSlots(*errCode);
    return ret;
}

int32_t FfiOHOSNotificationManagerRemoveSlot(int32_t type)
{
    auto code = NotificationManagerImpl::RemoveSlot(type);
    return code;
}

int32_t FfiOHOSNotificationManagerRemoveAllSlots()
{
    auto code = NotificationManagerImpl::RemoveAllSlots();
    return code;
}

RetDataUI32 FfiOHOSNotificationManagerGetActiveNotificationCount()
{
    RetDataUI32 ret = NotificationManagerImpl::GetActiveNotificationCount();
    return ret;
}

CArrayNotificationRequest FfiOHOSNotificationManagerGetActiveNotifications(int32_t* errCode)
{
    CArrayNotificationRequest ret = NotificationManagerImpl::GetActiveNotifications(*errCode);
    return ret;
}

int32_t FfiOHOSNotificationManagerCancelGroup(const char* cGroupName)
{
    auto code = NotificationManagerImpl::CancelGroup(cGroupName);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsSupportTemplate(const char* cTemplateName)
{
    RetDataBool ret =  NotificationManagerImpl::IsSupportTemplate(cTemplateName);
    return ret;
}

int32_t FfiOHOSNotificationManagerSetNotificationEnable(CNotificationBundleOption option, bool enable)
{
    auto code = NotificationManagerImpl::SetNotificationEnable(option, enable);
    return code;
}

int32_t FfiOHOSNotificationManagerDisplayBadge(CNotificationBundleOption option, bool enable)
{
    auto code = NotificationManagerImpl::DisplayBadge(option, enable);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsBadgeDisplayed(CNotificationBundleOption option)
{
    RetDataBool ret =  NotificationManagerImpl::IsBadgeDisplayed(option);
    return ret;
}

int32_t FfiOHOSNotificationManagerSetSlotFlagsByBundle(
    CNotificationBundleOption option,
    int32_t slotFlags)
{
    auto code = NotificationManagerImpl::SetSlotFlagsByBundle(option, slotFlags);
    return code;
}

RetDataUI32 FfiOHOSNotificationManagerGetSlotFlagsByBundle(CNotificationBundleOption option)
{
    RetDataUI32 ret = NotificationManagerImpl::GetSlotFlagsByBundle(option);
    return ret;
}

RetDataUI32 FfiOHOSNotificationManagerGetSlotNumByBundle(CNotificationBundleOption option)
{
    RetDataUI32 ret = NotificationManagerImpl::GetSlotNumByBundle(option);
    return ret;
}

int32_t FfiOHOSNotificationManagerRemoveGroupByBundle(
    CNotificationBundleOption option,
    const char* cGroupName)
{
    auto code = NotificationManagerImpl::RemoveGroupByBundle(option, cGroupName);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsNotificationEnabled()
{
    RetDataBool ret = { .code = ERR_INVALID_INSTANCE_CODE, .data = 0 };
    auto [status, enabledStatus] = NotificationManagerImpl::IsNotificationEnabled();
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

int32_t FfiOHOSNotificationManagerSetBadgeNumber(int32_t badgeNumber)
{
    auto code = NotificationManagerImpl::SetBadgeNumber(badgeNumber);
    return code;
}

int32_t FfiOHOSNotificationManagerRequestEnableNotification()
{
    auto code = NotificationManagerImpl::RequestEnableNotification();
    return code;
}

int32_t FfiOHOSNotificationManagerRequestEnableNotificationWithContext(int64_t id)
{
    auto context = FFIData::GetData<AbilityRuntime::CJAbilityContext>(id);
    if (context == nullptr) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotificationWithContext error");
        return ERROR_PARAM_INVALID;
    }
    auto code = NotificationManagerImpl::RequestEnableNotificationWithContext(context);
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsDistributedEnabled()
{
    RetDataBool ret = { .code = ERR_INVALID_INSTANCE_CODE, .data = 0 };
    auto [status, enabledStatus] = NotificationManagerImpl::IsDistributedEnabled();
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