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

#ifndef NOTIFICATION_MANAGER_FFI_H
#define NOTIFICATION_MANAGER_FFI_H

#include "native/ffi_remote_data.h"
#include "notification_manager_impl.h"
#include "notification_utils.h"
#include "inner_errors.h"

#include <cstdint>

extern "C" {
    FFI_EXPORT int32_t FfiOHOSNotificationManagerPublish(CNotificationRequest request);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerCancel(int32_t id, const char* label);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerCancelAll();
    FFI_EXPORT int32_t FfiOHOSNotificationManagerAddSlot(int32_t type);
    FFI_EXPORT CNotificationSlot FfiOHOSNotificationManagerGetSlot(int32_t type, int32_t* errCode);
    FFI_EXPORT CArrayNotificationSlots FfiOHOSNotificationManagerGetSlots(int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRemoveSlot(int32_t type);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRemoveAllSlots();
    FFI_EXPORT RetDataUI32 FfiOHOSNotificationManagerGetActiveNotificationCount();
    FFI_EXPORT CArrayNotificationRequest FfiOHOSNotificationManagerGetActiveNotifications(int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerCancelGroup(const char* cGroupName);
    FFI_EXPORT RetDataBool FfiOHOSNotificationManagerIsSupportTemplate(const char* cTemplateName);
    FFI_EXPORT RetDataBool FfiOHOSNotificationManagerIsNotificationEnabled();
    FFI_EXPORT int32_t FfiOHOSNotificationManagerSetBadgeNumber(int32_t badgeNumber);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRequestEnableNotification();
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRequestEnableNotificationWithContext(int64_t id);
    FFI_EXPORT RetDataBool FfiOHOSNotificationManagerIsDistributedEnabled();

    // systemAPI
    FFI_EXPORT int32_t FfiOHOSNotificationManagerSetNotificationEnable(CNotificationBundleOption option, bool enable);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerDisplayBadge(CNotificationBundleOption option, bool enable);
    FFI_EXPORT RetDataBool FfiOHOSNotificationManagerIsBadgeDisplayed(CNotificationBundleOption option);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerSetSlotFlagsByBundle(CNotificationBundleOption option,
        int32_t slotFlags);
    FFI_EXPORT RetDataUI32 FfiOHOSNotificationManagerGetSlotFlagsByBundle(CNotificationBundleOption option);
    FFI_EXPORT RetDataUI32 FfiOHOSNotificationManagerGetSlotNumByBundle(CNotificationBundleOption option);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRemoveGroupByBundle(CNotificationBundleOption option,
        const char* cGroupName);
}

#endif // NOTIFICATION_MANAGER_FFI_H