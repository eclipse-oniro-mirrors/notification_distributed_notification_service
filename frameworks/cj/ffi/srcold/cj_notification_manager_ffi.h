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
#include "cj_notification_manager_impl.h"
#include "inner_errors.h"

#include <cstdint>

extern "C" {
    FFI_EXPORT int32_t FfiOHOSNotificationManagerPublish(OHOS::CJSystemapi::CNotificationRequest request);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerCancel(int32_t id, const char* label);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerCancelAll();
    FFI_EXPORT int32_t FfiOHOSNotificationManagerAddSlot(int32_t type);
    FFI_EXPORT RetDataBool FfiOHOSNotificationManagerIsNotificationEnabled();
    FFI_EXPORT int32_t FfiOHOSNotificationManagerSetBadgeNumber(int32_t badgeNumber);
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRequestEnableNotification();
    FFI_EXPORT int32_t FfiOHOSNotificationManagerRequestEnableNotificationWithContext(int64_t id);
    FFI_EXPORT RetDataBool FfiOHOSNotificationManagerIsDistributedEnabled();
}

#endif // NOTIFICATION_MANAGER_FFI_H