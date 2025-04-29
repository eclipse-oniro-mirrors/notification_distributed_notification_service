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

#include "cj_notification_manager_ffi.h"
#include "macro.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace CJSystemapi {
namespace Notification {

extern "C" {
int32_t FfiOHOSNotificationManagerPublish(CNotificationRequest request)
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerPublish start");
    auto code = NotificationManagerImpl::Publish(request);
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerPublish success");
    return code;
}

int32_t FfiOHOSNotificationManagerCancel(int32_t id, const char* label)
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerCancel start");
    auto code = NotificationManagerImpl::Cancel(id, label);
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerCancel success");
    return code;
}

int32_t FfiOHOSNotificationManagerCancelAll()
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerCancelAll start");
    auto code = NotificationManagerImpl::CancelAll();
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerCancelAll success");
    return code;
}

int32_t FfiOHOSNotificationManagerAddSlot(int32_t type)
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerAddSlot start");
    auto code = NotificationManagerImpl::AddSlot(type);
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerAddSlot success");
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsNotificationEnabled()
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsNotificationEnabled start");
    RetDataBool ret = { .code = ERR_INVALID_INSTANCE_CODE, .data = 0 };
    auto [status, enabledStatus] = NotificationManagerImpl::IsNotificationEnabled();
    if (status != SUCCESS_CODE) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsNotificationEnabled error");
        ret.code = status;
        ret.data = false;
        return ret;
    }
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsNotificationEnabled success");
    ret.code = status;
    ret.data = enabledStatus;
    return ret;
}

int32_t FfiOHOSNotificationManagerSetBadgeNumber(int32_t badgeNumber)
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerSetBadgeNumber start");
    auto code = NotificationManagerImpl::SetBadgeNumber(badgeNumber);
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerSetBadgeNumber success");
    return code;
}

int32_t FfiOHOSNotificationManagerRequestEnableNotification()
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotification start");
    auto code = NotificationManagerImpl::RequestEnableNotification();
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotification success");
    return code;
}

int32_t FfiOHOSNotificationManagerRequestEnableNotificationWithContext(int64_t id)
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotificationWithContext start");
    auto context = FFIData::GetData<AbilityRuntime::CJAbilityContext>(id);
    if (context == nullptr) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotificationWithContext error");
        return ERROR_PARAM_INVALID;
    }
    auto code = NotificationManagerImpl::RequestEnableNotificationWithContext(context);
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerRequestEnableNotificationWithContext success");
    return code;
}

RetDataBool FfiOHOSNotificationManagerIsDistributedEnabled()
{
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsDistributedEnabled start");
    RetDataBool ret = { .code = ERR_INVALID_INSTANCE_CODE, .data = 0 };
    auto [status, enabledStatus] = NotificationManagerImpl::IsDistributedEnabled();
    if (status != SUCCESS_CODE) {
        LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsDistributedEnabled error");
        ret.code = status;
        ret.data = false;
        return ret;
    }
    LOGI("NOTIFICATION_TEST::FfiOHOSNotificationManagerIsDistributedEnabled success");
    ret.code = status;
    ret.data = enabledStatus;
    return ret;
}
}

} // namespace Notification
} // namespace CJSystemapi
} // namespace OHOS