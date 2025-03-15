/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_callback_service.h"
#include "ans_log_wrapper.h"
namespace OHOS {
namespace Notification {

SwingCallBackService::SwingCallBackService(std::function<void(bool, int)> swingCallback) : swingCallback_(swingCallback)
{}
ErrCode SwingCallBackService::OnUpdateStatus(bool isEnable, int32_t triggerMode, int32_t& funcResult)
{
    if (swingCallback_) {
        ANS_LOGI("swingCallback(isEnable: %{public}d, triggerMode: %{public}d)", isEnable, triggerMode);
        swingCallback_(isEnable, triggerMode);
        funcResult = NO_ERROR;
        return funcResult;
    }
    funcResult = ERR_UNKNOWN_OBJECT;
    return funcResult;
}
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_SMART_REMINDER_SUPPORTED