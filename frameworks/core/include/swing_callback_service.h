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

#ifndef NOTIFICATION_SWING_CALLBACK_SERVICE_H
#define NOTIFICATION_SWING_CALLBACK_SERVICE_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "swing_call_back_stub.h"
namespace OHOS {
namespace Notification {
class SwingCallBackService : public SwingCallBackStub,
    public std::enable_shared_from_this<SwingCallBackService>{
public:
    SwingCallBackService(std::function<void(bool, int)> swingCallback);
    SwingCallBackService();
    ~SwingCallBackService() = default;

    ErrCode OnUpdateStatus(bool isEnable, int32_t triggerMode, int32_t& funcResult) override;

private:
    std::function<void(bool, int)> swingCallback_;
};
} // namespace Notification
} // namespace OHOS
#endif // NOTIFICATION_SMART_REMINDER_SUPPORTED
#endif // NOTIFICATION_SWING_CALLBACK_SERVICE_H