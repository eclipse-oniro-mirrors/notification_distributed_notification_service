/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_INTERFACE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_INTERFACE_H
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "iremote_broker.h"

namespace OHOS {
namespace Notification {
/**
 * @class ISwingCallBack
 */
class ISwingCallBack : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Notification.SwingCallBack");

    /**
     * OnUpdateStatus
     *
     * @param isEnable, triggerMode param.
     * @return Returns update status result.
     */
    virtual int32_t OnUpdateStatus(bool isEnable, int triggerMode) = 0;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_SWING_CALLBACK_INTERFACE_H
#endif