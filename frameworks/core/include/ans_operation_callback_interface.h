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

#ifndef BASE_NOTIFICATION_ANS_DISTRIBUTED_OPERATION_CALLBACK_INTERFACE_H
#define BASE_NOTIFICATION_ANS_DISTRIBUTED_OPERATION_CALLBACK_INTERFACE_H

#include "iremote_broker.h"

#include "nocopyable.h"
#include "parcel.h"

namespace OHOS::Notification {

class OperationCallbackInterface : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Notification.AnsDistributedOperationCallback");

    OperationCallbackInterface() = default;
    ~OperationCallbackInterface() override = default;
    DISALLOW_COPY_AND_MOVE(OperationCallbackInterface);

    virtual void OnOperationCallback(int32_t operationResult) = 0;

    enum { ON_DISTRIBUTED_OPERATION_CALLBACK = 1 };
};
} // namespace OHOS::Notification

#endif // BASE_NOTIFICATION_ANS_DIALOG_CALLBACK_INTERFACE_H

