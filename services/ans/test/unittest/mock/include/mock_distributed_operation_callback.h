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

#ifndef MOCK_DISTRIBUTED_DISTRIBUTED_OPERATION_CALLBACK_STUB_H
#define MOCK_DISTRIBUTED_DISTRIBUTED_OPERATION_CALLBACK_STUB_H

#include "ans_operation_callback_stub.h"

namespace OHOS {
namespace Notification {

class MockOperationCallback : public AnsOperationCallbackStub {
public:
    MockOperationCallback() = default;
    ~MockOperationCallback() override {};
    static int32_t GetOperationResult();
    static void ResetOperationResult();
    ErrCode OnOperationCallback(const int32_t operationResult) override;

private:
    static int32_t result;
};

} // namespace Notification
} // namespace OHOS
#endif // MOCK_DISTRIBUTED_DISTRIBUTED_OPERATION_CALLBACK_STUB_H
