/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mock_distributed_operation_callback.h"

namespace OHOS {

namespace Notification {

int32_t MockOperationCallback::result = -1;
int32_t MockOperationCallback::GetOperationResult()
{
    return result;
}

void MockOperationCallback::ResetOperationResult()
{
    result = -1;
}

ErrCode MockOperationCallback::OnOperationCallback(const int32_t operationResult)
{
    result = operationResult;
    return 0;
}

} // namespace DistributedHardware
} // namespace OHOS
