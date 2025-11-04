/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ans_result_data_synchronizer.h"

namespace OHOS {
namespace Notification {
void AnsResultDataSynchronizerImpl::Wait()
{
    std::unique_lock<std::mutex> lock(condMutex_);
    condition_.wait(lock, [this] () { return this->pred_; });
    pred_ = false;
}

void AnsResultDataSynchronizerImpl::NotifyOne()
{
    std::unique_lock<std::mutex> lock(condMutex_);
    pred_ = true;
    condition_.notify_one();
}

ErrCode AnsResultDataSynchronizerImpl::TransferResultData(int32_t resultCode)
{
    resultCode_ = resultCode;
    NotifyOne();
    return resultCode_;
}

ErrCode AnsResultDataSynchronizerImpl::GetResultCode() const
{
    return resultCode_;
}
}  // namespace Notification
}  // namespace OHOS