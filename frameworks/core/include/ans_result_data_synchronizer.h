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

#ifndef BASE_NOTIFICATION_ANS_ANS_RESULT_DATA_SYNCHRONIZER_H
#define BASE_NOTIFICATION_ANS_ANS_RESULT_DATA_SYNCHRONIZER_H

#include <condition_variable>
#include <mutex>

#include "ans_inner_errors.h"
#include "ans_result_data_synchronizer_stub.h"

namespace OHOS {
namespace Notification {
class AnsResultDataSynchronizerImpl final : public AnsResultDataSynchronizerStub {
public:
    /**
     * @brief Block the framework thread to wait for the service return value.
     */
    void Wait();

    /**
     * @brief Wake up the thread blocked by the framework.
     */
    void NotifyOne();

public:
    /**
     * @brief The service transmits an error code to the framework.
     * @param resultCode Service execution result error code.
     * @return Returns the error code of the transmission execution result.
     */
    ErrCode TransferResultData(int32_t resultCode) override;

    /**
     * @brief Get the error code transmitted back by the service layer.
     * @return Returns the error code transmitted back by the service layer.
     */
    ErrCode GetResultCode() const;

private:
    ErrCode resultCode_ {};

private:
    std::mutex condMutex_ {};
    std::condition_variable condition_ {};
    bool pred_ {false};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_ANS_RESULT_DATA_SYNCHRONIZER_H