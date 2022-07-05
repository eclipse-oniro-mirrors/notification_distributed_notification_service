/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_MOCK_ANS_MANAGER_STUB_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_MOCK_ANS_MANAGER_STUB_H

#include "gmock/gmock.h"

#include "ans_log_wrapper.h"
#include "ans_manager_stub.h"

namespace OHOS {
namespace Notification {
class MockAnsManagerStub : public AnsManagerStub {
public:

    std::string GetCmd();
    std::string GetBundle();
    int32_t GetUserId();

    /**
     * @brief Obtains specific datas via specified dump option.
     *
     * @param cmd Indicates the specified dump command.
     * @param bundle Indicates the specified bundle name.
     * @param userId Indicates the specified userId.
     * @param dumpInfo Indicates the container containing datas.
     * @return Returns check result.
     */
    virtual ErrCode ShellDump(const std::string &cmd, const std::string &bundle, int32_t userId,
        std::vector<std::string> &dumpInfo) override;

private:
    std::string cmd_;
    std::string bundle_;
    int32_t userId_;
};
}  // namespace EventFwk
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_MOCK_ANS_MANAGER_STUB_H
