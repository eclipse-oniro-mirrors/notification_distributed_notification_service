/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANS_NOTIFICATION_MOCK_ABS_SHARED_RESULT_SET_H
#define ANS_NOTIFICATION_MOCK_ABS_SHARED_RESULT_SET_H
#include "abs_shared_result_set.h"
namespace OHOS::Notification::Infra {
class MockAbsSharedResultSet : public NativeRdb::AbsSharedResultSet {
public:
    int GoToFirstRow() override;
    int GetString(int columnIndex, std::string &value) override;
    int GetBlob(int columnIndex, std::vector<uint8_t>& blob) override;
    int GoToNextRow() override;
    int Close() override;
};

void SetMockGoToFirstRowErrCodes(const std::vector<int> &errCodes);
void SetMockGetStringValuesAndErrCodes(const std::vector<std::string> &values, const std::vector<int> &errCodes);
void SetMockGetBlobValuesAndErrCodes(const std::vector<std::vector<uint8_t>> blobs, const std::vector<int> &errCodes);
void SetMockGoToNextRowErrCodes(const std::vector<int> &errCodes);
void ResetMockAbsSharedResultSet();
} // namespace OHOS::Notification::Infra
#endif // ANS_NOTIFICATION_MOCK_ABS_SHARED_RESULT_SET_H