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

#ifndef ANS_NOTIFICATION_MOCK_RDB_HELPER_H
#define ANS_NOTIFICATION_MOCK_RDB_HELPER_H

#include <vector>
#include <memory>

namespace OHOS::Notification::Infra {
class MockRdbStore;
void SetMockGetRdbHelperErrCodes(const std::vector<int> &errCodes);
void SetMockRdbStoreResults(const std::vector<std::shared_ptr<MockRdbStore>> &results);
void SetMockDeleteRdbStoreErrCodes(const std::vector<int> &errCodes);
void ResetMockRdbHelper();
} // namespace OHOS::Notification::Infra

#endif // ANS_NOTIFICATION_RDB_EVENT_CALLBACK_MGR_H