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
#ifndef BASE_NOTIFICATION_MOCK_NOTIFICATION_RDB_DATA_MGR_H
#define BASE_NOTIFICATION_MOCK_NOTIFICATION_RDB_DATA_MGR_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Notification {
void MockInit(bool mockRet);
void MockQueryData(int32_t mockRet);
void MockSetDataValue(std::string value);
void MockSetDataValues(std::unordered_map<std::string, std::string> &values);
void MockInsertData(bool mockRet);
void MockInsertBatchData(bool mockRet);
void MockQueryDataBeginWithKey(bool mockRet);
void MockDeleteBatchData(bool mockRet);
void MockDeleteData(bool mockRet);
void MockQueryAllData(bool mockRet);
void MockDropTable(bool mockRet);
}
}
#endif