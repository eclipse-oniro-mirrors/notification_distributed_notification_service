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

#ifndef MOCK_RDB_EVENT_HANDLER_H
#define MOCK_RDB_EVENT_HANDLER_H

#include "i_rdb_event_handler.h"
#include <string>

namespace OHOS::Notification::Infra {
class MockRdbEventHandler : public IRdbEventHandler {
public:
    MockRdbEventHandler(const std::string &name, int32_t ret = 0, bool enabled = true);
    int32_t OnCreate(NativeRdb::RdbStore &) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &, int32_t, int32_t) override;
    int32_t OnDowngrade(NativeRdb::RdbStore &, int32_t, int32_t) override;
    int32_t OnOpen(NativeRdb::RdbStore &) override;
    int32_t OnCorruption(const std::string &) override;
    std::string GetHandlerName() const override;
    bool IsEnabled() const override;
    void SetEnabled(bool enabled) override;
    void SetReturnCode(int32_t ret);
private:
    std::string name_;
    int32_t ret_;
};
} // namespace OHOS::Notification::Infra

#endif // MOCK_RDB_EVENT_HANDLER_H