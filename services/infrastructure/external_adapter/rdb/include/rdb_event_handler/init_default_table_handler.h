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

#ifndef ANS_NOTIFICATION_INIT_DEFAULT_TABLE_HANDLER_H
#define ANS_NOTIFICATION_INIT_DEFAULT_TABLE_HANDLER_H

#include <cstdint>
#include <string>
#include "i_rdb_event_handler.h"
#include "notification_rdb_config.h"

namespace OHOS {
namespace NativeRdb {
class RdbStore;
} // namespace NativeRdb
namespace Notification::Infra {

/**
 * @class InitDefaultTableHandler
 * @brief Creates the default notification table when the database is first created.
 */
class InitDefaultTableHandler : public IRdbEventHandler {
public:
    /**
     * @brief Construct the handler.
     * @param config Database configuration providing the default table name.
     */
    explicit InitDefaultTableHandler(const NotificationRdbConfig &config);

    virtual ~InitDefaultTableHandler() = default;

    /** @brief Execute the CREATE TABLE statement for the default table (idempotent). */
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    /** @brief Return the fixed handler name used for registration. */
    std::string GetHandlerName() const override;

private:
    /** Local copy of configuration used to build SQL. */
    NotificationRdbConfig config_;

    /** Set to true once the CREATE TABLE operation has completed successfully. */
    bool tableInitialized_ = false;
};
} // namespace Notification::Infra
} // namespace OHOS

#endif // ANS_NOTIFICATION_INIT_DEFAULT_TABLE_HANDLER_H