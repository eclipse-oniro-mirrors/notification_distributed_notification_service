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

#ifndef ANS_NOTIFICATION_RDB_EVENT_HANDLER_TYPE_H
#define ANS_NOTIFICATION_RDB_EVENT_HANDLER_TYPE_H

namespace OHOS::Notification::Infra {

/**
 * @enum RdbEventHandlerType
 * @brief Built-in RDB event handlers that can be enabled for a database instance.
 */
enum class RdbEventHandlerType {
    /** Create the default notification table when the database is created. */
    ON_CREATE_INIT_DEFAULT_TABLE,
    /** Migrate live view records during schema upgrade. */
    ON_UPGRADE_LIVE_VIEW_MIGRATION,
};

} // OHOS::Notification::Infra
#endif