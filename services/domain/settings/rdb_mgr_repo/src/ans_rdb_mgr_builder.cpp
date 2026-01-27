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

#include "ans_rdb_mgr_builder.h"

#include "rdb_hooks.h"
#include "notification_rdb_mgr.h"
#include "notification_rdb_config.h"
#include "notification_rdb_event_handler_type.h"
#include "notification_rdb_hook.h"

namespace OHOS::Notification::Domain {
std::shared_ptr<Infra::NotificationRdbMgr> GetAnsNotificationRdbMgrInstance()
{
    static Infra::NotificationRdbConfig config;
    static Infra::NtfRdbHook hooks = {
        .OnRdbUpgradeLiveviewMigrate = OnRdbUpgradeLiveviewMigrate,
        .OnRdbOperationFailReport = OnRdbOperationFailReport,
        .OnSendUserDataSizeHisysevent = OnSendUserDataSizeHisysevent
    };
    static std::set<Infra::RdbEventHandlerType> eventHandlerTypes = {
        Infra::RdbEventHandlerType::ON_CREATE_INIT_DEFAULT_TABLE,
        Infra::RdbEventHandlerType::ON_UPGRADE_LIVE_VIEW_MIGRATION
    };
    static std::shared_ptr<Infra::NotificationRdbMgr> instance =
        std::make_shared<Infra::NotificationRdbMgr>(config, hooks, eventHandlerTypes);
    return instance;
}
} // namespace OHOS::Notification::Domain