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

#include "mock_ans_rdb_mgr_builder.h"

#include <cerrno>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <set>
#include <string>

#include "ans_rdb_mgr_builder.h"
#include "notification_rdb_config.h"
#include "notification_rdb_event_handler_type.h"
#include "notification_rdb_hook.h"
#include "notification_rdb_mgr.h"

namespace OHOS::Notification::Domain {
namespace {
Infra::NotificationRdbConfig& TestRdbConfig()
{
    static Infra::NotificationRdbConfig config = []() {
        Infra::NotificationRdbConfig c;
        c.dbPath = "/data/local/tmp/ans_rdb_test_" + std::to_string(static_cast<int32_t>(getpid())) + "/";
        c.dbName = "notificationdb_test.db";
        if (mkdir(c.dbPath.c_str(), 0770) != 0 && errno != EEXIST) {
            // best-effort: leave dbPath as-is, NotificationRdbMgr::Init surfaces the failure
        }
        return c;
    }();
    return config;
}

std::shared_ptr<Infra::NotificationRdbMgr>& TestInstance()
{
    static Infra::NtfRdbHook hooks;
    static std::set<Infra::RdbEventHandlerType> eventHandlerTypes = {
        Infra::RdbEventHandlerType::ON_CREATE_INIT_DEFAULT_TABLE,
    };
    static std::shared_ptr<Infra::NotificationRdbMgr> instance =
        std::make_shared<Infra::NotificationRdbMgr>(TestRdbConfig(), hooks, eventHandlerTypes);
    return instance;
}
}

std::shared_ptr<Infra::NotificationRdbMgr> GetAnsNotificationRdbMgrInstance()
{
    return TestInstance();
}

void DestroyTestRdb()
{
    auto& inst = TestInstance();
    if (inst != nullptr) {
        inst->Destroy();
        inst.reset();
    }
    rmdir(TestRdbConfig().dbPath.c_str());
}
}  // namespace OHOS::Notification::Domain
